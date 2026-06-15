require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// ===== Keep-Alive Agent（复用上游 TCP 连接） =====
const KEEP_ALIVE_MS = 60000;
const httpAgent = new http.Agent({ keepAlive: true, keepAliveMsecs: KEEP_ALIVE_MS, maxSockets: 100 });
const httpsAgent = new https.Agent({ keepAlive: true, keepAliveMsecs: KEEP_ALIVE_MS, maxSockets: 100 });
const agentSelector = (url) => url.startsWith('https') ? httpsAgent : httpAgent;

// ===== 内存缓存（TTL 自动过期 + 容量上限） =====
const CACHE_MAX = 1000;
const cacheStore = new Map();
const cacheTimers = new Map();
const cacheKeys = []; // LRU 辅助队列
function cacheGet(key) {
  const entry = cacheStore.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    cacheStore.delete(key);
    return null;
  }
  return entry.data;
}
function cacheSet(key, data, ttlMs) {
  // 达到上限时淘汰最旧条目
  if (cacheStore.size >= CACHE_MAX && !cacheStore.has(key)) {
    const oldest = cacheKeys.shift();
    if (oldest) {
      cacheStore.delete(oldest);
      if (cacheTimers.has(oldest)) { clearTimeout(cacheTimers.get(oldest)); cacheTimers.delete(oldest); }
    }
  }
  cacheStore.set(key, { data, expires: Date.now() + ttlMs });
  // 更新 LRU 顺序
  const idx = cacheKeys.indexOf(key);
  if (idx >= 0) cacheKeys.splice(idx, 1);
  cacheKeys.push(key);
  // 清理定时器
  if (cacheTimers.has(key)) clearTimeout(cacheTimers.get(key));
  cacheTimers.set(key, setTimeout(() => { cacheStore.delete(key); cacheTimers.delete(key); }, ttlMs));
}

// ===== 集群共享 Token（从文件读取，每个 worker 共享最新凭证） =====
const ENV_PATH = path.join(__dirname, '.env');
let cachedToken = null;
let tokenLoadTime = 0;
const TOKEN_RELOAD_MS = 2000;
function getToken() {
  if (cachedToken && Date.now() - tokenLoadTime < TOKEN_RELOAD_MS) {
    return cachedToken;
  }
  try {
    const content = fs.readFileSync(ENV_PATH, 'utf-8');
    const m = content.match(/^IOT_TOKEN=(.+)$/m);
    cachedToken = m ? m[1].trim() : process.env.IOT_TOKEN;
    tokenLoadTime = Date.now();
  } catch {
    cachedToken = process.env.IOT_TOKEN;
  }
  return cachedToken;
}

// ===== deviceId 校验（防 SSRF） =====
const DEFAULT_DEVICE_ID_RE = /^[a-zA-Z0-9_\-.]+$/;
function validateDeviceId(id) {
  return id && DEFAULT_DEVICE_ID_RE.test(id);
}

// ===== 熔断器（防雪崩） =====
const circuitBreakers = {};
function getCircuitBreaker(name, threshold = 3, resetMs = 30000) {
  if (!circuitBreakers[name]) {
    circuitBreakers[name] = { failures: 0, threshold, resetMs, state: 'closed', openedAt: 0 };
  }
  const cb = circuitBreakers[name];
  // 半开/已到重置时间 → 尝试恢复
  if (cb.state === 'open' && Date.now() - cb.openedAt > cb.resetMs) {
    cb.state = 'half-open';
  }
  return cb;
}
function recordFailure(name) {
  const cb = circuitBreakers[name];
  if (!cb) return;
  cb.failures++;
  if (cb.failures >= cb.threshold) {
    cb.state = 'open';
    cb.openedAt = Date.now();
    console.error(`[circuit-breaker] ${name} 已熔断，${cb.resetMs/1000}s 后尝试恢复`);
  }
}
function recordSuccess(name) {
  const cb = circuitBreakers[name];
  if (!cb) return;
  cb.failures = 0;
  if (cb.state === 'half-open') {
    cb.state = 'closed';
    console.log(`[circuit-breaker] ${name} 已恢复`);
  }
}

const BASE_URL = process.env.IOT_BASE_URL;
const AUTH_URL = (process.env.IOT_AUTH_URL || BASE_URL).replace(/\/+$/, '');
const DEFAULT_DEVICE_ID = process.env.DEVICE_ID;
const PORT = process.env.PORT || process.env.PROXY_PORT || 3000;

const PROXY_API_KEY = process.env.PROXY_API_KEY;

const app = express();

app.use(cors({
  origin: [
    'http://127.0.0.1:5173',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
  ],
  maxAge: 86400,
}));
// 限制请求体大小防止大 payload 攻击
app.use(express.json({ limit: '32kb' }));

// 代理 API 鉴权中间件
const AUTH_SKIP = ['/api/ping', '/api/captcha'];
app.use((req, res, next) => {
  if (AUTH_SKIP.includes(req.path)) return next();
  const key = req.headers['x-api-key'];
  if (!key || key !== PROXY_API_KEY) {
    return res.status(403).json({ code: 403, msg: 'Forbidden' });
  }
  next();
});

// 登录接口限流（每IP每10分钟最多10次尝试）
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { code: -1, msg: '登录尝试过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 业务 API 通用限流（每 IP 每 10 秒最多 30 次）
const apiLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 30,
  message: { code: -1, msg: '请求过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 高频率接口独立限流（设备属性轮询类，每 IP 每 5 秒最多 10 次）
const pollLimiter = rateLimit({
  windowMs: 5 * 1000,
  max: 10,
  message: { code: -1, msg: '请求过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

const PROPERTY_IDS = [
  'Pavement_Status', 'Ponding_Thickness', 'Icing_Thickness',
  'Snow_Thickness', 'Temperature', 'Install_Angle', 'Wet_Degree'
];

const PROPERTY_UNITS = {
  Ponding_Thickness: 'mm',
  Icing_Thickness: 'mm',
  Snow_Thickness: 'mm',
  Wet_Degree: '%',
};

// ===== 请求封装 =====

class AuthError extends Error {
  constructor(msg) { super(msg); this.name = 'AuthError'; }
}

const GENERIC_ERROR = '服务异常，请稍后重试';
function sanitizeError(e) {
  if (e instanceof AuthError) return e.message;
  if (e.response) {
    console.error('[API] 上游错误:', e.response?.status, e.response?.data);
  }
  return GENERIC_ERROR;
}

const CIRCUIT_NAME = 'jetlinks-upstream';
const AXIOS_TIMEOUT = 15000;

async function callApi(method, path, data = null) {
  // 熔断检查
  const cb = getCircuitBreaker(CIRCUIT_NAME, 5, 30000);
  if (cb.state === 'open') {
    throw new Error('上游服务暂不可用，请稍后重试');
  }

  const url = `${BASE_URL}${path}`;
  const config = {
    method,
    url,
    httpAgent, httpsAgent,
    headers: { 'X-Access-Token': getToken() },
    timeout: AXIOS_TIMEOUT,
    // 限制重定向次数
    maxRedirects: 3,
  };
  if (data) config.data = data;

  try {
    const res = await axios(config);
    recordSuccess(CIRCUIT_NAME);
    return res.data;
  } catch (e) {
    if (e.response?.status === 401) {
      throw new AuthError('登录已过期，请重新登录');
    }
    // 网络/超时错误触发熔断计数
    if (!e.response || e.code === 'ECONNABORTED') {
      recordFailure(CIRCUIT_NAME);
    }
    throw e;
  }
}

// ===== 统计数据 =====

async function fetchCount(endpoint, terms = []) {
  let path = endpoint;
  if (terms.length > 0) {
    const params = terms.map((t, i) =>
      `terms[${i}].column=${encodeURIComponent(t.column)}&terms[${i}].value=${encodeURIComponent(t.value)}`
    ).join('&');
    path += `?${params}`;
  }
  const data = await callApi('get', path);
  if (data.status !== 200) throw new Error(data.message || '请求失败');
  return data.result;
}

async function fetchDashboardStats() {
  const r = await Promise.allSettled([
    fetchCount('/device/instance/_count'),
    fetchCount('/device/instance/_count', [{ column: 'state', value: 'online' }]),
    fetchCount('/device/instance/_count', [{ column: 'state', value: 'offline' }]),
    fetchCount('/device-product/_count'),
    fetchCount('/device-product/_count', [{ column: 'state', value: '1' }]),
    fetchCount('/device-product/_count', [{ column: 'state', value: '0' }]),
    fetchCount('/device/alarm/history/_count'),
    fetchCount('/device/alarm/history/_count', [{ column: 'state', value: 'solve' }]),
    fetchCount('/device/alarm/history/_count', [{ column: 'state', value: 'newer' }]),
    fetchCount('/notifications/_count'),
    fetchCount('/notifications/_count', [{ column: 'state', value: 'unread' }]),
    fetchCount('/notifications/_count', [{ column: 'state', value: 'read' }]),
  ]);
  const v = (i, def = 0) => r[i].status === 'fulfilled' ? (r[i].value ?? def) : def;
  return {
    devices: { total: v(0), online: v(1), offline: v(2) },
    products: { total: v(3), enabled: v(4), disabled: v(5) },
    alarms: { total: v(6), solved: v(7), new: v(8) },
    notifications: { total: v(9), unread: v(10), read: v(11) },
  };
}

// ===== 获取设备数据 =====

async function fetchDeviceDetail(deviceId) {
  const data = await callApi('get', `/device/instance/${deviceId}/detail`);
  if (data.status !== 200) throw new Error(data.message || '请求失败');
  return data.result;
}

async function fetchLatestProperties(deviceId) {
  const data = await callApi('get', `/device/instance/${deviceId}/properties/latest`);
  if (data.status !== 200) throw new Error(data.message || '请求失败');
  return data.result || [];
}

async function fetchDevices() {
  const data = await callApi('post', '/device/instance/_query', {
    pageIndex: 0,
    pageSize: 100,
    terms: [],
    sorts: [],
  });
  if (data.status !== 200) throw new Error(data.message || '请求失败');
  return data.result?.data || [];
}

// ========== API 路由 ==========

// 获取设备列表（缓存 15 秒）
app.get('/api/devices', apiLimiter, async (req, res) => {
  try {
    const cacheKey = 'devices';
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);

    const devices = await fetchDevices();
    const result = {
      code: 0,
      data: devices.map(d => ({
        id: d.id,
        name: d.name,
        productName: d.productName,
        state: d.state?.value || 'offline',
        stateText: d.state?.text || '离线',
      })),
    };
    cacheSet(cacheKey, result, 15000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/info', pollLimiter, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEFAULT_DEVICE_ID;
    if (!validateDeviceId(deviceId)) {
      return res.status(400).json({ code: -1, msg: '无效的设备 ID' });
    }
    const cacheKey = `device-info:${deviceId}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);

    const d = await fetchDeviceDetail(deviceId);
    let metadata = {};
    try { metadata = JSON.parse(d.metadata); } catch (e) {}
    const result = {
      code: 0,
      data: {
        id: d.id,
        name: d.name,
        productName: d.productName,
        state: d.state.value,
        stateText: d.state.text,
        onlineTime: d.onlineTime,
        offlineTime: d.offlineTime,
        address: d.address,
        properties: (metadata.properties || []).map(p => ({
          id: p.id,
          name: p.name,
          type: p.valueType?.type,
          unit: p.valueType?.unit || PROPERTY_UNITS[p.id] || '',
        })),
      }
    };
    cacheSet(cacheKey, result, 10000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/properties', pollLimiter, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEFAULT_DEVICE_ID;
    if (!validateDeviceId(deviceId)) {
      return res.status(400).json({ code: -1, msg: '无效的设备 ID' });
    }
    const cacheKey = `device-props:${deviceId}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);

    const latest = await fetchLatestProperties(deviceId);
    const props = {};
    for (const item of latest) {
      props[item.property] = { value: item.value, timestamp: item.timestamp, formatValue: item.formatValue, unit: item.unit };
    }
    const result = { code: 0, data: props };
    cacheSet(cacheKey, result, 3000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/status', pollLimiter, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEFAULT_DEVICE_ID;
    if (!validateDeviceId(deviceId)) {
      return res.status(400).json({ code: -1, msg: '无效的设备 ID' });
    }
    const cacheKey = `device-status:${deviceId}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);
    const [d, latest] = await Promise.all([
      fetchDeviceDetail(deviceId),
      fetchLatestProperties(deviceId),
    ]);
    let metadata = {};
    try { metadata = JSON.parse(d.metadata); } catch (e) {}

    const propMap = {};
    for (const item of latest) {
      propMap[item.property] = item;
    }
    const properties = (metadata.properties || []).map(p => {
      const lv = propMap[p.id];
      return {
        id: p.id,
        name: p.name,
        type: p.valueType?.type,
        unit: lv?.unit || p.valueType?.unit || PROPERTY_UNITS[p.id] || '',
        value: lv?.value ?? null,
        formatValue: lv?.formatValue ?? null,
      };
    });

    const result = {
      code: 0,
      data: {
        id: d.id,
        name: d.name,
        state: d.state.value,
        stateText: d.state.text,
        onlineTime: d.onlineTime,
        offlineTime: d.offlineTime,
        address: d.address,
        properties,
        timestamp: Date.now(),
      }
    };
    cacheSet(cacheKey, result, 3000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

// 仪表盘统计数据（缓存 10 秒，支持 GET 和 POST）
app.get('/api/dashboard/stats', apiLimiter, async (req, res) => {
  try {
    const cacheKey = 'dashboard-stats';
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);
    const stats = await fetchDashboardStats();
    const result = { code: 0, data: stats };
    cacheSet(cacheKey, result, 10000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});
app.post('/api/dashboard/stats', apiLimiter, async (req, res) => {
  try {
    const cacheKey = 'dashboard-stats';
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);
    const stats = await fetchDashboardStats();
    const result = { code: 0, data: stats };
    cacheSet(cacheKey, result, 10000);
    res.json(result);
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/ping', (req, res) => {
  res.json({ code: 0, msg: 'ok', time: Date.now() });
});

// ===== 验证码（获取 JetLinks 验证码图片） =====

app.get('/api/captcha', async (req, res) => {
  try {
    const captchaRes = await axios.get(`${AUTH_URL}/authorize/captcha/image?width=130&height=40`, {
      timeout: 10000,
    });
    if (captchaRes.data.status !== 200) throw new Error('获取验证码失败');
    const { key, base64 } = captchaRes.data.result;
    res.json({ code: 0, data: { captchaKey: key, captchaImage: base64 } });
  } catch (e) {
    console.error('[captcha] 获取失败:', e.message);
    res.json({ code: -1, msg: '获取验证码失败' });
  }
});

// 登录
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password, captchaKey, captcha } = req.body;
  if (!username || !password) {
    return res.json({ code: -1, msg: '请输入账号和密码' });
  }
  if (!captchaKey || !captcha) {
    return res.json({ code: -1, msg: '请输入验证码' });
  }
  try {
    const loginRes = await axios.post(`${AUTH_URL}/authorize/login`,
      { username, password, verifyKey: captchaKey, verifyCode: captcha.trim() },
      { timeout: 15000, validateStatus: () => true }
    );
    if (loginRes.data && loginRes.data.status === 200) {
      // 写入文件，所有 worker 通过 getToken() 读取
      try {
        const envPath = path.join(__dirname, '.env');
        let envContent = fs.readFileSync(envPath, 'utf-8');
        envContent = envContent.replace(/^IOT_TOKEN=.*$/m, `IOT_TOKEN=${loginRes.data.result.token}`);
        fs.writeFileSync(envPath, envContent, 'utf-8');
      } catch (e) { console.error('[login] Token保存失败:', e.message); }
      return res.json({ code: 0, msg: '登录成功' });
    }
    return res.json({ code: -1, msg: loginRes.data?.message || '验证码错误' });
  } catch (e) {
    console.error('[login] 请求异常:', e.message);
    res.json({ code: -1, msg: '登录服务异常' });
  }
});

app.listen(PORT, () => {
  console.log(`IoT代理服务已启动: http://localhost:${PORT}`);
  console.log(`设备ID: ${DEFAULT_DEVICE_ID}`);
});
