require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();

const BASE_URL = process.env.IOT_BASE_URL;
const AUTH_URL = (process.env.IOT_AUTH_URL || BASE_URL).replace(/\/+$/, '');
const DEVICE_ID = process.env.DEVICE_ID;
const PORT = process.env.PROXY_PORT || 3000;

let token = process.env.IOT_TOKEN;
const PROXY_API_KEY = process.env.PROXY_API_KEY;

app.use(cors({
  origin: [
    'http://127.0.0.1:5173',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
  ],
  maxAge: 86400,
}));
app.use(express.json());

// 代理 API 鉴权中间件
const AUTH_SKIP = ['/api/ping'];
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

async function callApi(method, path, data = null) {
  const url = `${BASE_URL}${path}`;
  const config = {
    method,
    url,
    headers: { 'X-Access-Token': token },
    timeout: 15000,
  };
  if (data) config.data = data;

  try {
    const res = await axios(config);
    return res.data;
  } catch (e) {
    if (e.response?.status === 401) {
      throw new AuthError('登录已过期，请重新登录');
    }
    throw e;
  }
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

// 获取设备列表
app.get('/api/devices', async (req, res) => {
  try {
    const devices = await fetchDevices();
    res.json({
      code: 0,
      data: devices.map(d => ({
        id: d.id,
        name: d.name,
        productName: d.productName,
        state: d.state?.value || 'offline',
        stateText: d.state?.text || '离线',
      })),
    });
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/info', async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEVICE_ID;
    const d = await fetchDeviceDetail(deviceId);
    let metadata = {};
    try { metadata = JSON.parse(d.metadata); } catch (e) {}
    res.json({
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
    });
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/properties', async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEVICE_ID;
    const latest = await fetchLatestProperties(deviceId);
    const props = {};
    for (const item of latest) {
      props[item.property] = { value: item.value, timestamp: item.timestamp, formatValue: item.formatValue, unit: item.unit };
    }
    res.json({ code: 0, data: props });
  } catch (e) {
    res.json({ code: e instanceof AuthError ? 401 : -1, msg: sanitizeError(e) });
  }
});

app.get('/api/device/status', async (req, res) => {
  try {
    const deviceId = req.query.deviceId || DEVICE_ID;
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

    res.json({
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
    });
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
      token = loginRes.data.result.token;
      try {
        const envPath = path.join(__dirname, '.env');
        let envContent = fs.readFileSync(envPath, 'utf-8');
        envContent = envContent.replace(/^IOT_TOKEN=.*$/m, `IOT_TOKEN=${token}`);
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
  console.log(`设备ID: ${DEVICE_ID}`);
  console.log(`后端地址: ${BASE_URL}`);
  console.log(`Token: ${token ? '已配置' : '未配置'}`);
});
