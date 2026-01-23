const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// 404 页面
const notFoundHtml = `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`;

// =============================================
// 群组配置
// =============================================
const groups = {
  'chat': {
    name: '『新』大学生反差私密群',
    inviteCode: process.env.CHAT_INVITE_CODE || 'AuPJqZDiCFdlN2Vh'
  },
  'saolou': {
    name: '扫楼打胶共享',
    inviteCode: process.env.SAOLOU_INVITE_CODE || '2TskoPhkURkwMWE5'
  },
  'default': {
    name: '夜半客',
    inviteCode: process.env.DEFAULT_INVITE_CODE || '0X28B1v7veI0MjMx'
  }
};

// =============================================
// HMAC 密钥（只在服务端，永不泄露）
// =============================================
const SECRET_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// =============================================
// 生成 HMAC 签名（服务端）
// =============================================
function generateHMAC(data) {
  const hmac = crypto.createHmac('sha256', SECRET_KEY);
  hmac.update(data);
  return hmac.digest('hex');
}

// =============================================
// 验证请求合法性
// =============================================
function validateRequest(groupPath, timestamp, ip, ua, clientSignature) {
  // 1. 检查时间窗口（30秒内有效）
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > 30) {
    return { valid: false, reason: 'Expired' };
  }
  
  // 2. 生成服务端签名
  const data = `${groupPath}:${timestamp}:${ip}:${ua}`;
  const serverSignature = generateHMAC(data);
  
  // 3. 比对签名（防篡改）
  if (serverSignature !== clientSignature) {
    return { valid: false, reason: 'Invalid signature' };
  }
  
  return { valid: true };
}

// =============================================
// 访问频率限制
// =============================================
const requestLog = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxRequests = 30;
  
  if (!requestLog.has(ip)) {
    requestLog.set(ip, [now]);
    return true;
  }
  
  const requests = requestLog.get(ip).filter(time => now - time < windowMs);
  requests.push(now);
  requestLog.set(ip, requests);
  
  if (requestLog.size > 500 && Math.random() < 0.01) {
    const cutoff = now - windowMs;
    for (const [key, times] of requestLog.entries()) {
      if (times.every(t => t < cutoff)) {
        requestLog.delete(key);
      }
    }
  }
  
  return requests.length <= maxRequests;
}

// =============================================
// User-Agent 检测
// =============================================
const BOT_PATTERNS = [
  /bot|spider|crawl|scrape/i,
  /curl|wget|python|java|go-http/i,
  /headless|phantom|nightmare|selenium/i,
  /scrapy|beautifulsoup|mechanize/i
];

function isSuspiciousUA(ua) {
  if (!ua || ua.length < 10) return true;
  return BOT_PATTERNS.some(pattern => pattern.test(ua));
}

// =============================================
// API：获取签名（第一步）
// =============================================
app.post('/api/get-signature', (req, res) => {
  const { groupPath, timestamp } = req.body;
  
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             'unknown';
  
  const ua = req.headers['user-agent'] || '';
  
  // 验证
  if (!groupPath || !timestamp) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  if (isSuspiciousUA(ua)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  
  // 检查时间戳（防止重放攻击）
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > 10) {
    return res.status(403).json({ error: 'Invalid timestamp' });
  }
  
  // 生成签名
  const data = `${groupPath}:${timestamp}:${ip}:${ua}`;
  const signature = generateHMAC(data);
  
  res.json({ signature });
});

// =============================================
// API：获取链接（第二步）
// =============================================
app.post('/api/get-link', (req, res) => {
  const { groupPath, timestamp, signature } = req.body;
  
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             'unknown';
  
  const ua = req.headers['user-agent'] || '';
  
  // 验证签名
  const validation = validateRequest(groupPath, timestamp, ip, ua, signature);
  
  if (!validation.valid) {
    return res.status(403).json({ error: validation.reason });
  }
  
  const group = groups[groupPath];
  if (!group) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // 判断设备类型
  const isAndroid = /android/i.test(ua);
  const isIOS = /iphone|ipad|ipod/i.test(ua);
  const isMobile = isAndroid || isIOS;
  
  // 返回链接
  const link = isMobile 
    ? `tg://join?invite=${group.inviteCode}`
    : `https://t.me/+${group.inviteCode}`;
  
  res.json({ link });
});

// =============================================
// HTML 模板（完全无敏感信息）
// =============================================
function getDesktopHtml(groupPath) {
  // HTML 中只有群组路径，没有任何令牌或签名
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Redirecting...</title><style>body{margin:0;background:#17212b;}</style><script>(function(){var s=0;if(navigator.webdriver)s+=5;if(navigator.plugins.length===0)s+=3;var u=navigator.userAgent||'';if(/HeadlessChrome|PhantomJS|Nightmare/i.test(u))s+=5;if(typeof window.chrome!=='undefined'&&!window.chrome.runtime)s+=3;if(navigator.languages&&navigator.languages.length===0)s+=2;if(s>=8){document.body.innerHTML='';return}var g="${groupPath}";var t=Math.floor(Date.now()/1000);fetch('/api/get-signature',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({groupPath:g,timestamp:t})}).then(function(r){return r.json()}).then(function(d){if(!d.signature){document.body.innerHTML='';return}return fetch('/api/get-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({groupPath:g,timestamp:t,signature:d.signature})})}).then(function(r){return r.json()}).then(function(d){if(d.link){setTimeout(function(){window.location.replace(d.link)},100)}else{document.body.innerHTML=''}}).catch(function(){document.body.innerHTML=''})})();</script></head><body></body></html>`;
}

function getMobileHtml(groupName, groupPath, deviceTipHtml) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>${groupName}</title><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/><meta property="og:title" content="${groupName}"><meta property="og:description" content="View in Telegram"><meta property="og:image" content="https://telegram.org/img/t_logo.png"><link rel="icon" type="image/png" href="https://telegram.org/img/website_icon.svg"><style>:root{--bg-color:#17212b;--text-primary:#fff;--text-secondary:#7e8c9d;--accent-color:#5288c1;--warning-bg:#3f2e2e;--warning-text:#ff6b6b;--info-bg:#2b3847;--info-text:#64b5f6}body{margin:0;padding:0;background-color:var(--bg-color);color:var(--text-primary);font-family:-apple-system,BlinkMacSystemFont,"Roboto","Helvetica Neue",sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{text-align:center;max-width:420px;width:90%;padding:30px 20px}.tg-logo{width:80px;height:80px;background-color:var(--accent-color);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px;box-shadow:0 4px 15px rgba(0,0,0,.3)}.tg-logo svg{width:42px;height:42px;fill:#fff;transform:translateX(-2px)}h1{font-size:22px;font-weight:600;margin:0 0 12px 0;letter-spacing:.5px}.desc{color:var(--text-secondary);font-size:15px;line-height:1.6;margin:0 0 25px}.device-tip{font-size:13px;text-align:left;padding:12px 15px;border-radius:8px;margin-bottom:25px;line-height:1.5}.device-tip a{font-weight:700;text-decoration:underline}.device-tip.warning{background:var(--warning-bg);color:var(--warning-text);border:1px solid rgba(255,107,107,.2)}.device-tip.warning a{color:var(--warning-text)}.device-tip.info{background:var(--info-bg);color:var(--info-text);border:1px solid rgba(100,181,246,.2)}.device-tip.info a{color:var(--info-text)}.btn{display:flex;align-items:center;justify-content:center;width:100%;background-color:var(--accent-color);color:#fff;text-decoration:none;padding:16px 0;border-radius:12px;font-weight:600;font-size:17px;border:none;cursor:pointer;transition:transform .1s,opacity .2s;box-shadow:0 4px 12px rgba(82,136,193,.3)}.btn:active{transform:scale(.98);opacity:.9}.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top:2px solid #fff;border-radius:50%;animation:spin .8s linear infinite;margin-right:10px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}.footer-note{margin-top:20px;font-size:13px;color:#536375}</style><script>(function(){var s=0;if(navigator.webdriver)s+=5;if(navigator.plugins.length===0)s+=3;var u=navigator.userAgent||'';if(/HeadlessChrome|PhantomJS|Nightmare/i.test(u))s+=5;if(typeof window.chrome!=='undefined'&&!window.chrome.runtime)s+=3;if(s>=8){document.addEventListener('DOMContentLoaded',function(){document.body.innerHTML=''});return}})();window.onload=function(){var c=3;var b=document.getElementById('btnText');var g="${groupPath}";var t=Math.floor(Date.now()/1000);var l=null;fetch('/api/get-signature',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({groupPath:g,timestamp:t})}).then(function(r){return r.json()}).then(function(d){if(!d.signature){document.body.innerHTML='';return}return fetch('/api/get-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({groupPath:g,timestamp:t,signature:d.signature})})}).then(function(r){return r.json()}).then(function(d){if(!d.link){document.body.innerHTML='';return}l=d.link;var v=setInterval(function(){c--;if(c>0){b.innerText="View in Telegram ("+c+"s)"}else{clearInterval(v);b.innerText="Opening Telegram...";window.location.replace(l)}},1000);document.getElementById('mainBtn').onclick=function(){if(l)window.location.href=l}}).catch(function(){document.body.innerHTML=''})};</script></head><body><div class="container"><div class="tg-logo"><svg viewBox="0 0 24 24"><path d="M20.665 3.717l-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42l10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l.002.001l-.314 4.692c.46 0 .663-.211.921-.46l2.211-2.15l4.599 3.397c.848.467 1.457.227 1.668-.785l3.019-14.228c.309-1.239-.473-1.8-1.282-1.434z"/></svg></div><h1>${groupName}</h1><div class="desc">Click the button below to join the channel.<br>点击下方按钮加入群组。</div>${deviceTipHtml}<button id="mainBtn" class="btn"><div class="spinner"></div><span id="btnText">View in Telegram (3s)</span></button><div class="footer-note">If you are not redirected automatically,<br>please click the button above.</div></div></body></html>`;
}

// =============================================
// 主路由
// =============================================
app.get('/:path?', (req, res) => {
  const path = req.params.path;
  
  if (!path) {
    return res.status(404).send(notFoundHtml);
  }

  const group = groups[path];
  
  if (!group) {
    return res.status(404).send(notFoundHtml);
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             'unknown';
  
  const ua = req.headers['user-agent'] || '';
  
  if (isSuspiciousUA(ua)) {
    return res.status(404).send(notFoundHtml);
  }
  
  if (!checkRateLimit(ip)) {
    return res.status(429).send(notFoundHtml);
  }

  const isAndroid = /android/i.test(ua);
  const isIOS = /iphone|ipad|ipod/i.test(ua);
  const isMobile = isAndroid || isIOS;

  if (!isMobile) {
    return res.send(getDesktopHtml(path));
  }

  let deviceTipHtml = '';
  if (isAndroid) {
    deviceTipHtml = '<div class="device-tip info"><strong>🤖 安卓用户必读：</strong><br>如无法查看色情消息，<a href="https://t.me/ym_ass/19" target="_blank">点击查看开启R18配置方法 &gt;&gt;</a></div>';
  } else if (isIOS) {
    deviceTipHtml = '<div class="device-tip warning"><strong>🍎 iOS 用户必读：</strong><br>如群组被限制无法查看，<a href="https://t.me/ym_ass/19" target="_blank">点击查看解除限制教程 &gt;&gt;</a></div>';
  }

  res.send(getMobileHtml(group.name, path, deviceTipHtml));
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`========================================`);
    console.log(`🚀 服务已启动！`);
    console.log(`========================================`);
    console.log(`📱 本地访问: http://localhost:${port}/chat`);
    console.log(`========================================`);
    console.log(`🔒 安全特性:`);
    console.log(`   ✅ HMAC 动态签名（密钥永不泄露）`);
    console.log(`   ✅ HTML 中无任何敏感信息`);
    console.log(`   ✅ 两步验证（获取签名 → 获取链接）`);
    console.log(`   ✅ 30秒时间窗口`);
    console.log(`   ✅ IP + UA 强绑定`);
    console.log(`   ✅ Headless 浏览器检测`);
    console.log(`   ✅ User-Agent 过滤`);
    console.log(`   ✅ 访问频率限制（15分钟/30次）`);
    console.log(`========================================`);
    console.log(`🔑 SECRET_KEY: ${SECRET_KEY.substring(0, 16)}...`);
    console.log(`========================================`);
  });
}
