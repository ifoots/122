const express = require('express');
const crypto = require('crypto');
const app = express();

// 404 页面内容
const notFoundHtml = `
<!DOCTYPE html>
<html>
<head>
<title>404 Not Found</title>
</head>
<body>
<center><h1>404 Not Found</h1></center>
<hr>
<center>nginx</center>
</body>
</html>
`;

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
// 动态加密函数（基于时间窗口）
// =============================================
function encryptLink(link) {
  const SECRET_KEY = process.env.ENCRYPTION_KEY || 'default-secret-key-change-in-vercel';
  
  // 获取当前分钟数（每分钟加密结果都不同）
  const now = new Date();
  const timeWindow = Math.floor(now.getTime() / 60000);
  
  // 将链接和时间窗口组合
  const data = `${link}::${timeWindow}`;
  
  // 使用 AES-256-CBC 加密
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', crypto.scryptSync(SECRET_KEY, 'salt', 32), iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // 返回 IV + 密文（Base64 编码）
  const result = Buffer.from(iv.toString('hex') + ':' + encrypted).toString('base64');
  return result;
}

// =============================================
// 访问频率限制
// =============================================
const requestLog = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 分钟
  const maxRequests = 20; // 最多 20 次请求
  
  if (!requestLog.has(ip)) {
    requestLog.set(ip, []);
  }
  
  const requests = requestLog.get(ip).filter(time => now - time < windowMs);
  requests.push(now);
  requestLog.set(ip, requests);
  
  // 清理过期数据
  if (requestLog.size > 1000) {
    const oldestAllowed = now - windowMs;
    for (const [key, times] of requestLog.entries()) {
      if (times.every(t => t < oldestAllowed)) {
        requestLog.delete(key);
      }
    }
  }
  
  return requests.length <= maxRequests;
}

// =============================================
// User-Agent 检测
// =============================================
function isSuspiciousUA(ua) {
  if (!ua || ua.length < 10) return true;
  
  const botPatterns = [
    /bot|spider|crawl|scrape/i,
    /curl|wget|python|java|go-http/i,
    /headless|phantom|nightmare|selenium/i,
    /scrapy|beautifulsoup|mechanize/i
  ];
  
  return botPatterns.some(pattern => pattern.test(ua));
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

  // 服务端安全检查
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

  // ========================================
  // 桌面端：动态加密 + Headless 检测
  // ========================================
  if (!isMobile) {
    const httpsLink = `https://t.me/+${group.inviteCode}`;
    const encryptedLink = encryptLink(httpsLink);
    
    // 👇 这里已经添加了 crypto-js 的引用
    const desktopHtml = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Redirecting...</title>
<style>body{margin:0;background:#17212b;}</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" crossorigin="anonymous"></script>
<script>
(function(){
  // Headless 检测
  var score = 0;
  if (navigator.webdriver) score += 5;
  if (navigator.plugins.length === 0) score += 3;
  var ua = navigator.userAgent || '';
  if (/HeadlessChrome|PhantomJS|Nightmare/i.test(ua)) score += 5;
  if (typeof window.chrome !== 'undefined' && !window.chrome.runtime) score += 3;
  if (navigator.languages && navigator.languages.length === 0) score += 2;
  
  if (score >= 8) {
    document.body.innerHTML = '';
    return;
  }
  
  // 使用 CryptoJS 解密（完整实现）
  function decrypt(encData) {
    try {
      var SECRET_KEY = 'default-secret-key-change-in-vercel'; // 与服务端保持一致
      
      var decoded = atob(encData);
      var parts = decoded.split(':');
      if (parts.length !== 2) return null;
      
      var ivHex = parts[0];
      var encryptedHex = parts[1];
      
      // 将十六进制转换为 CryptoJS 格式
      var iv = CryptoJS.enc.Hex.parse(ivHex);
      var encrypted = CryptoJS.enc.Hex.parse(encryptedHex);
      
      // 生成密钥（与服务端一致的方式）
      var key = CryptoJS.PBKDF2(SECRET_KEY, 'salt', {
        keySize: 256/32,
        iterations: 1
      });
      
      // 解密
      var decrypted = CryptoJS.AES.decrypt(
        { ciphertext: encrypted },
        key,
        { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
      );
      
      var decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
      
      // 提取链接部分（去除时间戳）
      if (decryptedText.includes('::')) {
        return decryptedText.split('::')[0];
      }
      
      return decryptedText;
    } catch(e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }
  
  var encryptedData = "${encryptedLink}";
  var targetUrl = decrypt(encryptedData);
  
  if (!targetUrl || !targetUrl.startsWith('https://t.me/')) {
    document.body.innerHTML = '';
    return;
  }
  
  setTimeout(function() {
    window.location.replace(targetUrl);
  }, 100);
})();
</script>
</head>
<body></body>
</html>
    `;
    
    return res.send(desktopHtml);
  }

  // ========================================
  // 移动端：动态加密 + UI
  // ========================================
  const tgLink = `tg://join?invite=${group.inviteCode}`;
  const encryptedLink = encryptLink(tgLink);

  let deviceTipHtml = '';
  if (isAndroid) {
    deviceTipHtml = `
      <div class="device-tip info">
        <strong>🤖 安卓用户必读：</strong><br>
        如无法查看色情消息，<a href="https://t.me/ym_ass/19" target="_blank">点击查看开启R18配置方法 &gt;&gt;</a>
      </div>
    `;
  } else if (isIOS) {
    deviceTipHtml = `
      <div class="device-tip warning">
        <strong>🍎 iOS 用户必读：</strong><br>
        如群组被限制无法查看，<a href="https://t.me/ym_ass/19" target="_blank">点击查看解除限制教程 &gt;&gt;</a>
      </div>
    `;
  }

  // 👇 这里也已经添加了 crypto-js 的引用
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>${group.name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
<meta property="og:title" content="${group.name}">
<meta property="og:description" content="View in Telegram">
<meta property="og:image" content="https://telegram.org/img/t_logo.png">
<link rel="icon" type="image/png" href="https://telegram.org/img/website_icon.svg">
<style>
:root {
  --bg-color: #17212b;
  --text-primary: #ffffff;
  --text-secondary: #7e8c9d;
  --accent-color: #5288c1;
  --warning-bg: #3f2e2e;
  --warning-text: #ff6b6b;
  --info-bg: #2b3847;
  --info-text: #64b5f6;
}
body {
  margin: 0; padding: 0;
  background-color: var(--bg-color);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, "Roboto", "Helvetica Neue", sans-serif;
  display: flex; justify-content: center; align-items: center;
  min-height: 100vh;
}
.container {
  text-align: center; max-width: 420px; width: 90%;
  padding: 30px 20px;
}
.tg-logo {
  width: 80px; height: 80px;
  background-color: var(--accent-color);
  border-radius: 50%;
  display: inline-flex; align-items: center; justify-content: center;
  margin-bottom: 20px;
  box-shadow: 0 4px 15px rgba(0,0,0,0.3);
}
.tg-logo svg { width: 42px; height: 42px; fill: white; transform: translateX(-2px); }
h1 { font-size: 22px; font-weight: 600; margin: 0 0 12px 0; letter-spacing: 0.5px; }
.desc {
  color: var(--text-secondary);
  font-size: 15px; line-height: 1.6; margin: 0 0 25px;
}
.device-tip {
  font-size: 13px; text-align: left; padding: 12px 15px;
  border-radius: 8px; margin-bottom: 25px; line-height: 1.5;
}
.device-tip a { font-weight: bold; text-decoration: underline; }
.device-tip.warning { background: var(--warning-bg); color: var(--warning-text); border: 1px solid rgba(255,107,107,0.2); }
.device-tip.warning a { color: var(--warning-text); }
.device-tip.info { background: var(--info-bg); color: var(--info-text); border: 1px solid rgba(100,181,246,0.2); }
.device-tip.info a { color: var(--info-text); }
.btn {
  display: flex; align-items: center; justify-content: center;
  width: 100%;
  background-color: var(--accent-color);
  color: white;
  text-decoration: none;
  padding: 16px 0;
  border-radius: 12px;
  font-weight: 600; font-size: 17px;
  border: none; cursor: pointer;
  transition: transform 0.1s, opacity 0.2s;
  box-shadow: 0 4px 12px rgba(82, 136, 193, 0.3);
}
.btn:active { transform: scale(0.98); opacity: 0.9; }
.spinner {
  width: 18px; height: 18px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top: 2px solid #ffffff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin-right: 10px;
}
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.footer-note { margin-top: 20px; font-size: 13px; color: #536375; }
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" crossorigin="anonymous"></script>
<script>
(function() {
  var score = 0;
  if (navigator.webdriver) score += 5;
  if (navigator.plugins.length === 0) score += 3;
  var ua = navigator.userAgent || '';
  if (/HeadlessChrome|PhantomJS|Nightmare/i.test(ua)) score += 5;
  if (typeof window.chrome !== 'undefined' && !window.chrome.runtime) score += 3;
  
  if (score >= 8) {
    document.addEventListener('DOMContentLoaded', function() {
      document.body.innerHTML = '';
    });
    return;
  }
})();

window.onload = function() {
  var timeLeft = 3;
  var btnText = document.getElementById('btnText');
  var targetUrl;
  
  // 使用 CryptoJS 解密（完整实现）
  function decrypt(encData) {
    try {
      var SECRET_KEY = 'default-secret-key-change-in-vercel';
      
      var decoded = atob(encData);
      var parts = decoded.split(':');
      if (parts.length !== 2) return null;
      
      var ivHex = parts[0];
      var encryptedHex = parts[1];
      
      var iv = CryptoJS.enc.Hex.parse(ivHex);
      var encrypted = CryptoJS.enc.Hex.parse(encryptedHex);
      
      var key = CryptoJS.PBKDF2(SECRET_KEY, 'salt', {
        keySize: 256/32,
        iterations: 1
      });
      
      var decrypted = CryptoJS.AES.decrypt(
        { ciphertext: encrypted },
        key,
        { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
      );
      
      var decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
      
      if (decryptedText.includes('::')) {
        return decryptedText.split('::')[0];
      }
      
      return decryptedText;
    } catch(e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }
  
  targetUrl = decrypt("${encryptedLink}");
  
  if (!targetUrl || !targetUrl.startsWith('tg://')) {
    document.body.innerHTML = '';
    return;
  }
  
  var interval = setInterval(function() {
    timeLeft--;
    if (timeLeft > 0) {
      btnText.innerText = "View in Telegram (" + timeLeft + "s)";
    } else {
      clearInterval(interval);
      btnText.innerText = "Opening Telegram...";
      window.location.replace(targetUrl);
    }
  }, 1000);
  
  document.getElementById('mainBtn').onclick = function() {
    window.location.href = targetUrl;
  };
};
</script>
</head>
<body>
<div class="container">
<div class="tg-logo"><svg viewBox="0 0 24 24"><path d="M20.665 3.717l-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42l10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l.002.001l-.314 4.692c.46 0 .663-.211.921-.46l2.211-2.15l4.599 3.397c.848.467 1.457.227 1.668-.785l3.019-14.228c.309-1.239-.473-1.8-1.282-1.434z"/></svg></div>
<h1>${group.name}</h1>
<div class="desc">Click the button below to join the channel.<br>点击下方按钮加入群组。</div>
${deviceTipHtml}
<button id="mainBtn" class="btn">
<div class="spinner"></div>
<span id="btnText">View in Telegram (3s)</span>
</button>
<div class="footer-note">If you are not redirected automatically,<br>please click the button above.</div>
</div>
</body>
</html>
  `;

  res.send(html);
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
    console.log(`   ✅ AES-256 动态加密（每分钟变化）`);
    console.log(`   ✅ CryptoJS 完整解密`);
    console.log(`   ✅ Headless 浏览器检测`);
    console.log(`   ✅ User-Agent 过滤`);
    console.log(`   ✅ 访问频率限制（15分钟/20次）`);
    console.log(`========================================`);
  });
}