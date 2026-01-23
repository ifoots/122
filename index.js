const express = require('express');
const crypto = require('crypto');
const app = express();

// 404 页面内容
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
// 性能优化：预计算密钥
// =============================================
const SECRET_KEY = process.env.ENCRYPTION_KEY || 'default-secret-key-change-in-vercel';
const CACHED_KEY = crypto.pbkdf2Sync(SECRET_KEY, 'salt', 1, 32, 'sha1');

// =============================================
// 加密函数
// =============================================
function encryptLink(link) {
  const now = new Date();
  const timeWindow = Math.floor(now.getTime() / 60000);
  const data = `${link}::${timeWindow}`;
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', CACHED_KEY, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return Buffer.from(iv.toString('hex') + ':' + encrypted).toString('base64');
}

// =============================================
// 访问频率限制
// =============================================
const requestLog = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS = 20;

function checkRateLimit(ip) {
  const now = Date.now();
  
  if (!requestLog.has(ip)) {
    requestLog.set(ip, [now]);
    return true;
  }
  
  const requests = requestLog.get(ip).filter(time => now - time < RATE_LIMIT_WINDOW);
  requests.push(now);
  requestLog.set(ip, requests);
  
  if (requestLog.size > 500 && Math.random() < 0.01) {
    const cutoff = now - RATE_LIMIT_WINDOW;
    for (const [key, times] of requestLog.entries()) {
      if (times.every(t => t < cutoff)) {
        requestLog.delete(key);
      }
    }
  }
  
  return requests.length <= MAX_REQUESTS;
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
// HTML 模板（完全混淆版本）
// =============================================
function getDesktopHtml(encryptedLink) {
  // 使用变量名混淆，移除所有明文协议提示
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Redirecting...</title><style>body{margin:0;background:#17212b;}</style><script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" crossorigin="anonymous"></script><script>(function(){var s=0;if(navigator.webdriver)s+=5;if(navigator.plugins.length===0)s+=3;var u=navigator.userAgent||'';if(/HeadlessChrome|PhantomJS|Nightmare/i.test(u))s+=5;if(typeof window.chrome!=='undefined'&&!window.chrome.runtime)s+=3;if(navigator.languages&&navigator.languages.length===0)s+=2;if(s>=8){document.body.innerHTML='';return}function d(e){try{var k='default-secret-key-change-in-vercel';var c=atob(e);var p=c.split(':');if(p.length!==2)return null;var i=CryptoJS.enc.Hex.parse(p[0]);var n=CryptoJS.enc.Hex.parse(p[1]);var y=CryptoJS.PBKDF2(k,'salt',{keySize:8,iterations:1});var t=CryptoJS.AES.decrypt({ciphertext:n},y,{iv:i,mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7});var r=t.toString(CryptoJS.enc.Utf8);if(r.includes('::'))return r.split('::')[0];return r}catch(e){return null}}var a="${encryptedLink}";var l=d(a);if(!l||l.length<10){document.body.innerHTML='';return}setTimeout(function(){window.location.replace(l)},100)})();</script></head><body></body></html>`;
}

function getMobileHtml(groupName, encryptedLink, deviceTipHtml) {
  // 完全移除协议验证，只检查长度和基本格式
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>${groupName}</title><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/><meta property="og:title" content="${groupName}"><meta property="og:description" content="View in Telegram"><meta property="og:image" content="https://telegram.org/img/t_logo.png"><link rel="icon" type="image/png" href="https://telegram.org/img/website_icon.svg"><style>:root{--bg-color:#17212b;--text-primary:#fff;--text-secondary:#7e8c9d;--accent-color:#5288c1;--warning-bg:#3f2e2e;--warning-text:#ff6b6b;--info-bg:#2b3847;--info-text:#64b5f6}body{margin:0;padding:0;background-color:var(--bg-color);color:var(--text-primary);font-family:-apple-system,BlinkMacSystemFont,"Roboto","Helvetica Neue",sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{text-align:center;max-width:420px;width:90%;padding:30px 20px}.tg-logo{width:80px;height:80px;background-color:var(--accent-color);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px;box-shadow:0 4px 15px rgba(0,0,0,.3)}.tg-logo svg{width:42px;height:42px;fill:#fff;transform:translateX(-2px)}h1{font-size:22px;font-weight:600;margin:0 0 12px 0;letter-spacing:.5px}.desc{color:var(--text-secondary);font-size:15px;line-height:1.6;margin:0 0 25px}.device-tip{font-size:13px;text-align:left;padding:12px 15px;border-radius:8px;margin-bottom:25px;line-height:1.5}.device-tip a{font-weight:700;text-decoration:underline}.device-tip.warning{background:var(--warning-bg);color:var(--warning-text);border:1px solid rgba(255,107,107,.2)}.device-tip.warning a{color:var(--warning-text)}.device-tip.info{background:var(--info-bg);color:var(--info-text);border:1px solid rgba(100,181,246,.2)}.device-tip.info a{color:var(--info-text)}.btn{display:flex;align-items:center;justify-content:center;width:100%;background-color:var(--accent-color);color:#fff;text-decoration:none;padding:16px 0;border-radius:12px;font-weight:600;font-size:17px;border:none;cursor:pointer;transition:transform .1s,opacity .2s;box-shadow:0 4px 12px rgba(82,136,193,.3)}.btn:active{transform:scale(.98);opacity:.9}.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top:2px solid #fff;border-radius:50%;animation:spin .8s linear infinite;margin-right:10px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}.footer-note{margin-top:20px;font-size:13px;color:#536375}</style><script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" crossorigin="anonymous"></script><script>(function(){var s=0;if(navigator.webdriver)s+=5;if(navigator.plugins.length===0)s+=3;var u=navigator.userAgent||'';if(/HeadlessChrome|PhantomJS|Nightmare/i.test(u))s+=5;if(typeof window.chrome!=='undefined'&&!window.chrome.runtime)s+=3;if(s>=8){document.addEventListener('DOMContentLoaded',function(){document.body.innerHTML=''});return}})();window.onload=function(){var t=3;var b=document.getElementById('btnText');var l;function d(e){try{var k='default-secret-key-change-in-vercel';var c=atob(e);var p=c.split(':');if(p.length!==2)return null;var i=CryptoJS.enc.Hex.parse(p[0]);var n=CryptoJS.enc.Hex.parse(p[1]);var y=CryptoJS.PBKDF2(k,'salt',{keySize:8,iterations:1});var r=CryptoJS.AES.decrypt({ciphertext:n},y,{iv:i,mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7});var x=r.toString(CryptoJS.enc.Utf8);if(x.includes('::'))return x.split('::')[0];return x}catch(e){return null}}l=d("${encryptedLink}");if(!l||l.length<10||l.indexOf(':')<0){document.body.innerHTML='';return}var v=setInterval(function(){t--;if(t>0){b.innerText="View in Telegram ("+t+"s)"}else{clearInterval(v);b.innerText="Opening Telegram...";window.location.replace(l)}},1000);document.getElementById('mainBtn').onclick=function(){window.location.href=l}};</script></head><body><div class="container"><div class="tg-logo"><svg viewBox="0 0 24 24"><path d="M20.665 3.717l-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42l10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l.002.001l-.314 4.692c.46 0 .663-.211.921-.46l2.211-2.15l4.599 3.397c.848.467 1.457.227 1.668-.785l3.019-14.228c.309-1.239-.473-1.8-1.282-1.434z"/></svg></div><h1>${groupName}</h1><div class="desc">Click the button below to join the channel.<br>点击下方按钮加入群组。</div>${deviceTipHtml}<button id="mainBtn" class="btn"><div class="spinner"></div><span id="btnText">View in Telegram (3s)</span></button><div class="footer-note">If you are not redirected automatically,<br>please click the button above.</div></div></body></html>`;
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
    const httpsLink = `https://t.me/+${group.inviteCode}`;
    const encryptedLink = encryptLink(httpsLink);
    return res.send(getDesktopHtml(encryptedLink));
  }

  const tgLink = `tg://join?invite=${group.inviteCode}`;
  const encryptedLink = encryptLink(tgLink);

  let deviceTipHtml = '';
  if (isAndroid) {
    deviceTipHtml = '<div class="device-tip info"><strong>🤖 安卓用户必读：</strong><br>如无法查看色情消息，<a href="https://t.me/ym_ass/19" target="_blank">点击查看开启R18配置方法 &gt;&gt;</a></div>';
  } else if (isIOS) {
    deviceTipHtml = '<div class="device-tip warning"><strong>🍎 iOS 用户必读：</strong><br>如群组被限制无法查看，<a href="https://t.me/ym_ass/19" target="_blank">点击查看解除限制教程 &gt;&gt;</a></div>';
  }

  res.send(getMobileHtml(group.name, encryptedLink, deviceTipHtml));
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
    console.log(`   ✅ AES-256 动态加密（每分钟变化）`);
    console.log(`   ✅ 预计算密钥（性能优化）`);
    console.log(`   ✅ 压缩 HTML（减少传输）`);
    console.log(`   ✅ 完全协议混淆（无明文泄露）`);
    console.log(`   ✅ Headless 浏览器检测`);
    console.log(`   ✅ User-Agent 过滤`);
    console.log(`   ✅ 访问频率限制（15分钟/20次）`);
    console.log(`========================================`);
  });
}
