// ============================================================
// 🔐 密码计算器 - 核心逻辑
// ============================================================

// ---------- 📌 你的公式在这里 ----------
// 把下面的函数替换成你的真实公式即可
// 参数：factoryCode(厂家代码), secretKey(密钥), expireDate(到期时间 格式:YYYY-MM-DD)
// 返回：{ password: 'xxx', superPassword: 'xxx' }

function calculate(factoryCode, secretKey, expireDate) {

  // ========== 示例公式（占位）==========
  // 👇 这里只是演示，请替换成你自己的公式

  // 密码 = 厂家代码 + 密钥 + 日期的组合处理
  const raw = factoryCode + secretKey + expireDate;

  // 生成密码：对每个字符取字符码并拼接
  let pwd = '';
  for (let i = 0; i < raw.length; i++) {
    pwd += (raw.charCodeAt(i) % 10).toString();
  }
  // 取前8位作为密码
  const password = pwd.substring(0, 8);

  // 生成超级密码：密码的反转 + 额外校验
  const superPassword = password.split('').reverse().join('') +
                        (factoryCode.length * 7).toString().padStart(2, '0');

  // ========== 替换结束 ==========

  return {
    password: password,
    superPassword: superPassword
  };
}

// ---------- 之后你只需要修改上面的 calculate 函数即可 ----------

// ============================================================
// 界面交互逻辑
// ============================================================

// DOM 元素
const mainPage = document.getElementById('mainPage');
const historyPage = document.getElementById('historyPage');
const factoryInput = document.getElementById('factoryCode');
const secretInput = document.getElementById('secretKey');
const dateInput = document.getElementById('expireDate');
const calcBtn = document.getElementById('calcBtn');
const outputArea = document.getElementById('outputArea');
const passwordEl = document.getElementById('password');
const superPwdEl = document.getElementById('superPassword');
const errorMsg = document.getElementById('errorMsg');
const historyBtn = document.getElementById('historyBtn');
const backBtn = document.getElementById('backBtn');
const clearBtn = document.getElementById('clearBtn');
const historyList = document.getElementById('historyList');
const copyPwdBtn = document.getElementById('copyPwd');
const copySuperBtn = document.getElementById('copySuper');

// 默认日期：今天
dateInput.value = new Date().toISOString().split('T')[0];

// 计算按钮点击
calcBtn.addEventListener('click', function() {
  const factoryCode = factoryInput.value.trim();
  const secretKey = secretInput.value.trim();
  const expireDate = dateInput.value;

  // 校验输入
  if (!factoryCode) {
    showError('请输入厂家代码');
    return;
  }
  if (!secretKey) {
    showError('请输入密钥');
    return;
  }
  if (!expireDate) {
    showError('请选择到期时间');
    return;
  }

  errorMsg.textContent = '';

  // 执行计算
  const result = calculate(factoryCode, secretKey, expireDate);

  // 显示结果
  passwordEl.textContent = result.password;
  superPwdEl.textContent = result.superPassword;
  outputArea.classList.add('show');

  // 保存到历史记录
  saveHistory(factoryCode, secretKey, expireDate, result.password, result.superPassword);
});

// 复制按钮
copyPwdBtn.addEventListener('click', function() {
  copyText(passwordEl.textContent);
});
copySuperBtn.addEventListener('click', function() {
  copyText(superPwdEl.textContent);
});

// 跳转历史页面
historyBtn.addEventListener('click', function() {
  mainPage.classList.remove('active');
  historyPage.classList.add('active');
  loadHistory();
});

// 返回主页
backBtn.addEventListener('click', function() {
  historyPage.classList.remove('active');
  mainPage.classList.add('active');
});

// 清空历史
clearBtn.addEventListener('click', function() {
  if (confirm('确定要清空所有历史记录吗？')) {
    localStorage.removeItem('calcHistory');
    loadHistory();
  }
});

// ============================================================
// 历史记录管理
// ============================================================

const HISTORY_KEY = 'calcHistory';

function saveHistory(factoryCode, secretKey, expireDate, password, superPassword) {
  const records = getHistory();

  records.unshift({
    id: Date.now(),
    time: new Date().toLocaleString('zh-CN'),
    factoryCode: factoryCode,
    secretKey: secretKey,
    expireDate: expireDate,
    password: password,
    superPassword: superPassword
  });

  // 最多保存 500 条
  if (records.length > 500) {
    records.pop();
  }

  localStorage.setItem(HISTORY_KEY, JSON.stringify(records));
}

function getHistory() {
  try {
    const data = localStorage.getItem(HISTORY_KEY);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    return [];
  }
}

function loadHistory() {
  const records = getHistory();

  if (records.length === 0) {
    historyList.innerHTML = '<div class="empty-hint">暂无记录</div>';
    return;
  }

  let html = '';
  records.forEach(function(record) {
    html += `
      <div class="history-item">
        <div class="hi-time">🕐 ${record.time}</div>
        <div class="hi-row"><span>厂家代码</span><span>${escapeHtml(record.factoryCode)}</span></div>
        <div class="hi-row"><span>密&nbsp;&nbsp;&nbsp;&nbsp;钥</span><span>${escapeHtml(record.secretKey)}</span></div>
        <div class="hi-row"><span>到期时间</span><span>${record.expireDate}</span></div>
        <div class="hi-result">
          <span>密码：${escapeHtml(record.password)}</span>
          <span>超级密码：${escapeHtml(record.superPassword)}</span>
        </div>
      </div>
    `;
  });

  historyList.innerHTML = html;
}

// ============================================================
// 工具函数
// ============================================================

function copyText(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('已复制 ✅');
    });
  } else {
    // 兼容旧浏览器
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast('已复制 ✅');
  }
}

function showError(msg) {
  errorMsg.textContent = msg;
  setTimeout(function() {
    errorMsg.textContent = '';
  }, 3000);
}

function showToast(msg) {
  let toast = document.querySelector('.toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(function() {
    toast.classList.remove('show');
  }, 1500);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
