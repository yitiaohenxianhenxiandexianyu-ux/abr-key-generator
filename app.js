// ============================================================
// 阿搏锐密钥生成 - 分期付款密码系统
// 算法严格按照需求规格书实现
// ============================================================

// ==================== 3.1 MD5 哈希 (RFC 1321) ====================
// 使用 blueimp-md5 库（md5-lib.js），全局 md5() 函数

// ==================== 3.2 8位累加校验和 ====================

function checksum(str) {
  var sum = 0;
  for (var i = 0; i < str.length; i++) {
    sum += str.charCodeAt(i);
  }
  return sum % 256;
}

// ==================== 3.3 密钥派生函数 ====================

function derive_streams(K, M, D) {
  // S = K + M + D（按顺序，无分隔符）
  var S = K + M + D;
  var md5_hex = md5(S);

  // Stream1：取 md5_hex 前 6 个字节，每个字节值 % 10
  var Stream1 = [];
  for (var i = 0; i < 6; i++) {
    var hexByte = md5_hex.substring(i * 2, i * 2 + 2);
    var byteVal = parseInt(hexByte, 16);
    Stream1.push(byteVal % 10);
  }

  // Stream2_val：取第 7、8 字节 (索引 12-13, 14-15)
  var byte7 = parseInt(md5_hex.substring(12, 14), 16);
  var byte8 = parseInt(md5_hex.substring(14, 16), 16);
  var Stream2_val = (byte7 * 256 + byte8) % 100;

  return { Stream1: Stream1, Stream2_val: Stream2_val };
}

// ==================== 3.4 生成普通/超级密码 ====================

function generate_password(K, M, D, T) {
  var result = derive_streams(K, M, D);
  var Stream1 = result.Stream1;
  var Stream2_val = result.Stream2_val;

  // 加密时间：对 T 的每一位
  var C = '';
  for (var i = 0; i < 6; i++) {
    var t_digit = parseInt(T.charAt(i));
    var c_digit = (t_digit + Stream1[i]) % 10;
    C += c_digit.toString();
  }

  // MAC 校验码
  var mac_data = M + D + T;
  var chksum = checksum(mac_data);
  var mac_val = (chksum + Stream2_val) % 100;
  var mac_str = mac_val.toString().padStart(2, '0');

  return C + mac_str;
}

// ==================== 3.5 生成密钥更新密码 ====================

function generate_update_password(K_old, M, D, K_new) {
  // 前 8 位
  var P_front = generate_password(K_old, M, D, '000000');

  // 派生更新专用流（加盐）
  var salt = K_old + M + D + 'UPDATE';
  var md5_update = md5(salt);

  // 取前 16 个字节，每个字节 % 10
  var enc_stream = [];
  for (var i = 0; i < 16; i++) {
    var hexByte = md5_update.substring(i * 2, i * 2 + 2);
    var byteVal = parseInt(hexByte, 16);
    enc_stream.push(byteVal % 10);
  }

  // 加密新密钥
  var enc_key = '';
  for (var i = 0; i < 16; i++) {
    var p_digit = parseInt(K_new.charAt(i));
    var c_digit = (p_digit + enc_stream[i]) % 10;
    enc_key += c_digit.toString();
  }

  return P_front + enc_key;
}

// ==================== 4.1 验证 8 位密码（自测用） ====================

function verify_8digit(pwd_8, K, M, D) {
  if (pwd_8.length !== 8) return { ok: false, error: '长度错误' };

  var C = pwd_8.substring(0, 6);
  var mac_in = parseInt(pwd_8.substring(6, 8));
  var result = derive_streams(K, M, D);
  var Stream1 = result.Stream1;
  var Stream2_val = result.Stream2_val;

  // 解密时间
  var T_str = '';
  for (var i = 0; i < 6; i++) {
    var c = parseInt(C.charAt(i));
    var t = (c - Stream1[i] + 10) % 10;
    T_str += t.toString();
  }

  // 校验 MAC
  var mac_calc = (checksum(M + D + T_str) + Stream2_val) % 100;
  if (mac_calc !== mac_in) return { ok: false, error: 'MAC错误' };

  if (T_str === '999999') return { ok: true, type: 'permanent', T: T_str };
  if (T_str === '000000') return { ok: true, type: 'update', T: T_str };

  return { ok: true, type: 'normal', T: T_str };
}

// ==================== 4.2 验证密钥更新密码（自测用） ====================

function verify_update(pwd_24, K_old, M, D) {
  if (pwd_24.length !== 24) return { ok: false, error: '长度错误' };

  var front8 = pwd_24.substring(0, 8);
  var enc_new_key = pwd_24.substring(8, 24);

  var verify_result = verify_8digit(front8, K_old, M, D);
  if (!verify_result.ok || verify_result.T !== '000000') {
    return { ok: false, error: '前导校验失败' };
  }

  var salt = K_old + M + D + 'UPDATE';
  var md5_update = md5(salt);

  var new_key = '';
  for (var i = 0; i < 16; i++) {
    var hexByte = md5_update.substring(i * 2, i * 2 + 2);
    var byteVal = parseInt(hexByte, 16) % 10;
    var c = parseInt(enc_new_key.charAt(i));
    var p = (c - byteVal + 10) % 10;
    new_key += p.toString();
  }

  return { ok: true, new_key: new_key };
}

// ==================== 自测 ====================

function runSelfTest() {
  var K = '12345678';
  var M = '100';
  var D = '888';

  // 测试 MD5 向量
  var md5Test = md5('1234567890');
  if (md5Test !== 'e807f1fcf82d132f9bb018ca6738a19f') {
    return 'MD5 自检失败: ' + md5Test;
  }

  // 测试 checksum
  if (checksum('123') !== 150) {
    return 'checksum 自检失败: ' + checksum('123');
  }

  // 测试普通密码（自洽性：生成 → 验证）
  var pwd_normal = generate_password(K, M, D, '260630');
  var verify_normal = verify_8digit(pwd_normal, K, M, D);
  if (!verify_normal.ok || verify_normal.T !== '260630') {
    return '普通密码自洽失败: ' + JSON.stringify(verify_normal);
  }

  // 测试超级密码
  var pwd_super = generate_password(K, M, D, '999999');
  var verify_super = verify_8digit(pwd_super, K, M, D);
  if (!verify_super.ok || verify_super.type !== 'permanent') {
    return '超级密码验证失败: ' + JSON.stringify(verify_super);
  }

  // 测试密钥更新密码
  var K_new = '9876543210987654';
  var pwd_update = generate_update_password(K, M, D, K_new);
  if (pwd_update.length !== 24) {
    return '密钥更新密码长度错误: ' + pwd_update.length;
  }

  var verify_update_result = verify_update(pwd_update, K, M, D);
  if (!verify_update_result.ok || verify_update_result.new_key !== K_new) {
    return '密钥更新验证失败: ' + JSON.stringify(verify_update_result);
  }

  return 'OK';
}

// ============================================================
// 界面交互逻辑
// ============================================================

// DOM 元素
var mainPage = document.getElementById('mainPage');
var historyPage = document.getElementById('historyPage');

// 设置面板
var settingsToggle = document.getElementById('settingsToggle');
var settingsPanel = document.getElementById('settingsPanel');
var keyKInput = document.getElementById('keyK');
var keyMInput = document.getElementById('keyM');
var keyDInput = document.getElementById('keyD');

// 模式选择
var modeNormal = document.getElementById('modeNormal');
var modeSuper = document.getElementById('modeSuper');
var modeUpdate = document.getElementById('modeUpdate');

// 输入区域
var dateGroup = document.getElementById('dateGroup');
var dateInput = document.getElementById('expireDate');
var newKeyGroup = document.getElementById('newKeyGroup');
var newKeyInput = document.getElementById('newKey');

// 输出区域
var calcBtn = document.getElementById('calcBtn');
var outputArea = document.getElementById('outputArea');
var passwordLabel = document.getElementById('passwordLabel');
var passwordEl = document.getElementById('password');
var copyBtn = document.getElementById('copyPwd');
var errorMsg = document.getElementById('errorMsg');
var verifyHint = document.getElementById('verifyHint');

// 历史
var historyBtn = document.getElementById('historyBtn');
var backBtn = document.getElementById('backBtn');
var clearBtn = document.getElementById('clearBtn');
var historyList = document.getElementById('historyList');

// ==================== 状态 ====================

var currentMode = 'normal'; // 'normal' | 'super' | 'update'

// ==================== 初始化 ====================

// 设置默认值
keyKInput.value = '12345678';
keyMInput.value = '100';
keyDInput.value = '888';

// 日期默认今天
var today = new Date();
var yyyy = today.getFullYear().toString();
var mm = (today.getMonth() + 1).toString().padStart(2, '0');
var dd = today.getDate().toString().padStart(2, '0');
dateInput.value = yyyy.substring(2) + mm + dd;

// ==================== 设置面板折叠 ====================

settingsToggle.addEventListener('click', function() {
  if (settingsPanel.style.display === 'none') {
    settingsPanel.style.display = 'block';
    settingsToggle.textContent = '⚙️ 参数设置 ▲';
  } else {
    settingsPanel.style.display = 'none';
    settingsToggle.textContent = '⚙️ 参数设置 ▼';
  }
});

// ==================== 模式切换 ====================

modeNormal.addEventListener('click', function() { switchMode('normal'); });
modeSuper.addEventListener('click', function() { switchMode('super'); });
modeUpdate.addEventListener('click', function() { switchMode('update'); });

function switchMode(mode) {
  currentMode = mode;

  // 更新标签样式
  modeNormal.className = mode === 'normal' ? 'mode-tab active' : 'mode-tab';
  modeSuper.className = mode === 'super' ? 'mode-tab active' : 'mode-tab';
  modeUpdate.className = mode === 'update' ? 'mode-tab active' : 'mode-tab';

  // 切换输入区域
  if (mode === 'normal') {
    dateGroup.style.display = 'block';
    newKeyGroup.style.display = 'none';
    passwordLabel.textContent = '分期密码';
    calcBtn.textContent = '生成分期密码';
  } else if (mode === 'super') {
    dateGroup.style.display = 'none';
    newKeyGroup.style.display = 'none';
    passwordLabel.textContent = '超级密码';
    calcBtn.textContent = '生成超级密码';
  } else if (mode === 'update') {
    dateGroup.style.display = 'none';
    newKeyGroup.style.display = 'block';
    passwordLabel.textContent = '更新密码';
    calcBtn.textContent = '生成更新密码';
  }

  // 清空结果
  outputArea.classList.remove('show');
  errorMsg.textContent = '';
  verifyHint.textContent = '';
}

// ==================== 计算 ====================

calcBtn.addEventListener('click', function() {
  var K = keyKInput.value.trim();
  var M = keyMInput.value.trim();
  var D = keyDInput.value.trim();

  // 校验
  if (!K) { showError('请设置主密钥 K'); return; }
  if (K.length < 8 || K.length > 16) { showError('主密钥 K 需为 8~16 位数字'); return; }
  if (!/^\d+$/.test(K)) { showError('主密钥 K 必须为纯数字'); return; }
  if (!M) { showError('请设置厂商代码 M'); return; }
  if (!/^\d+$/.test(M)) { showError('厂商代码 M 必须为纯数字'); return; }
  if (!D) { showError('请输入设备唯一码 D'); return; }
  if (!/^\d+$/.test(D)) { showError('设备唯一码 D 必须为纯数字'); return; }

  var password = '';
  var T = '';
  var desc = '';

  if (currentMode === 'normal') {
    T = dateInput.value.trim();
    if (!T || T.length !== 6 || !/^\d{6}$/.test(T)) {
      showError('到期时间格式错误，需为 6 位数字 YYMMDD');
      return;
    }
    password = generate_password(K, M, D, T);
    desc = '普通分期密码 (到期: ' + T + ')';

  } else if (currentMode === 'super') {
    T = '999999';
    password = generate_password(K, M, D, '999999');
    desc = '超级密码 (永久关闭分期)';

  } else if (currentMode === 'update') {
    var K_new = newKeyInput.value.trim();
    if (!K_new) { showError('请输入新密钥 K_new'); return; }
    if (K_new.length !== 16) { showError('新密钥 K_new 需为 16 位数字'); return; }
    if (!/^\d+$/.test(K_new)) { showError('新密钥 K_new 必须为纯数字'); return; }
    T = '000000';
    password = generate_update_password(K, M, D, K_new);
    desc = '密钥更新密码 (新密钥: ' + K_new + ')';
  }

  errorMsg.textContent = '';

  // 显示结果
  passwordEl.textContent = password;
  outputArea.classList.add('show');

  // 自检验证
  var verifyStr = '';
  if (currentMode === 'update') {
    var v = verify_update(password, K, M, D);
    if (v.ok) {
      verifyStr = '✅ 自检通过 → 新密钥: ' + v.new_key;
    } else {
      verifyStr = '❌ 自检失败: ' + v.error;
    }
  } else {
    var v = verify_8digit(password, K, M, D);
    if (v.ok) {
      if (v.type === 'permanent') {
        verifyStr = '✅ 自检通过 → 类型: 永久关闭';
      } else if (v.type === 'update') {
        verifyStr = '✅ 自检通过 → 类型: 密钥更新前导';
      } else {
        verifyStr = '✅ 自检通过 → 解密到期日: 20' + v.T.substring(0,2) + '-' + v.T.substring(2,4) + '-' + v.T.substring(4,6);
      }
    } else {
      verifyStr = '❌ 自检失败: ' + v.error;
    }
  }
  verifyHint.textContent = verifyStr;

  // 保存历史
  var historyT = (currentMode === 'normal') ? dateInput.value : T;
  saveHistory(K, M, D, historyT, password, desc);
});

// ==================== 复制 ====================

copyBtn.addEventListener('click', function() {
  copyText(passwordEl.textContent);
});

// ==================== 历史记录切换 ====================

historyBtn.addEventListener('click', function() {
  mainPage.classList.remove('active');
  historyPage.classList.add('active');
  loadHistory();
});

backBtn.addEventListener('click', function() {
  historyPage.classList.remove('active');
  mainPage.classList.add('active');
});

clearBtn.addEventListener('click', function() {
  if (confirm('确定要清空所有历史记录吗？')) {
    localStorage.removeItem('calcHistory');
    loadHistory();
  }
});

// ==================== 历史记录 ====================

var HISTORY_KEY = 'calcHistory';

function saveHistory(K, M, D, T, password, desc) {
  var records = getHistory();
  records.unshift({
    id: Date.now(),
    time: new Date().toLocaleString('zh-CN'),
    K: K,
    M: M,
    D: D,
    T: T,
    password: password,
    desc: desc
  });
  if (records.length > 500) { records.pop(); }
  localStorage.setItem(HISTORY_KEY, JSON.stringify(records));
}

function getHistory() {
  try {
    var data = localStorage.getItem(HISTORY_KEY);
    return data ? JSON.parse(data) : [];
  } catch (e) { return []; }
}

function loadHistory() {
  var records = getHistory();
  if (records.length === 0) {
    historyList.innerHTML = '<div class="empty-hint">暂无记录</div>';
    return;
  }
  var html = '';
  records.forEach(function(r) {
    html += '<div class="history-item">' +
      '<div class="hi-time">🕐 ' + escapeHtml(r.time) + '</div>' +
      '<div class="hi-row"><span>主密钥 K</span><span>' + escapeHtml(r.K) + '</span></div>' +
      '<div class="hi-row"><span>厂商码 M</span><span>' + escapeHtml(r.M) + '</span></div>' +
      '<div class="hi-row"><span>设备码 D</span><span>' + escapeHtml(r.D) + '</span></div>' +
      '<div class="hi-row"><span>T</span><span>' + escapeHtml(r.T) + '</span></div>' +
      '<div class="hi-row"><span>类型</span><span>' + escapeHtml(r.desc) + '</span></div>' +
      '<div class="hi-result">密码：' + escapeHtml(r.password) + '</div>' +
      '</div>';
  });
  historyList.innerHTML = html;
}

// ==================== 工具函数 ====================

function copyText(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('已复制 ✅');
    });
  } else {
    var textarea = document.createElement('textarea');
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
  setTimeout(function() { errorMsg.textContent = ''; }, 4000);
}

function showToast(msg) {
  var toast = document.querySelector('.toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(function() { toast.classList.remove('show'); }, 1500);
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ==================== 启动自检 ====================

console.log('自检结果: ' + runSelfTest());
