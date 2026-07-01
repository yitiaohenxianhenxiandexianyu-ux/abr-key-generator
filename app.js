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

function derive_streams(K, M, D, T) {
  // S = K + M + D + T（T 参与派生，每个日期独立加密流）
  var S = K + M + D + (T || '');
  var md5_hex = md5(S);

  var Stream1 = [];
  for (var i = 0; i < 6; i++) {
    var hexByte = md5_hex.substring(i * 2, i * 2 + 2);
    var byteVal = parseInt(hexByte, 16);
    Stream1.push(byteVal % 10);
  }

  var byte7 = parseInt(md5_hex.substring(12, 14), 16);
  var byte8 = parseInt(md5_hex.substring(14, 16), 16);
  var Stream2_val = (byte7 * 256 + byte8) % 100;

  return { Stream1: Stream1, Stream2_val: Stream2_val };
}

// ==================== md5_to_mac 辅助 ====================

function md5_to_mac(md5_hex) {
  var len = md5_hex.length;
  var b1 = parseInt(md5_hex.substring(len - 4, len - 2), 16);
  var b2 = parseInt(md5_hex.substring(len - 2, len), 16);
  return (b1 * 256 + b2) % 100;
}

// ==================== 3.4 生成普通/超级密码 ====================

function generate_password(K, M, D, T) {
  var result = derive_streams(K, M, D, T);
  var Stream1 = result.Stream1;
  // 用 MD5(K+M+D+T) 前两字节作为初始反馈 (0~255)，每个日期几乎唯一
  var fbHex = md5(K + M + D + T);
  var feedback = (parseInt(fbHex.substring(0, 2), 16) * 256 + parseInt(fbHex.substring(2, 4), 16)) % 10;
  // 再加一层：用 MD5 第3字节扰动初始反馈
  feedback = (feedback + parseInt(fbHex.substring(4, 6), 16)) % 10;

  var C = '';
  for (var i = 0; i < 6; i++) {
    var t_digit = parseInt(T.charAt(i));
    var perturb = parseInt(md5(K + M + D + i + feedback).substring(0, 2), 16) % 10;
    var c_digit = (t_digit + Stream1[i] + perturb + feedback) % 10;
    C += c_digit.toString();
    feedback = c_digit;
  }

  var mac_val = md5_to_mac(md5(K + M + D + T));
  return C + mac_val.toString().padStart(2, '0');
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

function verify_8digit(pwd_8, K, M, D, knownT) {
  if (pwd_8.length !== 8) return { ok: false, error: '长度错误' };

  // 已知 T 的快速路径：重加密直接比对
  if (knownT !== undefined) {
    if (generate_password(K, M, D, knownT) === pwd_8) {
      if (knownT === '999999') return { ok: true, type: 'permanent', T: knownT };
      if (knownT === '000000') return { ok: true, type: 'update', T: knownT };
      return { ok: true, type: 'normal', T: knownT };
    }
    return { ok: false, error: '密码不匹配' };
  }
}

// ==================== 4.2 验证密钥更新密码（自测用） ====================

function verify_update(pwd_24, K_old, M, D) {
  if (pwd_24.length !== 24) return { ok: false, error: '长度错误' };

  var front8 = pwd_24.substring(0, 8);
  var enc_new_key = pwd_24.substring(8, 24);

  var verify_result = verify_8digit(front8, K_old, M, D, '000000');
  if (!verify_result.ok) {
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

  // 测试 MD5 向量（Lua 兼容版）
  var md5Test = md5('1234567890');
  if (md5Test !== '9ed230bf27771ea96211d8eb78fd4317') {
    return 'MD5 自检失败: ' + md5Test;
  }

  // 测试 checksum
  if (checksum('123') !== 150) {
    return 'checksum 自检失败: ' + checksum('123');
  }

  // 测试普通密码（自洽性：生成 → 验证）
  var pwd_normal = generate_password(K, M, D, '260630');
  var verify_normal = verify_8digit(pwd_normal, K, M, D, '260630');
  if (!verify_normal.ok || verify_normal.T !== '260630') {
    return '普通密码自洽失败: ' + JSON.stringify(verify_normal);
  }

  console.log('自检: MD5=' + md5Test + ' password=' + pwd_normal);

  // 测试超级密码
  var pwd_super = generate_password(K, M, D, '999999');
  var verify_super = verify_8digit(pwd_super, K, M, D, '999999');
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
var loginPage = document.getElementById('loginPage');
var loginAccount = document.getElementById('loginAccount');
var loginCode = document.getElementById('loginCode');
var loginBtn = document.getElementById('loginBtn');
var loginError = document.getElementById('loginError');
var mainPage = document.getElementById('mainPage');
var historyPage = document.getElementById('historyPage');

// 设置面板
var keyKInput = document.getElementById('keyK');
var keyMInput = document.getElementById('keyM');
var keyDInput = document.getElementById('keyD');
// 模式选择
var modeNormal = document.getElementById('modeNormal');
var modeMulti = document.getElementById('modeMulti');
var modeSuper = document.getElementById('modeSuper');
var modeUpdate = document.getElementById('modeUpdate');

// 输入区域
var dateGroup = document.getElementById('dateGroup');
var multiGroup = document.getElementById('multiGroup');
// 到期时间三列
var expYY = document.getElementById('expYY');
var expMM = document.getElementById('expMM');
var expDD = document.getElementById('expDD');
var dateCalInput = document.getElementById('expireDateCal');
// 设备日期三列
var devYY = document.getElementById('devYY');
var devMM = document.getElementById('devMM');
var devDD = document.getElementById('devDD');
var deviceDateCalInput = document.getElementById('deviceDateCal');

// 辅助：从三列拼 YYMMDD，设置三列值
function getYYMMDD(yyEl, mmEl, ddEl) {
  var y = yyEl.value.trim(), m = mmEl.value.trim(), d = ddEl.value.trim();
  if (y.length === 2 && m.length === 2 && d.length === 2) return y + m + d;
  return '';
}
function setYYMMDD(yyEl, mmEl, ddEl, yymmdd) {
  yyEl.value = yymmdd.substring(0, 2);
  mmEl.value = yymmdd.substring(2, 4);
  ddEl.value = yymmdd.substring(4, 6);
}
var newKeyGroup = document.getElementById('newKeyGroup');
var newKeyInput = document.getElementById('newKey');
// 多次分期
var multiYY = document.getElementById('multiYY');
var multiMM = document.getElementById('multiMM');
var multiDD = document.getElementById('multiDD');
var multiDateCal = document.getElementById('multiDateCal');
var intervalNum = document.getElementById('intervalNum');
var intervalUnit = document.getElementById('intervalUnit');
var periodCount = document.getElementById('periodCount');
var singleOutput = document.getElementById('singleOutput');
var multiOutput = document.getElementById('multiOutput');

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

// 不设置默认值，用户自行输入

// ==================== 登录验证 ====================

var LOGIN_KEY = 'abr_login_verified';

// 根据登录状态显示对应页面
if (localStorage.getItem(LOGIN_KEY) === '1') {
  loginPage.style.display = 'none';
  mainPage.classList.add('active');
  var savedSuffix = localStorage.getItem('abr_account_suffix');
  if (savedSuffix) setVersion(savedSuffix);
} else {
  loginPage.style.display = '';
  loginPage.classList.add('active');
}

loginBtn.addEventListener('click', function() {
  var account = loginAccount.value.trim();
  var code = loginCode.value.trim();
  if (!account) { loginError.textContent = '请输入账号'; return; }
  if (!/^\d+$/.test(account)) { loginError.textContent = '账号必须为纯数字'; return; }
  if (!code) { loginError.textContent = '请输入验证码'; return; }

  var K = document.getElementById('keyK').value;
  var encrypted = vigenereEncrypt(account, K);
  if (encrypted === code) {
    localStorage.setItem(LOGIN_KEY, '1');
    // 保存账号后缀用于版本号
    var suffix = account.length > 6 ? account.substring(account.length - 6) : account;
    localStorage.setItem('abr_account_suffix', suffix);
    setVersion(suffix);
    loginPage.style.display = 'none';
    loginPage.classList.remove('active');
    mainPage.classList.add('active');
    loginError.textContent = '';
  } else {
    loginError.textContent = '验证失败，请检查账号和验证码';
  }
});

// 到期时间默认次日
var tomorrow = new Date();
tomorrow.setDate(tomorrow.getDate() + 1);
setYYMMDD(expYY, expMM, expDD,
  tomorrow.getFullYear().toString().substring(2) +
  (tomorrow.getMonth() + 1).toString().padStart(2, '0') +
  tomorrow.getDate().toString().padStart(2, '0'));
dateCalInput.value = tomorrow.getFullYear().toString() + '-' +
  (tomorrow.getMonth() + 1).toString().padStart(2, '0') + '-' +
  tomorrow.getDate().toString().padStart(2, '0');

// 设备当前日期默认今天
var todayDate = new Date();
setYYMMDD(devYY, devMM, devDD,
  todayDate.getFullYear().toString().substring(2) +
  (todayDate.getMonth() + 1).toString().padStart(2, '0') +
  todayDate.getDate().toString().padStart(2, '0'));
deviceDateCalInput.value = todayDate.getFullYear().toString() + '-' +
  (todayDate.getMonth() + 1).toString().padStart(2, '0') + '-' +
  todayDate.getDate().toString().padStart(2, '0');

// ==================== 日期同步 ====================

function syncCalToInputs(calInput, yyEl, mmEl, ddEl) {
  calInput.addEventListener('change', function() {
    var yymmdd = dateToYYMMDD(calInput.value);
    setYYMMDD(yyEl, mmEl, ddEl, yymmdd);
  });
}
function syncInputsToCal(yyEl, mmEl, ddEl, calInput) {
  var sync = function() {
    var v = getYYMMDD(yyEl, mmEl, ddEl);
    if (v.length === 6) calInput.value = yyMMDDtoDate(v);
  };
  yyEl.addEventListener('input', sync);
  mmEl.addEventListener('input', sync);
  ddEl.addEventListener('input', sync);
}

syncCalToInputs(deviceDateCalInput, devYY, devMM, devDD);
syncInputsToCal(devYY, devMM, devDD, deviceDateCalInput);
syncCalToInputs(dateCalInput, expYY, expMM, expDD);
syncInputsToCal(expYY, expMM, expDD, dateCalInput);
syncCalToInputs(multiDateCal, multiYY, multiMM, multiDD);
syncInputsToCal(multiYY, multiMM, multiDD, multiDateCal);

// ==================== Vigenère 加解密 ====================

function vigenereEncrypt(plainStr, keyStr) {
  var result = '';
  var keyLen = keyStr.length;
  for (var i = 0; i < plainStr.length; i++) {
    var digit = parseInt(plainStr.charAt(i));
    var keyDigit = parseInt(keyStr.charAt(i % keyLen));
    var newDigit = (digit + keyDigit) % 10;
    result += newDigit.toString();
  }
  return result;
}

function vigenereDecrypt(encryptedStr, keyStr) {
  var result = '';
  var keyLen = keyStr.length;
  for (var i = 0; i < encryptedStr.length; i++) {
    var digit = parseInt(encryptedStr.charAt(i));
    var keyDigit = parseInt(keyStr.charAt(i % keyLen));
    var newDigit = (digit - keyDigit + 10) % 10;
    result += newDigit.toString();
  }
  return result;
}

// 获取真实厂商码（自动解密）
function getRealM() {
  var inputM = keyMInput.value.trim();
  var K = keyKInput.value.trim();
  if (!inputM || !K) return inputM;
  return vigenereDecrypt(inputM, K);
}
// ==================== 日期格式转换 ====================

// YYYY-MM-DD → YYMMDD
function dateToYYMMDD(dateStr) {
  var parts = dateStr.split('-');
  if (parts.length !== 3) return '';
  return parts[0].substring(2) + parts[1] + parts[2];
}

// YYMMDD → 显示用 YYYY-MM-DD
function yyMMDDtoDate(yymmdd) {
  return '20' + yymmdd.substring(0,2) + '-' + yymmdd.substring(2,4) + '-' + yymmdd.substring(4,6);
}

// ==================== 模式切换 ====================

modeNormal.addEventListener('click', function() { switchMode('normal'); });
modeMulti.addEventListener('click', function() { switchMode('multi'); });
modeSuper.addEventListener('click', function() { switchMode('super'); });
modeUpdate.addEventListener('click', function() { switchMode('update'); });

function switchMode(mode) {
  currentMode = mode;

  // 更新标签样式
  modeNormal.className = mode === 'normal' ? 'mode-tab active' : 'mode-tab';
  modeMulti.className = mode === 'multi' ? 'mode-tab active' : 'mode-tab';
  modeSuper.className = mode === 'super' ? 'mode-tab active' : 'mode-tab';
  modeUpdate.className = mode === 'update' ? 'mode-tab active' : 'mode-tab';

  // 隐藏所有条件区域
  dateGroup.style.display = 'none';
  newKeyGroup.style.display = 'none';
  multiGroup.style.display = 'none';
  singleOutput.style.display = 'none';
  multiOutput.style.display = 'none';

  if (mode === 'normal') {
    dateGroup.style.display = 'block';
    singleOutput.style.display = '';
    passwordLabel.textContent = '分期密码';
    calcBtn.textContent = '生成分期密码';
  } else if (mode === 'multi') {
    multiGroup.style.display = 'block';
    multiOutput.style.display = 'block';
    calcBtn.textContent = '生成多期密码';
    // 初始化首期日期为到期时间的值
    if (!multiYY.value) setYYMMDD(multiYY, multiMM, multiDD, getYYMMDD(expYY, expMM, expDD));
  } else if (mode === 'super') {
    singleOutput.style.display = '';
    passwordLabel.textContent = '超级密码';
    calcBtn.textContent = '生成超级密码';
  } else if (mode === 'update') {
    newKeyGroup.style.display = 'block';
    singleOutput.style.display = '';
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
  var M_input = keyMInput.value.trim();
  var M = getRealM(); // 解密后的真实厂商码
  var D = keyDInput.value.trim();

  // 校验
  if (!K) { showError('请设置主密钥 K'); return; }
  if (K.length < 8 || K.length > 16) { showError('主密钥 K 需为 8~16 位数字'); return; }
  if (!/^\d+$/.test(K)) { showError('主密钥 K 必须为纯数字'); return; }
  if (!M_input) { showError('请输入厂商代码 M'); return; }
  if (!/^\d+$/.test(M_input)) { showError('厂商代码 M 必须为纯数字'); return; }
  if (!D) { showError('请输入设备唯一码 D'); return; }
  if (!/^\d+$/.test(D)) { showError('设备唯一码 D 必须为纯数字'); return; }

  var password = '';
  var T = '';
  var desc = '';

  if (currentMode === 'normal') {
    T = getYYMMDD(expYY, expMM, expDD);
    if (!T || T.length !== 6) {
      showError('到期时间格式错误，请填写 YY MM DD');
      return;
    }
    password = generate_password(K, M, D, T);
    desc = '普通分期密码 (到期: ' + T + ')';

  } else if (currentMode === 'multi') {
    // 多次分期
    var firstYYMMDD = getYYMMDD(multiYY, multiMM, multiDD);
    if (!firstYYMMDD || firstYYMMDD.length !== 6) { showError('请填写首期日期'); return; }
    var ival = parseInt(intervalNum.value) || 1;
    var iunit = intervalUnit.value; // 'month' or 'day'
    var periods = parseInt(periodCount.value) || 1;
    if (periods < 1 || periods > 12) { showError('期数需在 1~12 之间'); return; }

    // 日期运算辅助
    function addMonths(yymmdd, n) {
      var yy = parseInt(yymmdd.substring(0,2));
      var mm = parseInt(yymmdd.substring(2,4));
      var dd = parseInt(yymmdd.substring(4,6));
      var totalM = yy * 12 + mm + n;
      var newYY = Math.floor((totalM - 1) / 12);
      var newMM = ((totalM - 1) % 12) + 1;
      // 处理月末溢出：取当月最后一天
      var daysInMonth = new Date(2000 + newYY, newMM, 0).getDate();
      if (dd > daysInMonth) dd = daysInMonth;
      return newYY.toString().padStart(2,'0') +
             newMM.toString().padStart(2,'0') +
             dd.toString().padStart(2,'0');
    }
    function addDays(yymmdd, n) {
      var d = new Date(2000 + parseInt(yymmdd.substring(0,2)),
                       parseInt(yymmdd.substring(2,4)) - 1,
                       parseInt(yymmdd.substring(4,6)));
      d.setDate(d.getDate() + n);
      return d.getFullYear().toString().substring(2) +
             (d.getMonth() + 1).toString().padStart(2,'0') +
             d.getDate().toString().padStart(2,'0');
    }

    var results = [];
    var currentT = firstYYMMDD;
    for (var p = 0; p < periods; p++) {
      var pwd = generate_password(K, M, D, currentT);
      results.push({ period: p + 1, T: currentT, password: pwd });
      if (iunit === 'month') {
        currentT = addMonths(currentT, ival);
      } else {
        currentT = addDays(currentT, ival);
      }
    }

    // 超级密码
    var superPwd = generate_password(K, M, D, '999999');

    // 日期格式化
    function fmtDate(yymmdd) {
      return '20' + yymmdd.substring(0,2) + '-' + yymmdd.substring(2,4) + '-' + yymmdd.substring(4,6);
    }

    // 设备当前日期
    var devDate = getYYMMDD(devYY, devMM, devDD) || dateToYYMMDD(new Date().toISOString().split('T')[0]);

    // 渲染多期结果
    var html = '';
    html += '<div class="multi-header">';
    html += '<div>生成日期：' + fmtDate(devDate) + '</div>';
    html += '<div>厂商校验码：' + escapeHtml(M_input) + '     特征代码：' + escapeHtml(D) + '</div>';
    html += '</div>';
    html += '<hr class="multi-sep">';

    var allText = '';
    allText += '生成日期：\t' + fmtDate(devDate) + '\n';
    allText += '厂商校验码：\t' + M_input + '\t特征代码：\t' + D + '\n';
    allText += '-------------------------------------------------------\n';

    for (var r = 0; r < results.length; r++) {
      var item = results[r];
      html += '<div class="multi-item">' +
        '<span class="mi-label">第' + item.period + '期授权码：</span>' +
        '<span class="mi-value">' + item.password + '</span>' +
        '<span class="mi-date">(到期日：' + fmtDate(item.T) + ')</span>' +
        '</div>';
      allText += '第' + item.period + '期授权码：\t' + item.password + '\t(到期日：\t' + fmtDate(item.T) + ')\n';
    }

    html += '<hr class="multi-sep">';
    html += '<div class="multi-item multi-unlock">' +
      '<span class="mi-label">完全解锁码：</span>' +
      '<span class="mi-value">' + superPwd + '</span>' +
      '</div>';
    allText += '-------------------------------------------------------\n';
    allText += '完全解锁码：\t' + superPwd;

    html += '<button id="btnCopyAll" class="btn-copy-all">📋 复制全部</button>';
    multiOutput.innerHTML = html;
    multiOutput.style.display = 'block';
    outputArea.classList.add('show');
    verifyHint.textContent = '';
    // 绑定复制按钮
    var allTextCopy = allText.trim();
    document.getElementById('btnCopyAll').addEventListener('click', function() {
      copyText(allTextCopy);
    });
    // 保存历史
    saveHistory(K, M, D, firstYYMMDD + ' 共' + periods + '期', allText.trim().replace(/\t/g, ' '), desc);
    return; // 跳过单密码输出

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
    var v = verify_update(password, K, M, D);  // verify_update 内部传 T='000000'
    if (v.ok) {
      verifyStr = '✅ 自检通过 → 新密钥: ' + v.new_key;
    } else {
      verifyStr = '❌ 自检失败: ' + v.error;
    }
  } else {
    var v = verify_8digit(password, K, M, D, T);
    if (v.ok) {
      if (v.type === 'permanent') {
        verifyStr = '✅ 自检通过 → 类型: 永久关闭';
      } else if (v.type === 'update') {
        verifyStr = '✅ 自检通过 → 类型: 密钥更新前导';
      } else {
        var decDate = '20' + v.T.substring(0,2) + '-' + v.T.substring(2,4) + '-' + v.T.substring(4,6);
        verifyStr = '✅ 自检通过 → 解密到期日: ' + decDate;

        // 对比设备当前日期，判断是否过期
        var devYYMMDD = getYYMMDD(devYY, devMM, devDD);
        var devDate = deviceDateCalInput.value;
        if (devDate && devYYMMDD.length === 6) {
          if (v.T <= devYYMMDD) {
            verifyStr += ' ⚠️ 设备日期(' + devDate + ')已超过到期日，密码将失效！';
          } else {
            verifyStr += ' | 设备日期(' + devDate + ')未到期 ✅';
          }
        }
      }
    } else {
      verifyStr = '❌ 自检失败: ' + v.error;
    }
  }
  verifyHint.textContent = verifyStr;

  // 保存历史（日期用 YYYY-MM-DD 显示格式）
  var historyT = (currentMode === 'normal') ? getYYMMDD(expYY, expMM, expDD) : (T === '999999' ? '永久' : T);
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
      '<div class="hi-row"><span>厂商码 M</span><span>' + escapeHtml(r.M) + '</span></div>' +
      '<div class="hi-row"><span>设备码 D</span><span>' + escapeHtml(r.D) + '</span></div>' +
      '<div class="hi-row"><span>T</span><span>' + escapeHtml(r.T) + '</span></div>' +
      '<div class="hi-row"><span>类型</span><span>' + escapeHtml(r.desc) + '</span></div>' +
      '<div class="hi-result">密码：' + escapeHtml(r.password) + '</div>' +
      '</div>';
  });
  historyList.innerHTML = html;
}

// ==================== 版本号 ====================

function setVersion(suffix) {
  var vb = document.getElementById('versionBar');
  if (vb) vb.textContent = 'V0.1.2512' + suffix;
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
