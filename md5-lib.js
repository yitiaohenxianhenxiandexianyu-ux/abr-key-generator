// ============================================================
// Lua-compatible MD5 - 1:1 对照设备 Lua 实现
// 关键：round 函数结构与标准 MD5 不同！
// ============================================================

(function() {

  // ---- 位操作函数（与 Lua 行为完全一致）----

  function band(a, b) {
    var result = 0;
    var bitval = 1;
    while (a > 0 && b > 0) {
      if (mod2(a) === 1 && mod2(b) === 1) result += bitval;
      a = Math.floor(a / 2);
      b = Math.floor(b / 2);
      bitval *= 2;
    }
    return result;
  }

  function bor(a, b) {
    var result = 0;
    var bitval = 1;
    while (a > 0 || b > 0) {
      var abit = mod2(a);
      var bbit = mod2(b);
      if (abit === 1 || bbit === 1) result += bitval;
      a = Math.floor(a / 2);
      b = Math.floor(b / 2);
      bitval *= 2;
    }
    return result;
  }

  function bxor(a, b) {
    var result = 0;
    var bitval = 1;
    while (a > 0 || b > 0) {
      var abit = mod2(a);
      var bbit = mod2(b);
      if (abit !== bbit) result += bitval;
      a = Math.floor(a / 2);
      b = Math.floor(b / 2);
      bitval *= 2;
    }
    return result;
  }

  function lshift(a, n) {
    return Math.floor(a * Math.pow(2, n)) % 4294967296;
  }

  function rshift(a, n) {
    return Math.floor(a / Math.pow(2, n));
  }

  function bnot(a) {
    return 4294967295 - a;
  }

  // Lua 的 % 始终返回非负余数，JS 需修正
  function mod2(n) {
    var r = n % 2;
    return r < 0 ? r + 2 : r;
  }

  function rol(x, n) {
    return bor(lshift(x, n), rshift(x, 32 - n));
  }

  // ---- 辅助函数 ----

  function to_le_bytes(n) {
    return String.fromCharCode(
      band(n, 0xFF),
      band(rshift(n, 8), 0xFF),
      band(rshift(n, 16), 0xFF),
      band(rshift(n, 24), 0xFF)
    );
  }

  function from_le_bytes(s, pos) {
    pos = pos || 0;
    var a = s.charCodeAt(pos);
    var b = s.charCodeAt(pos + 1);
    var c = s.charCodeAt(pos + 2);
    var d = s.charCodeAt(pos + 3);
    return a + lshift(b, 8) + lshift(c, 16) + lshift(d, 24);
  }

  // ---- T 常量表 ----
  var T = [];
  for (var i = 1; i <= 64; i++) {
    T[i] = Math.floor(4294967296 * Math.abs(Math.sin(i)));
  }

  // ---- 非线性函数 ----
  function F(x, y, z) { return bor(band(x, y), band(bnot(x), z)); }
  function G(x, y, z) { return bor(band(x, z), band(y, bnot(z))); }
  function H(x, y, z) { return bxor(x, bxor(y, z)); }
  function I(x, y, z) { return bxor(y, bor(x, bnot(z))); }

  // ---- 单轮运算（关键：与标准 MD5 不同！）----
  function round(func, a, b, c, d, k, s, i, data) {
    var pos = (k - 1) * 4;
    return rol(b + func(a, b, c) + from_le_bytes(data, pos) + T[i], s) + a;
  }

  // ---- MD5 主函数 ----
  window.md5 = function(message) {
    var a0 = 0x67452301;
    var b0 = 0xefcdab89;
    var c0 = 0x98badcfe;
    var d0 = 0x10325476;

    var len = message.length;

    // 计算需要补零的个数
    var zeros = (64 - ((len + 1 + 8) % 64)) % 64;

    // 构造完整消息
    var msg = message + '\x80' + '\x00'.repeat(zeros) + to_le_bytes(len * 8) + '\x00\x00\x00\x00';

    for (var i = 0; i < msg.length; i += 64) {
      var block = msg.substring(i, i + 64);
      var a = a0, b = b0, c = c0, d = d0;

      // 第1轮
      a = round(F, a, b, c, d,  1,  7,  1, block);
      d = round(F, d, a, b, c,  2, 12,  2, block);
      c = round(F, c, d, a, b,  3, 17,  3, block);
      b = round(F, b, c, d, a,  4, 22,  4, block);
      a = round(F, a, b, c, d,  5,  7,  5, block);
      d = round(F, d, a, b, c,  6, 12,  6, block);
      c = round(F, c, d, a, b,  7, 17,  7, block);
      b = round(F, b, c, d, a,  8, 22,  8, block);
      a = round(F, a, b, c, d,  9,  7,  9, block);
      d = round(F, d, a, b, c, 10, 12, 10, block);
      c = round(F, c, d, a, b, 11, 17, 11, block);
      b = round(F, b, c, d, a, 12, 22, 12, block);
      a = round(F, a, b, c, d, 13,  7, 13, block);
      d = round(F, d, a, b, c, 14, 12, 14, block);
      c = round(F, c, d, a, b, 15, 17, 15, block);
      b = round(F, b, c, d, a, 16, 22, 16, block);

      // 第2轮
      a = round(G, a, b, c, d,  2,  5, 17, block);
      d = round(G, d, a, b, c,  7,  9, 18, block);
      c = round(G, c, d, a, b, 12, 14, 19, block);
      b = round(G, b, c, d, a,  1, 20, 20, block);
      a = round(G, a, b, c, d,  6,  5, 21, block);
      d = round(G, d, a, b, c, 11,  9, 22, block);
      c = round(G, c, d, a, b, 16, 14, 23, block);
      b = round(G, b, c, d, a,  5, 20, 24, block);
      a = round(G, a, b, c, d, 10,  5, 25, block);
      d = round(G, d, a, b, c, 15,  9, 26, block);
      c = round(G, c, d, a, b,  4, 14, 27, block);
      b = round(G, b, c, d, a,  9, 20, 28, block);
      a = round(G, a, b, c, d, 14,  5, 29, block);
      d = round(G, d, a, b, c,  3,  9, 30, block);
      c = round(G, c, d, a, b,  8, 14, 31, block);
      b = round(G, b, c, d, a, 13, 20, 32, block);

      // 第3轮
      a = round(H, a, b, c, d,  6,  4, 33, block);
      d = round(H, d, a, b, c,  9, 11, 34, block);
      c = round(H, c, d, a, b, 12, 16, 35, block);
      b = round(H, b, c, d, a, 15, 23, 36, block);
      a = round(H, a, b, c, d,  2,  4, 37, block);
      d = round(H, d, a, b, c,  5, 11, 38, block);
      c = round(H, c, d, a, b,  8, 16, 39, block);
      b = round(H, b, c, d, a, 11, 23, 40, block);
      a = round(H, a, b, c, d, 14,  4, 41, block);
      d = round(H, d, a, b, c,  1, 11, 42, block);
      c = round(H, c, d, a, b,  4, 16, 43, block);
      b = round(H, b, c, d, a,  7, 23, 44, block);
      a = round(H, a, b, c, d, 10,  4, 45, block);
      d = round(H, d, a, b, c, 13, 11, 46, block);
      c = round(H, c, d, a, b, 16, 16, 47, block);
      b = round(H, b, c, d, a,  3, 23, 48, block);

      // 第4轮
      a = round(I, a, b, c, d,  1,  6, 49, block);
      d = round(I, d, a, b, c,  8, 10, 50, block);
      c = round(I, c, d, a, b, 15, 15, 51, block);
      b = round(I, b, c, d, a,  6, 21, 52, block);
      a = round(I, a, b, c, d, 13,  6, 53, block);
      d = round(I, d, a, b, c,  4, 10, 54, block);
      c = round(I, c, d, a, b, 11, 15, 55, block);
      b = round(I, b, c, d, a,  2, 21, 56, block);
      a = round(I, a, b, c, d,  9,  6, 57, block);
      d = round(I, d, a, b, c, 16, 10, 58, block);
      c = round(I, c, d, a, b,  7, 15, 59, block);
      b = round(I, b, c, d, a, 14, 21, 60, block);
      a = round(I, a, b, c, d,  5,  6, 61, block);
      d = round(I, d, a, b, c, 12, 10, 62, block);
      c = round(I, c, d, a, b,  3, 15, 63, block);
      b = round(I, b, c, d, a, 10, 21, 64, block);

      a0 = (a0 + a) % 4294967296;
      b0 = (b0 + b) % 4294967296;
      c0 = (c0 + c) % 4294967296;
      d0 = (d0 + d) % 4294967296;
    }

    function toHex8(v) {
      var h = v.toString(16);
      while (h.length < 8) h = '0' + h;
      return h;
    }

    return toHex8(a0) + toHex8(b0) + toHex8(c0) + toHex8(d0);
  };

})();
