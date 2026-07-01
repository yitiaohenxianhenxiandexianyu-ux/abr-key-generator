-- 数字版维吉尼亚密码
function vigenereNumber(numStr)
    local result = {}
    local keyStr = "26070199"
    local keyLen = #keyStr
    print("9")
    for i = 1, #numStr do
        local digit = tonumber(numStr:sub(i, i))
        local keyDigit = tonumber(keyStr:sub((i-1) % keyLen + 1, (i-1) % keyLen + 1))
        local newDigit = (digit + keyDigit) % 10
        table.insert(result, newDigit)
    end
    
    return table.concat(result)
end

-- 解密
function vigenereNumberDecrypt(encryptedStr, keyStr)
    local result = {}
    local keyLen = #keyStr
    
    for i = 1, #encryptedStr do
        local digit = tonumber(encryptedStr:sub(i, i))
        local keyDigit = tonumber(keyStr:sub((i-1) % keyLen + 1, (i-1) % keyLen + 1))
        local newDigit = (digit - keyDigit + 10) % 10
        table.insert(result, newDigit)
    end
    
    return table.concat(result)
end

--~ --[[
--------------------------------------------------------------------
-- 纯 Lua 实现 MD5（与上位机完全一致）
--------------------------------------------------------------------
local md5 = {}

-- 位操作函数
function band(a, b)
    local result = 0
    local bitval = 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then
            result = result + bitval
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bitval = bitval * 2
    end
    return result
end

function bor(a, b)
    local result = 0
    local bitval = 1
    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit == 1 or bbit == 1 then
            result = result + bitval
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bitval = bitval * 2
    end
    return result
end

function bxor(a, b)
    local result = 0
    local bitval = 1
    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit ~= bbit then
            result = result + bitval
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bitval = bitval * 2
    end
    return result
end

function lshift(a, n)
    return math.floor(a * (2 ^ n)) % 4294967296
end

function rshift(a, n)
    return math.floor(a / (2 ^ n))
end

function bnot(a)
    return 4294967295 - a
end

function rol(x, n)
    return bor(lshift(x, n), rshift(x, 32 - n))
end

function to_le_bytes(n)
    return string.char(band(n, 0xFF),
                       band(rshift(n, 8), 0xFF),
                       band(rshift(n, 16), 0xFF),
                       band(rshift(n, 24), 0xFF))
end

function from_le_bytes(s, pos)
    pos = pos or 1
    local a, b, c, d = string.byte(s, pos, pos + 3)
    return a + lshift(b, 8) + lshift(c, 16) + lshift(d, 24)
end

local T = {}
for i = 1, 64 do
    T[i] = math.floor(4294967296 * math.abs(math.sin(i)))
end

local function F(x, y, z) return bor(band(x, y), band(bnot(x), z)) end
local function G(x, y, z) return bor(band(x, z), band(y, bnot(z))) end
local function H(x, y, z) return bxor(x, bxor(y, z)) end
local function I(x, y, z) return bxor(y, bor(x, bnot(z))) end

function round(func, a, b, c, d, k, s, i, data)
    return rol(b + func(a, b, c) + from_le_bytes(data, k * 4 - 3) + T[i], s) + a
end

function md5.sum(message)
    local a0 = 0x67452301
    local b0 = 0xefcdab89
    local c0 = 0x98badcfe
    local d0 = 0x10325476

    local len = #message
    local zeros = (64 - ((len + 1 + 8) % 64)) % 64
    local msg = message .. "\128" .. string.rep("\0", zeros) .. to_le_bytes(len * 8) .. "\0\0\0\0"

    for i = 1, #msg, 64 do
        local block = string.sub(msg, i, i + 63)
        local a, b, c, d = a0, b0, c0, d0

        -- 第1轮
        a = round(F, a, b, c, d,  1,  7,  1, block)
        d = round(F, d, a, b, c,  2, 12,  2, block)
        c = round(F, c, d, a, b,  3, 17,  3, block)
        b = round(F, b, c, d, a,  4, 22,  4, block)
        a = round(F, a, b, c, d,  5,  7,  5, block)
        d = round(F, d, a, b, c,  6, 12,  6, block)
        c = round(F, c, d, a, b,  7, 17,  7, block)
        b = round(F, b, c, d, a,  8, 22,  8, block)
        a = round(F, a, b, c, d,  9,  7,  9, block)
        d = round(F, d, a, b, c, 10, 12, 10, block)
        c = round(F, c, d, a, b, 11, 17, 11, block)
        b = round(F, b, c, d, a, 12, 22, 12, block)
        a = round(F, a, b, c, d, 13,  7, 13, block)
        d = round(F, d, a, b, c, 14, 12, 14, block)
        c = round(F, c, d, a, b, 15, 17, 15, block)
        b = round(F, b, c, d, a, 16, 22, 16, block)

        -- 第2轮
        a = round(G, a, b, c, d,  2,  5, 17, block)
        d = round(G, d, a, b, c,  7,  9, 18, block)
        c = round(G, c, d, a, b, 12, 14, 19, block)
        b = round(G, b, c, d, a,  1, 20, 20, block)
        a = round(G, a, b, c, d,  6,  5, 21, block)
        d = round(G, d, a, b, c, 11,  9, 22, block)
        c = round(G, c, d, a, b, 16, 14, 23, block)
        b = round(G, b, c, d, a,  5, 20, 24, block)
        a = round(G, a, b, c, d, 10,  5, 25, block)
        d = round(G, d, a, b, c, 15,  9, 26, block)
        c = round(G, c, d, a, b,  4, 14, 27, block)
        b = round(G, b, c, d, a,  9, 20, 28, block)
        a = round(G, a, b, c, d, 14,  5, 29, block)
        d = round(G, d, a, b, c,  3,  9, 30, block)
        c = round(G, c, d, a, b,  8, 14, 31, block)
        b = round(G, b, c, d, a, 13, 20, 32, block)

        -- 第3轮
        a = round(H, a, b, c, d,  6,  4, 33, block)
        d = round(H, d, a, b, c,  9, 11, 34, block)
        c = round(H, c, d, a, b, 12, 16, 35, block)
        b = round(H, b, c, d, a, 15, 23, 36, block)
        a = round(H, a, b, c, d,  2,  4, 37, block)
        d = round(H, d, a, b, c,  5, 11, 38, block)
        c = round(H, c, d, a, b,  8, 16, 39, block)
        b = round(H, b, c, d, a, 11, 23, 40, block)
        a = round(H, a, b, c, d, 14,  4, 41, block)
        d = round(H, d, a, b, c,  1, 11, 42, block)
        c = round(H, c, d, a, b,  4, 16, 43, block)
        b = round(H, b, c, d, a,  7, 23, 44, block)
        a = round(H, a, b, c, d, 10,  4, 45, block)
        d = round(H, d, a, b, c, 13, 11, 46, block)
        c = round(H, c, d, a, b, 16, 16, 47, block)
        b = round(H, b, c, d, a,  3, 23, 48, block)

        -- 第4轮
        a = round(I, a, b, c, d,  1,  6, 49, block)
        d = round(I, d, a, b, c,  8, 10, 50, block)
        c = round(I, c, d, a, b, 15, 15, 51, block)
        b = round(I, b, c, d, a,  6, 21, 52, block)
        a = round(I, a, b, c, d, 13,  6, 53, block)
        d = round(I, d, a, b, c,  4, 10, 54, block)
        c = round(I, c, d, a, b, 11, 15, 55, block)
        b = round(I, b, c, d, a,  2, 21, 56, block)
        a = round(I, a, b, c, d,  9,  6, 57, block)
        d = round(I, d, a, b, c, 16, 10, 58, block)
        c = round(I, c, d, a, b,  7, 15, 59, block)
        b = round(I, b, c, d, a, 14, 21, 60, block)
        a = round(I, a, b, c, d,  5,  6, 61, block)
        d = round(I, d, a, b, c, 12, 10, 62, block)
        c = round(I, c, d, a, b,  3, 15, 63, block)
        b = round(I, b, c, d, a, 10, 21, 64, block)

        a0 = (a0 + a) % 4294967296
        b0 = (b0 + b) % 4294967296
        c0 = (c0 + c) % 4294967296
        d0 = (d0 + d) % 4294967296
    end

    return string.format("%08x%08x%08x%08x", a0, b0, c0, d0)
end

-- 封装成与之前兼容的函数名
function md5_string(str)
    return md5.sum(str)
end

-- 取 MD5 结果的两个字节组成 0~99 的数（与上位机一致）
function md5_to_mac(md5_hex)
    local len = #md5_hex
    local b1 = tonumber(string.sub(md5_hex, len-3, len-2), 16)
    local b2 = tonumber(string.sub(md5_hex, len-1, len), 16)
    return ((b1 * 256 + b2) % 100)
end

--------------------------------------------------------------------
-- 初始化寄存器（设置默认 K, M, D）
--------------------------------------------------------------------
function hmi_init()
we_bas_setword("@W_0#HDW3500",1)
local sBoardType, sMachineID, sImageList = we_bas_getmachineinfo()
    K = "26070199"
    M = tostring(we_bas_getstring("@W_0#HAW300",6))
    D = string.sub(tostring(sMachineID or 888888) , -6) 
    we_bas_setstring("@W_0#HAW220",D)
    --~ print("sMachineID",sMachineID)
    print(string.format("hmi_init K = %s M = %s D = %s",K,M,D))
end

--------------------------------------------------------------------
-- 模拟当前日期
--------------------------------------------------------------------
local function get_current_date()
local year = string.sub(tostring(we_bas_getword("@W_0#HSW28")), -2) 
local month = string.format("%02d",we_bas_getword("@W_0#HSW29"))
local day = string.format("%02d",we_bas_getword("@W_0#HSW30"))

local T_normal = year..month..day
return T_normal
end

--------------------------------------------------------------------
-- 密码解析依赖函数
--------------------------------------------------------------------
-- 自定义 8 位累加校验和
local function checksum(str)
    local sum = 0
    for i = 1, #str do
        sum = (sum + string.byte(str, i)) % 256
    end
    return sum
end

-- 从 K, M, D, T 派生加密流（T 可选，与上位机完全一致）
function derive_streams(T)
    local S = K .. M .. D
    if T then S = S .. T end
    local md5_main = md5_string(S)

    local Stream1 = {}
    for i = 1, 6 do
        local byte_str = string.sub(md5_main, 2*i-1, 2*i)
        Stream1[i] = tonumber(byte_str, 16) % 10
    end

    local byte7 = tonumber(string.sub(md5_main, 13, 14), 16)
    local byte8 = tonumber(string.sub(md5_main, 15, 16), 16)
    local Stream2_val = (byte7 * 256 + byte8) % 100

    return Stream1, Stream2_val
end

--------------------------------------------------------------------
-- 核心验证函数
--------------------------------------------------------------------

-- 生成密码（与上位机完全一致，用于穷举验证）
function generate_password(T)
    local S1, _ = derive_streams(T)
    local fb_hex = md5_string(K .. M .. D .. T)
    local fb = (tonumber(string.sub(fb_hex, 1, 2), 16) * 256
             + tonumber(string.sub(fb_hex, 3, 4), 16)) % 10
    fb = (fb + tonumber(string.sub(fb_hex, 5, 6), 16)) % 10

    local C = ""
    for i = 1, 6 do
        local t = tonumber(string.sub(T, i, i))
        local pert_str = md5_string(K .. M .. D .. (i-1) .. fb)
        local pert = tonumber(string.sub(pert_str, 1, 2), 16) % 10
        local c = (t + S1[i] + pert + fb) % 10
        C = C .. tostring(c)
        fb = c
    end

    local mac = md5_to_mac(md5_string(K .. M .. D .. T))
    return C .. string.format("%02d", mac)
end

-- 日期递增（YYMMDD 格式 +1 天）
function next_day(yymmdd)
    local yy = tonumber(string.sub(yymmdd, 1, 2))
    local mm = tonumber(string.sub(yymmdd, 3, 4))
    local dd = tonumber(string.sub(yymmdd, 5, 6))
    -- 简化：用 2000+yy 年
    local days_in_month = {31,28,31,30,31,30,31,31,30,31,30,31}
    local full_year = 2000 + yy
    if full_year % 4 == 0 and (full_year % 100 ~= 0 or full_year % 400 == 0) then
        days_in_month[2] = 29
    end
    dd = dd + 1
    if dd > days_in_month[mm] then
        dd = 1; mm = mm + 1
        if mm > 12 then mm = 1; yy = yy + 1 end
    end
    return string.format("%02d%02d%02d", yy, mm, dd)
end

-- 验证 8 位密码（MAC 预筛 + 窄范围穷举）
-- 返回: (是否通过, 到期时间或状态)
function verify_8digit(pwd, current_fn)
    if #pwd ~= 8 then return false, "长度错误" end
    local mac_in = tonumber(string.sub(pwd, 7, 8))

    -- 先检查超级密码（MAC 快速验证）
    if md5_to_mac(md5_string(K .. M .. D .. "999999")) == mac_in
       and generate_password("999999") == pwd then return true, "permanent" end
    -- 检查密钥更新前导
    if md5_to_mac(md5_string(K .. M .. D .. "000000")) == mac_in
       and generate_password("000000") == pwd then return true, "000000" end

    -- 从当前日期起穷举（90 天，MAC 预筛）
    local T_try = get_current_date()
    for _ = 1, 90 do
        T_try = next_day(T_try)
        -- MAC 快速预筛（仅 1 次 MD5）
        if md5_to_mac(md5_string(K .. M .. D .. T_try)) == mac_in then
            -- MAC 命中 → 完整验证
            if generate_password(T_try) == pwd then
                if current_fn and T_try <= current_fn() then return false, "过期" end
                return true, T_try
            end
        end
    end

    return false, "MAC错误"
end


-- 验证 24 位密钥更新密码
function verify_update(pwd_24digit)
    if #pwd_24digit ~= 24 then
        return false, "长度错误"
    end

    local front8 = string.sub(pwd_24digit, 1, 8)
    local enc_new_key = string.sub(pwd_24digit, 9, 24)

    -- 前8位必须能解出 T="000000"
    local ok, T_str = verify_8digit(front8)
    if not ok or T_str ~= "000000" then
        return false, "前导校验失败"
    end

    -- 解密新密钥
    local S = K .. M .. D
    local md5_update = md5_string(S .. "UPDATE")
    local new_key = ""
    for i = 1, 16 do
        local byte = tonumber(string.sub(md5_update, 2*i-1, 2*i), 16)
        local ks = byte % 10
        local c = tonumber(string.sub(enc_new_key, i, i))
        local p = (c - ks + 10) % 10
        new_key = new_key .. tostring(p)
    end

    return true, new_key
end

--------------------------------------------------------------------
-- 处理接收到的密码
--------------------------------------------------------------------
function process_received_password(pwd_str)
    local len = #pwd_str
    if len == 8 then
        local ok, result = verify_8digit(pwd_str)
        if not ok then
            print(we_u8ta("[错误] " .. tostring(result)))
        elseif result == "permanent" then
            print(we_u8ta("[永久解除] 关闭分期付款功能"))
            disable_installment()
        else
            print(we_u8ta("[成功] 下一期到期时间: " .. result))
            write_expiry_register(result)
            return 1,result
        end
    elseif len == 24 then
        local ok, new_k = verify_update(pwd_str)
        if ok then
            print(we_u8ta("[密钥更新] 新密钥已生效: " .. new_k))
            -- K = new_k; save_K(new_k)
        else
            print(we_u8ta("[密钥更新失败] " .. tostring(new_k)))
        end
    else
        print(we_u8ta("[错误] 密码长度无效"))
    end
end
function write_expiry_register(result)
local year = string.sub(result,1,2)
local month = string.sub(result,3,4)
local day = string.sub(result,5,6)
we_bas_setword("@W_0#HAW310",tonumber(year))
we_bas_setword("@W_0#HAW311",tonumber(month))
we_bas_setword("@W_0#HAW312",tonumber(day))
end
function disable_installment()
we_bas_setword("@W_0#HAW310",99)
we_bas_setword("@W_0#HAW311",99)
we_bas_setword("@W_0#HAW312",99)   
end
--------------------------------------------------------------------
-- 测试函数
--------------------------------------------------------------------
function hmitest()
    print(we_u8ta("===== 触摸屏解析流程测试 ====="))
    print(we_u8ta("当前参数 K=" .. K .. " M=" .. M .. " D=" .. D))
    print(we_u8ta("当前日期 " .. get_current_date()))
    print(we_u8ta(""))

    -- 测试1：普通分期密码
    local pwd_normal = we_bas_getstring("@W_0#HDW500",25)
    print(we_u8ta("[测试1] 输入普通密码: " .. pwd_normal))
    process_received_password(pwd_normal)

    -- 测试2：超级密码（永久解除）
    local pwd_super = we_bas_getstring("@W_0#HDW1100",25)   -- 示例值，请替换为实际计算结果
    print(we_u8ta("[测试2] 输入超级密码: " .. pwd_super))
    process_received_password(pwd_super)

    -- ~ print(we_u8ta(""))

    -- 测试3：密钥更新密码（新密钥 9876543210987654）
    local pwd_update = we_bas_getstring("@W_0#HDW1200",25)  -- 示例 24 位
    print(we_u8ta("[测试3] 输入密钥更新密码: " .. pwd_update))
    process_received_password(pwd_update)

    -- ~ print(we_u8ta(""))
    print(we_u8ta("===== 解析测试结束 ====="))
end