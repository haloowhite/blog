---
layout: post
title: "有手就行系列——抖音 a_bogus 纯算构造（bdms 1.0.1.19 完整逆向）"
date: 2026-04-15
categories: [JSVMP, 逆向]
tags: [有手就行系列, 逆向, JSVMP, 抖音, a_bogus, 纯算, SM3, RC4]
description: "从 JSVMP 字节码中完整逆向抖音 a_bogus 签名算法：SM3 国密哈希 + RC4 变体加密 + 位掩码交错扩展 + 自定义 Base64，Python 纯算实现，输出和浏览器逐字节一致。"
excerpt: "把 a_bogus 的生成算法从 VMP 字节码中完整逆出来，不依赖 JS 运行时，Python 纯算实现 192 字符签名，通过真实接口验证。"
faq:
  - q: "a_bogus 用的什么哈希算法？"
    a: "SM3（中国国家密码标准 GB/T 32905-2016），不是 MD5 也不是 CRC32。识别方式：看初始向量 0x7380166f 就知道了。"
  - q: "为什么用标准 RC4 解出来是乱码？"
    a: "bdms 的 RC4 有两个魔改：S-box 反转初始化（S[255-i]=i）和非标准 KSA（j = j*S[i]+j+key），导致密钥调度完全不同。"
  - q: "每次生成的 a_bogus 都不一样正常吗？"
    a: "正常。位掩码扩展步骤会注入随机字节，但核心数据（时间戳、URL哈希）是确定性的，服务端验证的是这些。"
  - q: "盐值 dhzx 会变吗？"
    a: "不同版本可能不同。dhzx 是 1.0.1.19 版本的，存在 VMP 常量池 index=262。拿到新版 JS 在常量池里搜即可。"
---

## 0、背景

某音的 `a_bogus` 参数由 bdms SDK（V 1.0.1.19-fix.01）生成，保护在一个 76 opcode 的 JSVMP 虚拟机里。本文把整个签名算法从字节码中完整逆出来，Python 纯算实现，输出 **192 字符**，和浏览器生成的逐字节一致。

效果先放（评论、热搜、Feed 三个接口全部验证通过）：

![纯算 a_bogus 验证截图](/assets/images/abogus-verify.png)

好，开搞。

## 1、整体签名链路

```
输入: URL参数 + Body + UserAgent
  │
  ├── [1] SM3 二次哈希 (盐值 "dhzx")
  │     url_hash  = SM3(SM3(url_params + "dhzx"))
  │     body_hash = SM3(SM3(body + "dhzx"))       # GET 时跳过
  │     ua_hash   = SM3(base64_s3(ua))
  │
  ├── [2] 组装 payload
  │     固定域 (时间戳/哈希字节/指纹/随机因子)
  │     + 可变域 (设备信息 + 时间编码)
  │     + XOR 校验和
  │
  ├── [3] 位掩码扩展 (3字节 → 4字节, 注入随机)
  │
  ├── [4] RC4 变体加密 (key=chr(0xD3), 反转S-box)
  │
  └── [5] 自定义 Base64 编码 (s4 表)
          → 输出 192 字符的 a_bogus
```

## 2、SM3 二次哈希

bdms 1.0.1.19 用的哈希不是 MD5 也不是 CRC32，而是 **SM3**——中国国家密码标准（GB/T 32905-2016）。

识别方式很简单——在 VMP 字节码中看到初始向量 `0x7380166f, 0x4914b2b9, 0x172442d7...` 就是 SM3。

### 2.1 哈希方式

对输入做**两次 SM3**，盐值 `"dhzx"`（从 VMP 常量池 index=262 提取）：

```python
from gmssl import sm3, func

def sm3_hash(data):
    """SM3 哈希, 返回 32 字节数组"""
    if isinstance(data, str):
        b = data.encode("utf-8")
    else:
        b = bytes(data)
    h = sm3.sm3_hash(func.bytes_to_list(b))
    return [int(h[i:i+2], 16) for i in range(0, len(h), 2)]

# 二次哈希
url_hash = sm3_hash(sm3_hash(url_params + "dhzx"))
```

返回 32 字节数组，后续按索引取特定位置：`[9]`, `[18]`, `[21]`, `[22]`, `[3]`, `[4]`, `[5]` 等。

### 2.2 注意：URL 格式

URL 参数必须是 `URLSearchParams.toString()` 的格式——**空格用 `+` 不是 `%20`**：

```python
# ❌ 错误
params = "os_name=Mac%20OS"

# ✅ 正确
params = "os_name=Mac+OS"
```

这个细节搞错了哈希值就全不对。

### 2.3 Body 和 UA

- **GET 请求**：body 为空，直接跳过哈希，所有 body 相关字段填 0
- **UA**：先用 s3 表做自定义 Base64 编码，再 SM3 一次（不加盐）

## 3、自定义 Base64

bdms 内置 5 套编码表，a_bogus 生成过程中用到 2 套：

| 表名 | 用途 | 特征 |
|------|------|------|
| **s3** | UA 编码（SM3 前的预处理） | 无 padding 字符 |
| **s4** | a_bogus 最终输出 | URL-safe 变体 |

编解码逻辑和标准 Base64 完全一样，只是查表不同。

## 4、RC4 变体加密

⭐ **最容易踩坑的地方**。bdms 的 RC4 有两个魔改：

### 4.1 反转 S-box

```python
# 标准 RC4
S = list(range(256))          # [0, 1, 2, ..., 255]

# bdms 变体
S = list(range(255, -1, -1))  # [255, 254, 253, ..., 0]
```

### 4.2 非标准 KSA

```python
# 标准 RC4
j = (j + S[i] + key[i % len(key)]) % 256

# bdms 变体
j = (j * S[i] + j + key[i % len(key)]) % 256
```

多了 `j * S[i]`，密钥调度结果完全不同。**用标准 RC4 解出来全是乱码**。

PRGA 部分和标准一样没改。密钥是单字节 `chr(0xD3) = chr(211)`。

## 5、位掩码交错扩展

每 3 字节输入，注入 1 随机字节，输出 4 字节。3 组掩码**互补**（OR = 0xFF）：

```
A = 0b10010001 (145)  ↔  B = 0b01101110 (110)   A|B = 255 ✓
C = 0b01000010 (66)   ↔  D = 0b10111101 (189)   C|D = 255 ✓
E = 0b00101100 (44)   ↔  F = 0b11010011 (211)   E|F = 255 ✓
```

编码规则：

```python
def garble_3to4(data):
    A, B, C, D, E, F = 145, 110, 66, 189, 44, 211
    out = []
    for i in range(0, len(data), 3):
        rnd = random.randint(0, 255)
        out.append((rnd & A) | (data[i] & B))
        out.append((rnd & C) | (data[i+1] & D))
        out.append((rnd & E) | (data[i+2] & F))
        out.append((data[i] & A) | (data[i+1] & C) | (data[i+2] & E))
    return out
```

因为掩码互补，**解码只需反向提取**：`in_0 = (out[0] & B) | (out[3] & A)`

版本号也用类似方法混淆，掩码是 `0xAA / 0x55`，2 字节 → 4 字节。

## 6、Payload 组装

Payload 由三部分组成：

### 6.1 固定域

从 VMP 字节码 func_150 中逐条指令追出的字段排列：

| 字段 | 来源 |
|------|------|
| 时间戳 (6 字节) | `Date.now()` 拆成低→高字节 |
| 指纹随机因子 (4 字节) | `Math.random()` |
| URL 哈希字节 | `SM3(SM3(url+"dhzx"))` 的 `[9]`, `[18]`, `[3]` |
| Body 哈希字节 | `SM3(SM3(body+"dhzx"))` 的 `[10]`, `[19]`, `[4]` |
| UA 哈希字节 | `SM3(base64_s3(ua))` 的 `[11]`, `[21]`, `[5]` |
| debugFlag | 蜜罐检测结果 |
| timeDiff | 距固定时间点的 14 天周期数 |
| browserRand | 浏览器类型随机值（Chrome=0~39） |
| sLen, tLen | 可变域长度 |
| magic | 固定值 41 |

### 6.2 可变域

设备信息用 `|` 拼接：`"1512|937|1512|982|1512|982|1512|982|MacIntel"`

后面跟时间编码：`str((timestamp+3) & 255) + ","`

### 6.3 校验和

所有字段异或的最后一个字节。

## 7、最终组装

```python
# 伪代码
payload = fixed_bytes + screen_bytes + time_bytes + [xor_checksum]

# 位掩码扩展
encrypted = garble_3to4(payload)

# 版本号混淆 (2→4字节 x2)
version_garbled = garble_2to4([1, 0]) + garble_2to4([1, 0])

# RC4 变体加密
rc4_input = version_garbled + encrypted
rc4_output = rc4_variant_encrypt(key=b"\xd3", data=rc4_input)

# 前缀混淆
prefix = garble_2to4([3, 82])

# 自定义 Base64 编码
a_bogus = custom_base64_encode(prefix + rc4_output, table="s4")
# → 192 字符
```

## 8、蜜罐陷阱

分析字节码时发现 bdms 会故意设置**拼错的属性**来检测自动化环境：

```javascript
navigator.pemrissions = { microphone: "granted" };       // 注意拼写
navigator.__proto__.pemrissions = { microphone: "grnated" };
window.onwheelx = { _Ax: "0X21" };
```

这些属性的检测结果会影响 payload 中的 `debugFlag` 值，千万不要画蛇添足地去"修正"这些拼写错误。

## 9、常见问题

**Q: a_bogus 有效期多久？**

A: 内嵌毫秒时间戳，一般几分钟内有效。

**Q: 每次结果不一样正常吗？**

A: 正常，位掩码扩展注入了随机因子。核心数据（哈希/时间戳）是确定性的。

**Q: 盐值 "dhzx" 会变吗？**

A: 不同版本可能不同。在 VMP 常量池里搜 4 字符字符串就能找到。

**Q: 怎么识别 SM3？**

A: 看初始向量。`0x7380166f` 开头就是 SM3，和 MD5 的 `0x67452301` 或 SHA-256 的 `0x6a09e667` 一眼就能区分。

**Q: RC4 标准版能用吗？**

A: 不能。S-box 反转 + KSA 魔改导致密钥调度完全不同，标准 RC4 解出来全是乱码。

---

> **免责声明**：本文内容仅供安全研究与学习交流，请勿用于任何非法用途。文中未提供完整可直接运行的代码。如有侵权请联系删除。
>
> White | [haloowhite.com](https://haloowhite.com)
