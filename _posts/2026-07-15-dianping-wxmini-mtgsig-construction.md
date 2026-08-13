---
layout: post
title: "有手就行系列——大众点评 mtgsig 构造（微信小程序 wx-jsguard 纯算）"
date: 2026-07-15
categories: [逆向, 小程序]
tags: [有手就行系列, 逆向, 大众点评, mtgsig, 微信小程序, jsguard, MurmurHash2, 纯算]
description: "接上篇响应解密：从点评微信小程序的 wx-jsguard 里把请求头 mtgsig 完整逆出来。9 个字段怎么拼、a5 哪一段能离线重算、哪一段只能复用，Python 纯算和抓包样本逐字段一致。"
excerpt: "上篇把响应密文解开了，这篇补请求侧：微信小程序里的 mtgsig 怎么构造。核心不在 iOS 白盒 VMP，而在 wx-jsguard 的纯 JS 算法——MurmurHash2 + 自定义 CRC/Base64，Python 纯算复现。"
faq:
  - q: "mtgsig 是 iOS 和微信小程序共用一套吗？"
    a: "字段名都叫 mtgsig，形态都是 JSON，但实现完全不同。iOS 走 SAK + 原生白盒 VMP（a5 极难离线）；小程序走 @mtfe/wx-jsguard，签名逻辑在 JS 里，本文就是这一条。"
  - q: "为什么 a5 不能完全从零生成？"
    a: "a5 前 16 字节是时间戳相关、可重算；后面两百多字节是 jsguard 闭包里的 vm_output，依赖运行时私有状态。服务端验的是 a4/d1 与 URL/时间的自洽，不单独验这段尾巴——所以从抓包里抠出来复用即可。"
  - q: "纯复用整段 a5 行不行？"
    a: "不行。a5 前半嵌了时间戳，a4/d1 又依赖 a5 字符串本身的 Murmur 哈希。时间一变或 URL 一变，必须重算 a4/d1，最好连 a5 前 16 字节一起刷新。"
  - q: "查询参数顺序会影响签名吗？"
    a: "会。jsguard 会把 query 先 decode 再按 encodeURIComponent 规则重编码，再按 [key, value] 字典序排序后拼进签名输入。顺序或编码不一致，a4 立刻对不上。"
  - q: "能直接套到 iOS mapi 上吗？"
    a: "不能指望一套算法打天下。iOS 的 a5 是白盒 VMP 输出，结构也不同（常见 a0/a1/a3/a4/a5）。小程序线适合 m.dianping.com/wxmapi/*；iOS 线目前更现实的是 frida-rpc 调真机 SAK。"
---

> **本篇范围说明（下篇）**：
>
> [上篇](/2026/04/20/dianping-ios-mapi-response-decrypt/) 把点评 iOS 的 `application/binary` 响应从 DES 解到明文 JSON。这篇补**请求侧**：HTTP 头里的 `mtgsig` 怎么来的、怎么构造。
>
> 路线选择上我走了**微信小程序**：签名在 `wx-jsguard` 的 JS 里，能纯算；iOS 那条是原生白盒 VMP，离线复现成本完全不是一个量级。本文所有字段名、算法步骤都对真实抓包做过 **self-test 逐字段 match**，敏感 token / 设备指纹已打码。

## 0、背景

上篇抓包时，你一定见过这种 header（字段已打码）：

![mtgsig 请求头形态示意](/assets/images/mtgsig/mtgsig-header-mock.png)

```http
GET /wxmapi/wxsearch/search?... HTTP/1.1
Host: m.dianping.com
mtgsig: {"a1":"1.2","a2":17xxxxxxxxxx,"a3":"...","a4":"...","a5":"...","a6":"...","a7":"wx……","x0":3,"d1":"..."}
```

没有它，接口直接 403 / 风控；有了过期的、或 URL 对不上的，也是 403。上篇把「看得见响应」打通了，这篇把「自己能签请求」补上。

先把结论放前面，避免你在 iOS 白盒里空转半个月：

| 端 | 签名实现 | 离线纯算难度 | 本文是否展开 |
| --- | --- | --- | --- |
| 点评 iOS `dpscope` | `SAKRequestSignatureProcessor` → 原生 VMP 白盒 | 极高（字节码 + 设备指纹） | 只对比，不展开 |
| 点评微信小程序 | `@mtfe/wx-jsguard` 纯 JS | 中（算法可逆，设备字段要种子） | **本文主线** |

小程序这条线的关键包路径类似：

```text
induction/wxmp/@mtfe/wx-jsguard/jsguard.js
```

![wxapkg 解包路径示意](/assets/images/mtgsig/mtgsig-wxapkg-tree.png)

解 wxapkg → 反混淆 → 搜 `calcmtgsig` / `header.mtgsig`，就能落到真正的组装函数。后面所有算法都是从这里抠出来的。

> **声明**：仅供安全研究与技术学习交流。密钥、openid、dpid、指纹串等一律打码或改写；请勿对线上业务造成干扰。

---

## 1、整体签名链路

鸟瞰图先放这儿，后面按块拆：

![mtgsig 签名链路鸟瞰](/assets/images/mtgsig/mtgsig-flow.png)

```text
抓包一条合法请求
        │
        ▼
抽出设备绑定字段：a1 / a3 / a6 / a7 / x0
抽出 a5 尾巴：vm_out（约 200+ 字节，复用）
反推 env_flag（a5[7] 与时间戳 CRC 异或）
        │
        ▼
对任意新请求 (method, url, body, ts)，现签五步：
  1. 规范化 query → 排序 → 拼 z 字符串
  2. 用 ts + a6 + env_flag + vm_out 重算 a5
  3. MurmurHash2(z, ts) 与 MurmurHash2(a5, ts) → 拼出 a4
  4. MD5 串 + 循环左移异或 → d1
  5. JSON 九字段 → header.mtgsig
        │
        ▼
Python 发请求；服务端按「自洽性」校验 a4/d1
（不独立重算那段 vm_out）
```

一句话：**可离线重算的是「和 URL / 时间绑定的部分」；不能离线重算的是「设备侧 vm 输出」——抓一次当种子，后面反复用。**

---

## 2、mtgsig 长什么样

小程序版是一个 **9 字段 JSON**（紧凑序列化，无空格）：

```json
{
  "a1": "1.2",
  "a2": 17xxxxxxxxxx,
  "a3": "08……………………",
  "a4": "f8ce3984……（48 hex）",
  "a5": "K8bcQ+YX……（自定义 Base64，约 300+ 字符）",
  "a6": "w1.6……",
  "a7": "wx734c1ad7b3562129",
  "x0": 3,
  "d1": "a0b13ad5……（32 hex）"
}
```

字段分工可以记成三层（黄=每请求重算，蓝=设备种子，灰=常量）：

![mtgsig 九字段角色](/assets/images/mtgsig/mtgsig-fields.png)

| 字段 | 角色 | 来源 | 每次请求是否变 |
| --- | --- | --- | --- |
| **a1** | 协议/算法版本 | 常量，常见 `"1.2"` | 否 |
| **a2** | 毫秒时间戳 | `Date.now()` | 是 |
| **a3** | 设备指纹串 | jsguard finger | 否（同设备） |
| **a4** | 请求绑定签名 | 算法算 | **是（URL/时间一变就变）** |
| **a5** | 环境 token | 前 16B 可算 + 尾巴复用 | 前半随时刷新 |
| **a6** | 风控/环境串（siua 一类） | finger / 上报缓存 | 基本固定 |
| **a7** | 小程序 appId | 如 `wx734c…` | 否 |
| **x0** | 旋转位数 | 常量 `3` | 否 |
| **d1** | 二次校验 | 算法算 | **是** |

服务端真正校验的是 **a4 / d1 是否和 (method, path, query, a5, a2, …) 自洽**。  
`a3/a6` 更像设备身份，短时间复用没问题；长期风控需要注意频率。

---

## 3、入口：从 wxapkg 到 calcmtgsig

实操路径（有手就行）：

1. 微信开发者工具 / 手机沙盒拿到点评小程序 `.wxapkg`
2. 解密 + 解包（公共脚本一堆，不赘述）
3. 在包里搜 `mtgsig`、`jsguard`、`calcmtgsig`
4. 定位到 `@mtfe/wx-jsguard` 模块

反混淆后，核心组装大概是这种形态（变量名已简化）：

![wx-jsguard 中 calcmtgsig 字段组装片段](/assets/images/mtgsig/mtgsig-jsguard-snippet.png)

```javascript
// 伪代码：jsguard 内 calcmtgsig
r = {}
r.a1 = VERSION          // "1.2"
r.a2 = s                // 毫秒时间戳
r.a3 = finger.d()       // 设备指纹
r.a4 = S                // murmur 拼出来的 hex
r.a5 = w                // 自定义 base64(token)
r.a6 = m                // 环境串
r.a7 = APPID            // wx...
r.x0 = 3
// d1 = md5Array(a1+a2+a3+a4+f+v+a7) 再和 (o<<x0) 等异或
r.d1 = md5ToHex(B)

header.mtgsig = JSON.stringify(r)
```

你不需要把整个 jsguard VM 跑起来——**签名公式已经暴露在这段 JS 里**。  
后面几节就是把里面的 `ge`（Murmur）、`Gn`（CRC）、`Tn`（自定义 Base64）翻译成 Python。

---

## 4、四个积木函数

### 4.1 MurmurHash2 变体（jsguard 的 `ge`）

标准 MurmurHash2 骨架，**最后多 XOR 一次魔法数 `0x5BD1E995`**：

```python
MURMUR_MAGIC = 0x5BD1E995

def murmur2_jsguard(data: bytes, seed: int) -> int:
    n = len(data)
    h = (seed ^ n) & 0xFFFFFFFF
    i = 0
    while n >= 4:
        k = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24)
        k = (k * MURMUR_MAGIC) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * MURMUR_MAGIC) & 0xFFFFFFFF
        h = (h * MURMUR_MAGIC) & 0xFFFFFFFF
        h ^= k
        h &= 0xFFFFFFFF
        i += 4
        n -= 4
    # 尾部 1~3 字节按小端拼进 h（与常见 Murmur2 一致）
    if n >= 3: h ^= data[i+2] << 16
    if n >= 2: h ^= data[i+1] << 8
    if n >= 1:
        h ^= data[i]
        h = (h * MURMUR_MAGIC) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MURMUR_MAGIC) & 0xFFFFFFFF
    h ^= h >> 15
    return (h ^ MURMUR_MAGIC) & 0xFFFFFFFF   # ← 多这一下
```

两个调用点：

- `x  = murmur2_jsguard(z, a2)`  // z 是规范化后的请求串
- `u  = murmur2_jsguard(a5.encode("utf-8"), a2)`

seed 用的是完整毫秒时间戳 `a2`，不是 `a2 & 0xFFFFFFFF`（后面 `o` 才截断）。

### 4.2 自定义 CRC32（jsguard 的 `Gn`）

查表多项式还是常见的 `0xEDB88320`，但**最终 XOR 不是 `0xFFFFFFFF`，而是 `0x12477CDF`**：

```python
def custom_crc32(data: bytes) -> int:
    r = 0xFFFFFFFF
    for b in data:
        r = CRC_TABLE[(r ^ b) & 0xFF] ^ (r >> 8)
    return (0x12477CDF ^ r) & 0xFFFFFFFF
```

这个只在 **a5 内部**用：时间戳 4 字节的 CRC、以及 y[0..11] 的整段 CRC。

### 4.3 自定义 Base64（a5 字母表）

a5 不是标准 Base64 字符集，而是 jsguard 内置的 64 字符置换表（下文用 `Tn` 指代）。实现方式很省事：

```python
CUSTOM = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
STD    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_a5(s: str) -> bytes:
    return base64.b64decode(s.translate(str.maketrans(CUSTOM, STD)))

def encode_a5(b: bytes) -> str:
    return base64.b64encode(b).decode().translate(str.maketrans(STD, CUSTOM))
```

算法层没有花活，**就换了张表**。用标准 Base64 直接 decode 会失败或解出垃圾。

### 4.4 端序工具

jsguard 里混用了大端和小端，别搞反：

| 符号 | 含义 |
| --- | --- |
| `ie(u32)` | uint32 → **4 字节大端** |
| `le_hex_u32(u32)` | uint32 → **小端 4 字节** 的 8 位 hex |
| `oe(bytes)` | bytes → 小写 hex |

---

## 5、请求规范化：z 字符串

签名输入不是裸 URL，而是：

```text
z = utf8( METHOD + " " + path + " " + sorted_query )
// 非 GET 且有 body 时：再 append body[:16200]
```

query 处理是最容易踩坑的一步，必须和 JS 一致：

1. 按 `&` 切开每个 `k=v`
2. `+` 当空格，再 `decodeURIComponent`
3. 用 jsguard 的 `fe`（基本等价 `encodeURIComponent`，safe 集 `-._~`）重新编码 key/value
4. 按 `(key, value)` **字典序**排序
5. 拼回 `k=v&k2=v2...`

```python
def build_z(method: str, url: str, body: str = "") -> bytes:
    p = urllib.parse.urlparse(url)
    pairs = []
    for part in (p.query or "").split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        k = urllib.parse.unquote(k.replace("+", " "))
        v = urllib.parse.unquote(v.replace("+", " "))
        pairs.append((fe(k), fe(v)))
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    w = "&".join(f"{k}={v}" for k, v in pairs)
    z = f"{method.upper()} {p.path} {w}".encode()
    if method.upper() != "GET" and body:
        z += body.encode()[:16200]
    return z
```

> ⚠️ 和抖音 a_bogus 那篇一样：**编码细节错了，后面哈希全错**。  
> 常见翻车：用了 `parse_qsl` 默认行为、没排序、空格编成 `%20` 和 `+` 混用、path 带了 host。

---

## 6、a5：可算的 16 字节 + 复用的 vm_out

### 6.1 二进制布局

把 a5 用自定义表 decode 后，长度大约 240~260 字节，前 16 字节结构固定：

![a5 二进制布局](/assets/images/mtgsig/mtgsig-a5-layout.png)

| offset | 长度 | 含义 |
| ---: | ---: | --- |
| 0 | 7B | `MD5(a6 ‖ ie(ts))` 的 hex 前 14 字符，两两转字节 |
| 7 | 1B | `env_flag XOR CRC32(ie(ts))` 的低 8 位 |
| 8 | 4B | ts 低 32 位，大端：`ie(a2 & 0xFFFFFFFF)` |
| 12 | 4B | `CRC32(y[0..11])` 大端 |
| 16 | N | `vm_out`：jsguard 闭包状态，离线算不出来 |

布局示意（只读结构，不依赖等宽对齐）：

```text
 y[0 .. 6]   MD5 前缀 7B
 y[7]        env_flag XOR crc(ts)
 y[8 .. 11]  timestamp BE 4B
 y[12 .. 15] CRC32(y[0..11]) BE 4B
 y[16 ..]    vm_out  (复用抓包尾巴)
```

实测一组样本：总长 249 字节 → `vm_out = 233` 字节。不同版本 N 会漂，以抓包为准。

### 6.2 为什么不能从零生成整段 a5

`vm_out` 来自 jsguard 内部 VM / 生物特征拼装结果，输入包含大量运行时闭包（源码里能看到对私有对象 `qn` 一类状态的 `JSON.stringify`）。  
你在 Node 里硬补环境，成本接近再写一个小程序运行时。

但服务端校验策略（小程序 wxmapi 实测）是：

- **会验**：`a4`、`d1` 是否由当前 URL + a5 字符串 + 时间戳按公式推出来
- **不会**（至少当前）：独立重跑那段 vm 逻辑核对 `vm_out` 每一位

所以工程解法变成：

```text
从任意一条合法抓包：
  1) decode a5 → 取 y[16:] 作为 vm_out
  2) 用 y[7] ^ CRC(l) 反推 env_flag
  3) 保存 a1/a3/a6/a7/x0

之后每次新请求：
  只重算 y[0..15]，尾巴拼原来的 vm_out → 新 a5
```

### 6.3 重算前 16 字节

```python
def build_a5(a6: str, ts_ms: int, env_flag: int, vm_out: bytes) -> str:
    o = ts_ms & 0xFFFFFFFF
    l = struct.pack(">I", o)                       # ie(o)
    md5_hex = hashlib.md5(a6.encode() + l).hexdigest()
    y = bytearray(int(md5_hex[i:i+2], 16) for i in range(0, 14, 2))  # 7 bytes
    y.append((env_flag ^ (custom_crc32(l) & 0xFF)) & 0xFF)
    y.extend(l)                                    # +4 → 12 bytes
    y.extend(struct.pack(">I", custom_crc32(bytes(y))))  # +4 → 16
    y.extend(vm_out)
    return encode_a5(bytes(y))
```

种子提取（抓包一次）：

```python
a5_bytes = decode_a5(captured["a5"])
vm_out   = bytes(a5_bytes[16:])
o        = captured["a2"] & 0xFFFFFFFF
l        = struct.pack(">I", o)
env_flag = a5_bytes[7] ^ (custom_crc32(l) & 0xFF)
```

---

## 7、a4：请求绑定签名

a4 是 **48 个 hex 字符** = 24 字节。和 d1 合在一起的鸟瞰公式：

![a4 / d1 核心公式鸟瞰](/assets/images/mtgsig/mtgsig-formula.png)

```text
a4 = hex( ie(x) ‖ ie(u) ‖ A )
     ── 4B ──   ── 4B ──  ─ 16B ─

x = murmur2_jsguard(z, a2)
u = murmur2_jsguard(utf8(a5), a2)
o = a2 & 0xFFFFFFFF

A = bytes.fromhex(
      le_hex(x) + le_hex(u) + le_hex(x^o) + le_hex(x^u^o)
    )   # 注意：这里是「小端 hex 再解回 bytes」，不是 ie 大端
```

对应 Python：

```python
x = murmur2_jsguard(z, s)
u = murmur2_jsguard(a5.encode(), s)
o = s & 0xFFFFFFFF
A = bytes.fromhex(
    le_hex_u32(x) + le_hex_u32(u) + le_hex_u32(x ^ o) + le_hex_u32(x ^ u ^ o)
)
a4 = (ie(x) + ie(u) + A).hex()
```

几个容易写错的点：

1. **a5 要先完整字符串算出来**，再 `murmur(a5_utf8)`——中间不能用「旧 a5」
2. `A` 那段是 **小端 hex 拼串再 `fromhex`**，和前面 `ie(x)` 大端并存，别统一成一种端序
3. z 的 method 必须大写 `GET` / `POST`

URL 一变 → z 变 → x 变 → a4 必变。  
这也是为啥「把 start=0 的 mtgsig 原样贴到 start=10」会秒 403。

---

## 8、d1：二次校验

d1 把身份字段和 a4 再揉一次：

```python
f = u & 0xFFFFFFFF
v = hashlib.md5(a6.encode() + ie(o)).hexdigest()   # 32 hex
M = f"{a1}{a2}{a3}{a4}{f}{v}{a7}"                  # 字符串拼接，f 是十进制
B = list(struct.unpack("<IIII", hashlib.md5(M.encode()).digest()))  # 4 个小端 u32

j = ((o << x0) | (o << (32 - x0))) & 0xFFFFFFFF    # 循环左移 x0 位
B[0] ^= j
B[1] ^= f
B[2] ^= f ^ j
B[3] ^= B[0]                                       # 注意依赖更新后的 B[0]

d1 = "".join(le_hex_u32(x) for x in B)             # 32 hex
```

`x0` 固定为 `3` 时，`j` 就是把时间戳低 32 位循环左移 3 位。  
`M` 里的 `f` 是 **无符号十进制字符串**，不是 hex——这点源码里是 `f = _ >>> 0` 直接拼进字符串。

---

## 9、串起来：从种子到 header

```python
@dataclass
class Seed:
    a1: str
    a3: str
    a6: str
    a7: str
    x0: int
    env_flag: int
    vm_out: bytes
    # 可选：抓包时的 a2，风控时间窗紧时优先复用

def forge(seed: Seed, method: str, url: str, body: str = "", ts_ms: int | None = None) -> dict:
    s = ts_ms if ts_ms is not None else int(time.time() * 1000)
    z = build_z(method, url, body)
    a5 = build_a5(seed.a6, s, seed.env_flag, seed.vm_out)

    x = murmur2_jsguard(z, s)
    u = murmur2_jsguard(a5.encode(), s)
    o = s & 0xFFFFFFFF
    A = bytes.fromhex(
        le_hex_u32(x) + le_hex_u32(u) + le_hex_u32(x ^ o) + le_hex_u32(x ^ u ^ o)
    )
    a4 = (ie(x) + ie(u) + A).hex()

    f = u & 0xFFFFFFFF
    v = hashlib.md5(seed.a6.encode() + ie(o)).hexdigest()
    M = f"{seed.a1}{s}{seed.a3}{a4}{f}{v}{seed.a7}"
    B = list(struct.unpack("<IIII", hashlib.md5(M.encode()).digest()))
    j = ((o << seed.x0) | (o << (32 - seed.x0))) & 0xFFFFFFFF
    B[0] = (B[0] ^ j) & 0xFFFFFFFF
    B[1] = (B[1] ^ f) & 0xFFFFFFFF
    B[2] = (B[2] ^ f ^ j) & 0xFFFFFFFF
    B[3] = (B[3] ^ B[0]) & 0xFFFFFFFF
    d1 = "".join(le_hex_u32(w) for w in B)

    return {
        "a1": seed.a1, "a2": s, "a3": seed.a3, "a4": a4,
        "a5": a5, "a6": seed.a6, "a7": seed.a7,
        "x0": seed.x0, "d1": d1,
    }

# 使用
headers["mtgsig"] = json.dumps(forge(seed, "GET", url), separators=(",", ":"))
```

### 自测怎么过

对**同一条抓包**做闭环：种子从这条的 mtgsig 解出，`forge(method, url)` 用原 `a2`，九个字段应 **逐字段相等**。

![self-test 九字段 PASS（敏感值已打码）](/assets/images/mtgsig/mtgsig-selftest-pass.png)

```text
a1 match ✓
a2 match ✓
a3 match ✓
a4 match ✓
a5 match ✓
a6 match ✓
a7 match ✓
x0 match ✓
d1 match ✓
overall: PASS
```

这一步不过，别急着打线上——100% 是端序 / query 排序 / a5 字母表写错了。

---

## 10、和上篇 iOS 线怎么拼

![小程序 vs iOS 对照](/assets/images/mtgsig/mtgsig-ios-vs-wxmini.png)

```text
请求侧
  ├─ 小程序 wxmapi  →  本文 mtgsig（jsguard 纯算）
  └─ iOS mapi       →  frida-rpc 签 SAK
         │
         ▼
      HTTPS
         │
响应侧（上篇）
  └─ DES-ECB + gzip  /  新版本 AES + zstd + NVObject
         │
         ▼
      明文 JSON
```

两套签名**不能互换**：

- 小程序：`m.dianping.com/wxmapi/...`，header 九字段，jsguard 纯算
- iOS：`mapi.dianping.com/mapi/...`，常见带 `a0:"3.0"` 的结构，a5 白盒 VMP

上篇解响应、本篇签请求——合在一起才是「看得见 + 发得出」。  
若目标是 iOS 业务接口，签名侧更稳的工程路径仍是：**真机 frida 调 `SAKRequestSignatureProcessor`**，而不是硬啃 VMP。

---

## 11、踩坑清单

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| a4 对不上抓包 | query 未排序 / 编码不一致 | 严格按 §5 做 fe + sort |
| a5 decode 失败 | 用了标准 Base64 表 | 换 Tn 字母表 |
| self-test a5 差一截 | 复用了整段旧 a5 却换了时间 | 只复用 `y[16:]`，重算前 16B |
| 线上 403，self-test 却 PASS | 种子过期、频控、缺其它 header | 补齐 openid/dpid/Referer 等；控制 QPS |
| 换 URL 仍 200、数据不对 | 签过了但业务参数错 | 和签名无关，查 regionId/start 等 |
| 想一套算法打 iOS | 实现不是同一套 | 回 iOS frida-rpc |

另外：

- **body 截断 16200 字节**——大 POST 别整包哈希
- **时间窗**：部分环境对 `a2` 有滑动窗口；调试时先固定抓包时间戳，再试 `Date.now()`
- **不要把 a3/a6 当可随机字段**——服务端把它们当设备身份，乱填等于新设备冷启动

---

## 12、局限（说清楚边界）

这篇解决的是：**小程序请求头 `mtgsig` 的构造**。

还没在本文承诺的：

1. **iOS 白盒 a5 纯算**——另一座山  
2. **翻页风控**——签过了也不等于 `start>0` 一定放行，业务层还有 session / 行为特征  
3. **长期稳定的设备农场**——`a3/a6/vm_out` 仍是单设备种子，滥用一样会进小黑屋  

安全研究场景下，一条合法抓包当种子 + 纯算 a4/d1/a5 前缀，足够把协议层读懂；工程化爬取还要自己处理频控、会话和合规边界。

---

## 13、常见问题

**Q1: 字母表 / CRC 常数会不会随版本变？**  
A: 会。换包后优先 diff `wx-jsguard`，搜 `0x5BD1E995`、`0x12477CDF`、64 字符常量串，三处在就能快速确认算法是否迁移。

**Q2: a1 什么时候不是 1.2？**  
A: 协议升级时。以抓包为准，不要写死后永远不看。

**Q3: 只用 HAR 里的 mtgsig 原样重放？**  
A: 同 URL 短时间可能行，换 query 必挂。本文的意义就是 **URL 变了还能现签**。

**Q4: 小程序明文接口还要不要管响应解密？**  
A: wxmapi 多数直接 JSON；iOS mapi 才是上篇那套 DES/AES。别两套混着解。

**Q5: 和美团 App / 其它小程序通用吗？**  
A: 美团系大量复用 jsguard / SAK 思路，但 appId、finger、字母表、字段集合都可能不同。**当思路模板，不当 drop-in 脚本。**

---

## 14、小结

1. 点评请求签名头叫 **`mtgsig`**，小程序版是 9 字段 JSON。  
2. 算法在 **`wx-jsguard`**，不在你想象的「必须 frida 才能签」。  
3. 积木：`MurmurHash2^MAGIC`、自定义 `CRC32^0x12477CDF`、自定义 Base64、MD5、循环左移异或。  
4. **a5 = 16 字节可算头 + vm_out 复用尾巴**——这是整篇最关键的工程洞察。  
5. **a4/d1 强绑定 URL**；种子字段 `a3/a6/a7` 绑定设备。  
6. 自测标准：对抓包样本 **9 字段 bit-level match**，再谈打真实接口。

上篇把密文响应变成可读 JSON，这篇把请求头变成可生成的签名。到这里，「看得见 + 签得出」这条小程序协议链路就算闭合了。

---

> **免责声明**：本文内容仅供安全研究与学习交流。请遵守《网络安全法》《数据安全法》，不要对任何线上业务造成干扰。文章中所有 token、指纹、openid、完整可运行利用链均未提供或已打码；若需复现请自行动手从合法抓包样本推导。
>
> White | [haloowhite.com](https://haloowhite.com)
