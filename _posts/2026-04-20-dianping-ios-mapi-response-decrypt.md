---
layout: post
title: "有手就行系列——大众点评 iOS 抓包解密明文返回 response（上篇）"
date: 2026-04-20
categories: [逆向, iOS]
tags: [有手就行系列, 逆向, iOS, frida, 大众点评, DES, Shark, Nova, MAPI]
description: "frida hook 大众点评 iOS 客户端的 NVOpenSSLDesUtil，把 MAPI application/binary 响应从 DES-ECB 密文还原成明文 JSON，10 行 Python 离线复现。顺便记录 frida 17 和 iOS 反调试踩坑。"
excerpt: "大众点评 iOS 在 HTTPS 之上又套了一层 DES + gzip。本篇 frida hook 解密函数，把加密响应还原成明文 JSON，10 行 Python 离线复现。"
faq:
  - q: "为什么 attach 大众点评会 timeout 或闪退？"
    a: "点评有反调试，会检测 task_for_pid / ptrace 异常行为。必须用 device.spawn() 挂起启动，resume 后 sleep 4 秒等 ObjC runtime 初始化完再 attach。"
  - q: "frida 17 为什么 ObjC.classes 用不了？"
    a: "frida 17 默认不加载 ObjC bridge。把 frida-tools/bridges/objc.js 的内容 inline 到 hook 脚本最前面即可，Module.findExportByName 也被换成 Process.findModuleByName(...).findExportByName。"
  - q: "DES 的密钥和算法模式怎么确认？"
    a: "hook NVOpenSSLDesUtil +decryptWithData:key: 拿到 key（取前 8 字节），用 9 组密文/明文样本穷举 ECB/CBC/3DES 等组合，DES-ECB + PKCS7 全中。"
  - q: "为什么有些响应解完 DES 没有 gzip 魔数？"
    a: "小于 1KB 的响应（启动开屏、回执、心跳等）走 NVObject 的 lazy view：头 + 原始 buffer + hash(key)->offset 表，不涉及业务数据，直接跳过即可。"
  - q: "这套方法能套用到美团、饿了么吗？"
    a: "美团 app 自己也用 Shark/CIP，很可能复用同一套 NV 协议，把前缀从 NV 改成 MT 扫一遍即可。饿了么是阿里系走 MTOP，不通用。"
---

> **本篇范围说明（上篇）**：
>
> 这篇只聊响应侧——**怎么把抓包降级到能看**、**整条协议链路长啥样**、以及**用 DES 把密文还原成原始明文 JSON**。简单说，就是把"看不见的接口"先变成"看得见"。
>
> 至于请求侧的 `mtgsig` 签名怎么生成、怎么伪造、以及全自动化批量爬取那一套，放到**下篇**再展开。这篇看完，你至少能用 frida 实时拿到点评返回的明文。

## 0、背景介绍

大众点评 iOS 客户端底层网络栈用的是美团自研的 **Shark / CIP** 协议（有经验的人知道关键词搜索wns，然后hook降级，因为美团之前使用的就是腾讯的WNS，现在是自研版的），业务层在 HTTPS 之上又套了一层 **DES + gzip** 加密。

所以当你用Proxyman、Charles、mitmproxy 抓包，看到的永远是这种画面：

```
POST https://mapi.dianping.com/mapi/...
Content-Type: application/binary
mtgsig: <一段看起来像 JSON 的签名>

<响应体：二进制密文，看不出内容>
```

`application/binary` 这个 二进制返回类型估计吓到了不少人，搜索关键词也基本没相关结果。但不重要，我们的目标是**把这段密文解成明文 JSON**，看看点评接口真正的返回结果是什么。本文从头记录使用frida 实现解密明文需求，顺便记录了一些 frida 17 和 iOS 反调试的坑。

> **声明**：本文仅供安全研究与技术学习交流，请勿用于任何非法用途。涉及到的具体密钥、poiId、token 等敏感数据已全部打码。

---

## 1、整体技术链路

先放一张鸟瞰图，后面每一步都在这条链路上：

```
HTTPS (libboringssl)
    │
    ▼
MAPI 业务响应  (Content-Type: application/binary, 带 mtgsig 签名)
    │
    ▼
DES-ECB 密文 body
    │
    ▼  frida hook NVOpenSSLDesUtil +decryptWithData:key:
    │
    ▼
NV 头 (含 m-shark-check-sum 等字段) + gzip payload (1f 8b magic)
    │
    ▼  gunzip
    │
    ▼
明文 JSON（商家详情、团购列表、评论等真实业务数据）
```

有几个地方可以提前预告下：

- **关于HTTPS 处理**。越狱机上装个 CA 或者直接 hook `SSL_read`/`SSL_write` 都能看到密文 body，但**看到了也没用** ，因为都是加密后的密文。
- **DES-ECB + PKCS7**，很经典的组合了，密钥是固定的（至少目前是）
- **gzip 不是总有**，小响应（启动开屏、设备回执这些）是 NV 裸包。判断条件： `1f 8b 08` 魔数。

---

## 2、环境准备

这次的工具链没什么特别，但版本一定要对上，否则你会卡在某个莫名其妙的地方半小时：

| 组件 | 版本 |
| --- | --- |
| iPhone | iOS 16.3.1，**已越狱**（palera1n/Dopamine 都行） |
| frida-server | 17.x（跟本机 frida 同步） |
| Mac 端 frida | 17.9.1 |
| frida-tools | 14.8.1 |
| 包管理 | `uv`（强烈推荐，`uv add frida frida-tools` 一把梭） |
| 点评 app | App Store 最新版 |
| bundle id | `com.dianping.dpscope` |

把 iPhone 用 USB 插上 Mac，frida-server 丢到手机上开起来，然后：

```bash
frida-ps -U | grep -i dianping
```

能看到点评的进程名和 PID，这一步就算过了。

---

## 3、第一步：spawn 不是 attach（反调试踩坑）

第一个坑，也是最耗时间的坑。如果按照网上大部分 frida 教程的写法，直接：

```bash
frida -U -n "大众点评" -l hook.js
```

或者：

```python
session = frida.get_usb_device().attach("大众点评")
```

然后……`TimeoutError: timeout was reached`，或者 app 直接闪退。为什么？因为点评有一层**反调试**，attach 的时候它会检测 `task_for_pid` / `ptrace` 的异常行为，或者干脆在启动早期就把调试端口关了。你 attach 上去时，它已经进入反调试状态。

**解决方法**：不要 attach 已经在跑的进程，**用 spawn**。

```python
import frida, sys, time

device = frida.get_usb_device()
pid = device.spawn(["com.dianping.dpscope"])   # 挂起启动
device.resume(pid)                              # 跑起来
time.sleep(4)                                   # ！！！关键：等 4 秒
session = device.attach(pid)                    # 这时候 ObjC runtime 已经加载完了

script = session.create_script(open("hook.js").read())
script.load()
sys.stdin.read()
```

关键就这一行：`time.sleep(4)`。

至于 sleep 4 秒，是可以言说的：

- spawn 之后立刻 resume，app 才刚开始跑 `main()`，很多 ObjC 类还没注册到 runtime
- 你这时候去 `ObjC.classes.XXX`，要么 `undefined`，要么直接 crash
- 4 秒是实测的结果，太短 hook 不到，太长 app 会漏掉请求

> ⚠️ 如果你 Mac 比较慢或者手机是老款 iPhone，可以把 sleep 调到 5~6 秒。这个值本质上是"等 ObjC runtime + 业务单例初始化完毕"的经验值。

---

## 4、第二步：frida 17 的 ObjC 坑

第二个坑，独属于 frida 17 用户。写 hook 脚本的时候，习惯性这么写的话：

```javascript
const fn = Module.findExportByName("libboringssl.dylib", "SSL_read");
```

frida 17 会报错：`Module.findExportByName is not a function`。

**API 已更新**，这么写就行：

```javascript
const mod = Process.findModuleByName("libboringssl.dylib");
const fn = mod ? mod.findExportByName("SSL_read") : null;
```

更麻烦的是 ObjC，frida 16 里 `ObjC.classes` 开箱即用，frida 17 **默认不加载 ObjC bridge**，直接用会报 `ObjC is not defined`。

有几种解决方法：

1. 启动参数加 `--runtime=v8 -l objc-bridge.js` 手动把 bridge 加进来。
2. **推荐**：直接把 `frida-tools/bridges/objc.js` 的内容 inline 到 hook 脚本最前面。一次搞定，后面不用再操心这块。从 pip 装的 frida-tools 里找这个文件：

```bash
python -c "import frida_tools, os; print(os.path.dirname(frida_tools.__file__))"
# 进到这个目录，下面有 bridges/objc.js
```

cat 到脚本开头，后面所有 `ObjC.classes.XXX` 就都能用了。

---

## 5、第三步：找 DES 解密函数

这一步是整个逆向最核心、也最吃经验的部分。思路很简单，**枚举所有看起来像加密工具类的 ObjC 类，挨个下断**。点评的代码前缀有这么几组：`MT`（美团）、`NV`（Nova，点评的网络层）、`DP`（DianPing）、`MAY`（MaYi，一个基础库）。所以扫这四个前缀里方法名含 `decrypt` / `AES` / `DES` / `Cipher` / `crypto` 的类即可。

```javascript
// 列出所有候选
for (const name of Object.keys(ObjC.classes)) {
    if (!/^(MT|NV|DP|MAY)/.test(name)) continue;
    const cls = ObjC.classes[name];
    const methods = cls.$ownMethods.filter(m =>
        /decrypt|AES|DES|cipher|crypto/i.test(m)
    );
    if (methods.length) {
        console.log(name, methods);
    }
}
```

跑出来一批候选，挨个 hook 打 log。前后试过：

- `MAYSafeCrypto +AES128CBCDecrypt:key:iv:` —— 没命中，这个是登录态相关的。
- `MTDXCrypto +decryptWithData:encryptKey:` —— 没命中，疑似 wifi 模块在用。
- **`NVOpenSSLDesUtil +decryptWithData:key:`** —— ✅ **每个 MAPI 响应都会走一次，就是它**。

看到类名前缀 `NV` + 名字含 `OpenSSLDes` 的一瞬间其实就应该猜到，点评网络层（Nova）做业务解密，用的就是 OpenSSL 的 DES 实现。

下一步就是把它的参数全 dump 出来：

```javascript
const cls = ObjC.classes.NVOpenSSLDesUtil;
const sel = ObjC.selector("decryptWithData:key:");
const method = cls[sel];

Interceptor.attach(method.implementation, {
    onEnter(args) {
        // args[0] = self, args[1] = _cmd, args[2] = data, args[3] = key
        const data = new ObjC.Object(args[2]);
        const key  = new ObjC.Object(args[3]);
        console.log("[DES IN] data len =", data.length(),
                    "key =", key.toString(),
                    "keyHex =", hexdump(key.bytes(), { length: 16 }));
        this.data = data;
    },
    onLeave(retval) {
        const out = new ObjC.Object(retval);
        console.log("[DES OUT] len =", out.length(),
                    "head =", hexdump(out.bytes(), { length: 32 }));
    }
});
```

跑一次，控制台立刻开始刷屏。重点看 `[DES OUT]` 的前几个字节：

```
[DES OUT] len = 8192
head =
00000000  4e 56 00 01 xx xx xx xx  xx xx xx xx 1f 8b 08 00
                                               ^^^^^^^^
                                               gzip 魔数！
```

`4e 56` = `"NV"`，是 Nova 响应的魔数；后面跟着一段头部（里面有 `m-shark-check-sum` 这种字段），再后面就是经典的 `1f 8b 08`——gzip。

到这里就成功了一半。

---

## 6、第四步：拦截 + dump + 纯 Python 离线复现

只在 frida 里解密意义不大，目标是**把 key 和算法摸清楚，然后用纯 Python 离线就能解**。这样以后抓包保存的 pcap，任意传一段密文进去，直接出明文。

### 6.1 先确认密钥

hook 日志里 key 的 `toString()` 输出是一个 16 字节的 NSString，比如 `C██████K` （**此处打码，真实值请自己 hook 出来**），而 DES 的 key 只要 8 字节。所以实际用的是**前 8 字节**。

### 6.2 穷举算法模式

`decryptWithData:key:` 这个方法名只能知道是 DES ，但具体是 ECB / CBC / CFB？是 DES 还是 3DES？padding 是 PKCS7 还是 Zero？

不想读汇编的话，直接**暴力穷举**。把 hook 到的 9 组（密文, 明文）样本保存下来，本地跑一遍所有组合：

```python
from Crypto.Cipher import DES, DES3
from itertools import product

KEY8 = b"C██████K"  # 前 8 字节，实际值打码

modes = {
    "DES-ECB": lambda: DES.new(KEY8, DES.MODE_ECB),
    "DES-CBC-zero-iv": lambda: DES.new(KEY8, DES.MODE_CBC, iv=b"\x00"*8),
    "DES-CBC-key-iv":  lambda: DES.new(KEY8, DES.MODE_CBC, iv=KEY8),
    "3DES-EDE3-ECB":   lambda: DES3.new(KEY8*3, DES3.MODE_ECB),
    # ...
}

for name, factory in modes.items():
    ok = 0
    for ct, pt in samples:
        try:
            got = factory().decrypt(ct)
            got = got[:-got[-1]]  # PKCS7 unpad
            if got == pt:
                ok += 1
        except Exception:
            pass
    print(f"{name}: {ok}/{len(samples)}")
```

结果其实很明显：

```
DES-ECB:         9/9  ✅
DES-CBC-zero-iv: 0/9
DES-CBC-key-iv:  0/9
3DES-EDE3-ECB:   0/9
```

**DES-ECB + PKCS7**，9 个样本全中，bit-level 完全一致。到此为止。

### 6.3 最终 10 行 Python

```python
from Crypto.Cipher import DES
import gzip

KEY = b"C██████K"  # 已打码，请自己上手实践

def decode_mapi(ciphertext: bytes) -> bytes:
    """把 MAPI 的 application/binary 响应体解成明文"""
    raw = DES.new(KEY, DES.MODE_ECB).decrypt(ciphertext)
    raw = raw[:-raw[-1]]                      # PKCS7 unpad
    gz = raw.find(b"\x1f\x8b\x08")            # 找 gzip 魔数
    return gzip.decompress(raw[gz:]) if gz >= 0 else raw
```

就是这么简单。所有 MAPI 响应一条函数搞定。

---

## 7、成果：一份真实的商家团购 JSON

商家详情接口，解出来的明文大概长这样（`poiId` 已打码）：

```json
{
  "poiId": 7285*****,
  "dealCount": 8,
  "couponTitle": "代金券",
  "mealModuleTitle": "到店套餐",
  "data": [
    {
      "mtDealId": 779*****,
      "title": "拉面爱好者单人餐",
      "dealType": 5,
      "originalPrice": 38.0,
      "currentPrice": 29.9,
      "salesVolume": 1234,
      "shortTitle": "单人套餐"
    }
  ]
}
```

商家 id、团购 id、真实销量、各种价格字段……全在里面。至此点评 MAPI 响应的明文提取就打通了。

---

## 8、踩坑彩蛋：NVObject 的"懒惰视图"

中间还有一个挺有意思的东西。

有些接口（比如**启动开屏**、**设备回执**、**日志上报**这类）响应很小，不到 1KB，**解完 DES 之后没有 gzip 魔数**，直接就是一段二进制。当你想解析的时候才发现完全不像 JSON，也不像 protobuf。然后翻 `NVObject` 这个类的实现才意识过来，它是个 **「懒惰视图」 (lazy view)**：

- 字段**不存 dict**，存的是一段原始 buffer + 一张 `hash(key) -> offset` 的表。
- 用的时候通过 key hash 查 offset，再按类型 decode 出来。
- 序列化出去就是"头 + 原始 buffer"，没 gzip 是因为太小了不划算压。

这类响应**完全不涉及业务数据**，就是网络层自己的心跳、回执、打点。所以解不出结构也没关系——它本来就没业务内容。

> 一句话总结：**小于 1KB 还没 gzip 魔数的，直接跳过就行**，免得搞半天才发现是个 ACK。

---

## 9、下篇预告

到这儿**降级抓包 + 响应解密**这一半算是打通了：密文进、明文出，整条链路清清楚楚。

但要脱离 app 自己发请求，还差另一半：**请求头里那个 `mtgsig`**。

下一篇就接着讲这个签名怎么还原、怎么构造，以及怎么把整套流程串成**全自动化爬取**。算法细节这里先不展开，留到下篇。

---

## 10、常见问题

**Q1: 为啥我 spawn 之后还是 timeout？**
A: 多半是 frida-server 版本不对。Mac 端 frida 17.9.1 必须搭配 iPhone 上 17.x 的 frida-server，跨大版本基本会出问题。

**Q2: 有没有可能不越狱搞？**
A: 有，但要重签（theos / Frida.Gadget 注入 ipa），门槛高不少，越狱机方便很多。

**Q3: 为啥我 hook `NVOpenSSLDesUtil` 没反应？**
A: 两种可能——① 你 attach 太早（<4s）类没注册；② 点评更新后重命名了。换个前缀重新枚举一下 `decrypt|DES|Cipher` 方法就行。

**Q4: key 会变吗？**
A: 近半年实测**固定值**。如果哪天点评升级了，你再 hook 一次就知道了，成本很低。

**Q5: 这套方法能套用到美团、饿了么吗？**
A: 思路完全一样。美团 app 自己也用 Shark/CIP，很大概率复用同一套 NV 协议，你把前缀改成 `MT` 扫一遍即可。饿了么是阿里系，走的是另一套（MTOP），不通用。

---

> **免责声明**：本文内容仅供安全研究与学习交流。请遵守《网络安全法》《数据安全法》，不要对任何线上业务造成干扰。文章中所有密钥、商家 id、token、udid 均已打码或改写，若需复现请自行动手。
