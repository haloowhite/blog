---
layout: post
title: "有手就行系列：贝壳 iOS 越狱检测绕过与 API 双签名纯算"
date: 2026-09-09
categories: [逆向, iOS]
tags: [有手就行系列, 逆向, iOS, frida, 贝壳, 链家, JGBSDK, HMAC-SHA256, SHA1]
description: "越狱 iPhone 上把贝壳 App 的 JGBSDK 检测总闸 replace 成空函数，再 hook CCHmac / CC_SHA1 把 WLL-KGSA 与 Authorization 两套签名完整逆出来。Python 纯算，和抓包逐字节一致。"
excerpt: "贝壳 iOS 启动约 5 秒闪退，不是随机崩溃——JGBSDK 用 dispatch_after 排队自毁。本篇把总闸拆掉，再把网关 HMAC 和 Authorization SHA1 两套签名纯算出来。"
faq:
  - q: "为什么只装 Shadow 还是会闪退？"
    a: "Shadow 只能挡文件路径那一波（/var/jb、Cydia.app 之类）。JGBSDK 还会 connect 127.0.0.1:27042 探 Frida，命中后走 svc #0x80 直接 exit(1)，不经过 libc。必须把 JGBSDK+0xc710 整个 replace 掉。"
  - q: "attach 已经在跑的贝壳为什么会 timeout？"
    a: "检测是 dispatch_after 延迟 5 秒触发的。你去 attach 的时候它多半已经进入反调试状态。正确姿势是 spawn 挂起 → 注入 patch → 再 resume。"
  - q: "WLL-KGSA 和 Authorization 为什么要签两套？"
    a: "WLL-KGSA 是网关 HMAC-SHA256，覆盖 method/host/path/query/设备头；Authorization 是更老的 SHA1 前缀签名，只吃排序后的 query。少哪一个都是 403。"
  - q: "密钥会变吗？"
    a: "WLL-KGSA 的 HMAC 密钥是 app 常量，版本内稳定。Authorization 的前缀密钥可能跟会话绑定，某天突然 40301 / 无权限，就重新 hook CC_SHA1 看输入串开头那 32 位 hex。"
  - q: "0xc710 这个偏移换版本还能用吗？"
    a: "3.06.21 上是 JGBSDK+0xc710。换版本先 nm / 搜 dispatch_after 调用来定位新总闸，别写死。"
---

> **本篇范围说明**：
>
> 这篇只做两件事——**让越狱机能把贝壳跑起来**，以及**把请求头里两套签名还原成纯 Python**。看完你至少能：spawn 注入后正常翻页，再用自己算的 `WLL-KGSA` / `Authorization` 打通 `apps.api.ke.com` 的租房 list。
>
> 全城遍历、并发农场、设备指纹长期保活不在本文范围。密钥、UUID、duid 一律打码，需要的请自己 hook。

## 0、背景介绍

贝壳 iOS（`com.lianjia.beike`，本文对应 3.06.21）主程序是加固壳 **`LJShell`**（约 200MB，FairPlay 加密），旁边挂了一个**没加密**的检测 SDK **`JGBSDK.framework`**（约 2.9MB）。

所以当你在越狱机上点开贝壳，典型体验是：

1. 图标能点，启动画面能出来
2. 大概四五秒后进程没了，闪退现场干净得像没发生过
3. Charles / Proxyman 即使装了 CA，也抓不到几条像样的业务请求

不是随机 crash。JGBSDK 做越狱 / 反调试 / 反 Frida / 反 Hook / VPN 检测，命中之后走的是 **svc 直连 `exit(1)`**，再把 `sp / x29 / x30` 清零后 `ret`——崩溃栈基本没法回溯。

目标很明确：

- 把检测总闸拆掉，App 能正常用
- hook 系统加密函数，把两套签名的规范串和密钥摸出来
- 离线纯算，不再依赖真机

> **声明**：本文仅供安全研究与技术学习交流，请勿用于任何非法用途。涉及到的密钥、设备标识、会话 token 已全部打码。

---

## 1、整体技术链路

先放一张鸟瞰图，后面每一步都在这条链路上：

```text
spawn 挂起 com.lianjia.beike
        │
        ├─ 脱壳：内存里 dump 已解密的 LJShell / JGBSDK
        │
        └─ 真机用：注入 patch，replace JGBSDK+0xc710
                │
                ▼
        resume → App 正常跑（检测总闸是空函数）
                │
                ▼
        hook CCHmac / CC_SHA1，对着真实请求打 log
                │
        ┌───────┴────────┐
        ▼                ▼
   WLL-KGSA         Authorization
   HMAC-SHA256      SHA1(secret || sorted query)
   覆盖 URL+设备头    只吃 query
        │                │
        └───────┬────────┘
                ▼
        Python 纯算 → GET apps.api.ke.com/Rentplat/v3/house/list
                ▼
        明文 JSON（房源列表 / 详情）
```

几个可以提前预告的点：

- **JGBSDK 没加壳**，偏移可以直接对着 dump 出来的 dylib 看，不必先啃 LJShell。
- 检测总闸在 **`JGBSDK + 0xc710`**，内部按顺序跑 theos / cycript / Frida，命中就 `dispatch_after(5.0s)` 排队自毁。
- 业务请求本身是普通 HTTPS JSON，**没有**点评那种 `application/binary`。难的是请求头两套签名。
- 两套签名都覆盖 URL，**每请求重算**；设备档案（uuid / device-id / duid）要跟着走，但不进 HMAC 的密钥位。

---

## 2、环境准备

工具链跟[点评那篇](/2026/04/20/dianping-ios-mapi-response-decrypt/)几乎一样，版本对上最省事：

| 组件 | 版本 |
| --- | --- |
| iPhone | iOS 16.3.1，**已越狱**（Dopamine / palera1n 都行） |
| frida-server | 17.x（跟本机 frida 同步） |
| Mac 端 frida | 17.x |
| 包管理 | `uv add frida frida-tools` |
| 贝壳 app | 3.06.21（`com.lianjia.beike`） |
| 可选 | Shadow（挡文件级越狱路径） |

USB 插上，frida-server 拉起来：

```bash
frida-ps -U | grep -iE 'beike|贝壳|LJShell'
```

能看到进程名（常见是 `贝壳找房` 或 `LJShell`）这一步就算过了。

> ⚠️ frida 17 的两个老坑这里同样存在：`Module.findExportByName` 没了，改 `Process.findModuleByName(...).findExportByName`；ObjC bridge 默认不加载。点评那篇第四节写过，不重复。

---

## 3、第一步：spawn 挂起，别去 attach

第一个坑，也是最耗时间的坑。如果按照网上大部分教程：

```bash
frida -U -n "贝壳找房" -l hook.js
```

然后……`TimeoutError`，或者 app 直接闪退。

原因比点评还直白：JGBSDK 的检测**不是启动瞬间同步跑完的**，它在总闸里对每一次命中都挂了 `dispatch_after`，delay 是精确的 **5.0 秒**（`0x12a05f200` ns）。你去 attach 一个已经在跑的进程时，定时器多半已经在主队列上了。

**解决方法**：不要 attach 活进程。**spawn 挂起 → 注入 → 再 resume。**

```python
import frida, sys, time, os

BUNDLE = "com.lianjia.beike"
JS = open("beike_patch.js", encoding="utf-8").read()

device = frida.get_usb_device(timeout=10)

# 先清掉残留
for p in device.enumerate_processes():
    if p.name in ("贝壳找房", "LJShell"):
        try:
            device.kill(p.pid)
        except Exception:
            pass

pid = device.spawn([BUNDLE])          # 挂起，检测还没机会跑
session = device.attach(pid)
script = session.create_script(JS)
script.load()
device.resume(pid)                    # 这时候 0xc710 已经是空函数了
print("pid =", pid)
sys.stdin.read()
```

和点评那篇「resume 之后 sleep 4 秒再 attach」**刚好相反**：贝壳必须在 resume **之前**把 patch load 进去。JGBSDK 可能还没 dlopen，脚本里要轮询模块，这个下一节补。

---

## 4、第二步：脱壳看 JGBSDK（LJShell 可以先放放）

贝壳主程序 FairPlay 加壳，直接从 ipa 里抄 `LJShell` 是加密的。但 **spawn 挂起的那一瞬间，内核已经把 crypt 段解在内存里了**。

思路就三步：

1. `device.spawn(bundle)`，**不要 resume**（或 resume 后立刻 dump 再 kill）
2. 枚举 `.app` 里的模块，按 Mach-O 的 `LC_ENCRYPTION_INFO_64` 找到 `cryptoff / cryptsize`
3. 把磁盘镜像拷出来，把内存里对应区间覆盖回去，再把 `cryptid` 写成 0

JGBSDK 本身 **cryptid 就是 0**，2.9MB 直接拉下来就能丢进 IDA。LJShell 那 200MB 可以晚点再啃——检测逻辑不在壳里。

`otool -tv` 对着 JGBSDK，字符串已经把作案动机写在脸上了：

```text
your app infused by theos:%s
your app infused by cycript:%s
your app hooked by Frida
Your application is running under a jailbreak environment...
Your application is running with a VPN environment...
Your application is running with Swizzle Hook behavior...
```

类名还做了混淆：`NIrdeTfmoeCyJUPn`、`lfIjsMmrkKLVRkqJ`、`BdSqiFhzMRgLhaEw`……但函数入口的交叉引用很老实。搜 `dispatch_after` 的调用点，会落到同一个编排函数。

---

## 5、第三步：总闸就在 `JGBSDK + 0xc710`

3.06.21 上，主编排函数从 **`0xc710`** 开始，典型的 `stp x24, x23, [sp, #-0x40]!` 序言。它干的事情按执行顺序是：

| 顺序 | 偏移 | 检测什么 | 怎么判 |
| --- | --- | --- | --- |
| 1 | `+0x8000` | theos / CydiaSubstrate | 遍历 dyld image，`strstr(..., "CydiaSubstrate.framework")` |
| 2 | `+0x8088` | cycript | `strstr(..., "libcycript")` |
| 3 | `+0x8140` | Frida | `connect(127.0.0.1:27042)`，通了就判定 hooked |
| 4 | 后续 | 越狱 / VPN / method swizzle | 混淆类名，字符串同样明文 |

Frida 那一段写得挺有意思。端口不是写死 `27042` 十进制，而是：

```asm
mov  w8, #0x2          ; AF_INET 写进 sockaddr.sin_family
strb w8, [sp, #0x9]
mov  w8, #0xa269       ; 小端写入后内存是 69 a2
strh w8, [sp, #0xa]    ; 按网络序读就是 0x69a2 = 27042
adrp x0, "127.0.0.1"
bl   _inet_aton
bl   _socket
bl   _connect
; connect 成功 → puts("your app hooked by Frida")，返回 1
```

`0xa269` 这一下是给静态扫端口的人看的：搜 `27042` 能搜到字符串，搜立即数 `0x69a2` 对不上，要按 `strh` 的端序转一次。

命中之后不是当场死，而是：

```asm
mov  x0, #0            ; DISPATCH_TIME_NOW
mov  x1, #0xf200
movk x1, #0x2a05, lsl #16
movk x1, #0x1,  lsl #32   ; x1 = 0x12a05f200 = 5.0e9 ns = 5.0s
bl   _dispatch_time
; x1 = dispatch_get_main_queue()
bl   _dispatch_after
```

5 秒后真正执行的自毁 stub 在 `0xcb9c` 附近，和 README 里抄的那几行完全一致：

```asm
mov x0,  #1          ; exit status
mov w16, #1          ; SYS_exit
svc #0x80            ; 直连内核，绕过 libc exit hook
mov x1,  #0
mov sp,  x1
mov x29, x1
mov x30, x1
ret                  ; 跳到 0，栈回溯直接没了
```

同一段 stub 复制了好几份（`0xcba4` / `0xcbc8` / `0xcbec` / `0xcc10`……），哪次检测命中都走同一套死法。

> 只装 Shadow **不够**。Shadow 能把 `/var/jb`、`Cydia.app` 这些路径藏起来，挡第一波文件检测；第二波是 `connect` + `svc`，Shadow 管不着。

所以策略就两层：

1. Shadow 挡路径
2. **frida 把 `0xc710` 整个 replace 成空函数**——检测不跑，自毁也不排队，UI 不受影响

核心 patch 就这几行：

```javascript
'use strict';

function doPatch() {
  var jgb = Process.findModuleByName('JGBSDK');
  if (!jgb) return false;
  var master = jgb.base.add(0xc710);
  Interceptor.replace(master, new NativeCallback(function () {
    return;
  }, 'void', []));
  console.log('replaced JGBSDK master @' + master);
  return true;
}

if (!doPatch()) {
  var timer = setInterval(function () {
    if (doPatch()) clearInterval(timer);
  }, 50);
}
```

`JGBSDK` 可能比主程序晚 dlopen，所以失败就 50ms 轮询。注入成功后 App 可以正常登录、刷租房 feed、翻页，实测不碰 UI。

换版本的定位方法：把新 dump 出来的 JGBSDK 搜 `dispatch_after`，看谁在循环 `bl` theos / cycript / Frida 三个检测函数，那就是新总闸。

---

## 6、第四步：签名不在 VMP 里，在 CommonCrypto

App 能跑了，抓包会看到这种请求：

```http
GET /Rentplat/v3/house/list?city_id=310000&condition=zrn0&limit=30&offset=0&... HTTP/1.1
Host: apps.api.ke.com
User-Agent: Beike 3.06.21;iPhone10,3;iOS 16.3.1;
WLL-KGSA: LJAPPVI accessKeyId=********; nonce=...; timestamp=...; signedHeaders=SystemInfo-s,Device-id-s,Channel-s,AppInfo-s,Hardware-s; signature=...
Authorization: ********
Device-id-s: ********;;
AppInfo-s: Beike;3.06.21;3.06.21.0
```

响应是普通 JSON，`status / msg / data.list`，没有 DES、没有 gzip 套娃。真正挡独立请求的是这两个头：

- **`WLL-KGSA`**：网关签名，缺了或算错直接拒
- **`Authorization`**：看起来像 Basic，其实不是

没有白盒、没有 JSVMP。iOS 上这种货的第一反应就是 hook `CCHmac` / `CC_SHA1`。

```javascript
const lib = Process.findModuleByName('libSystem.B.dylib');

Interceptor.attach(lib.findExportByName('CCHmac'), {
  onEnter(args) {
    // void CCHmac(algo, key, keyLen, data, dataLen, macOut)
    this.algo   = args[0].toInt32();
    this.keyLen = args[2].toInt32();
    this.dataLen = args[4].toInt32();
    this.key  = args[1].readUtf8String(this.keyLen);
    this.data = args[3].readUtf8String(this.dataLen);
    this.out  = args[5];
  },
  onLeave() {
    if (this.algo !== 2) return;          // kCCHmacAlgSHA256 = 2
    if (!this.data || this.data.indexOf('accessKeyId') === -1) return;
    console.log('[HMAC-SHA256 key ]', this.key);
    console.log('[HMAC-SHA256 data]', this.data);
    console.log('[HMAC-SHA256 mac ]',
      hexdump(this.out, { length: 32, ansi: false }));
  }
});

Interceptor.attach(lib.findExportByName('CC_SHA1'), {
  onEnter(args) {
    // unsigned char *CC_SHA1(data, len, md)
    this.len  = args[1].toInt32();
    this.data = args[0].readUtf8String(this.len);
    this.md   = args[2];
  },
  onLeave() {
    if (!this.data || this.len < 40) return;
    // Authorization 的输入是 secret || 排序后的 k=v 拼接，会带 city_id=
    if (this.data.indexOf('city_id=') === -1) return;
    console.log('[SHA1 in ]', this.data);
    console.log('[SHA1 md ]', hexdump(this.md, { length: 20, ansi: false }));
  }
});
```

刷一次租房列表，log 里会成对出现：

1. HMAC-SHA256：key 是一段 **32 字节 ASCII 常量**，data 是 `accessKeyId=...&appinfo-s=...&...` 这种 `&` 连接的规范串
2. SHA1：输入以 **32 位 hex 密钥** 开头，后面直接拼 `city_id=310000condition=zrn0...`，**中间没有 `&`**

把同一条抓包的 `WLL-KGSA.signature`、`Authorization` 拿来本地重算，对得上就结案。不必再进 LJShell 里找调用点。

---

## 7、第五步：`WLL-KGSA` = HMAC-SHA256 网关签

先把 header 形态拆开：

```text
WLL-KGSA: LJAPPVI accessKeyId={id}; nonce={n}; timestamp={ts}; signedHeaders={hdrs}; signature={b64}
```

`LJAPPVI` 是 scheme 名，固定。`signedHeaders` 也固定：

```text
SystemInfo-s,Device-id-s,Channel-s,AppInfo-s,Hardware-s
```

真正被 HMAC 的是规范串 `canon`。键名单如下，**按字母序**排，`k=v` 用 `&` 连接：

| 键 | 来源 |
| --- | --- |
| `accessKeyId` | app 常量（和 header 里那个一样） |
| `appinfo-s` | `Beike;{version};{build}` |
| `channel-s` | 固定 `lianjiabeike` |
| `device-id-s` | 设备 udid，**末尾多两个分号 `;;`** |
| `hardware-s` | 机型，如 `iPhone10,3` |
| `host` | `apps.api.ke.com` |
| `method` | `GET` |
| `nonce` | 32 位字母数字随机 |
| `path` | `/Rentplat/v3/house/list` |
| `query` | URL 查询串原文（已经是排序后的 `k=v&k=v`） |
| `signedHeaders` | 上面那串 |
| `systeminfo-s` | `iOS;{os_version}` |
| `timestamp` | unix 秒 |

然后：

```text
signature = Base64( HMAC-SHA256(secret_wll, canon) )
```

`secret_wll` 就是 hook 到的那 32 字节 ASCII，**app 常量，版本内不会变**。本文打码，自己从 `CCHmac` 的 `key` 参数抄。

两个极易踩的坑：

1. **`device-id-s` 的值带 `;;`**。header 里是 `Device-id-s: {udid};;`，规范串必须一模一样，少一个分号 signature 全错。
2. **`query` 用 URL 原文，不要再 encode 一次**。客户端自己拼 query 时键已经按字母序排好，HMAC 吃的就是这一份。你本地构造请求时，**URL 上的 query 顺序必须等于规范串里的 `query=`**。

对应 Python：

```python
import hmac, hashlib, base64, time, random, string

HOST = "apps.api.ke.com"
ACCESS_KEY_ID = "********"          # hook 出来
SECRET_WLL = b"****************"    # hook 出来，32 字节
SIGNED_HEADERS = "SystemInfo-s,Device-id-s,Channel-s,AppInfo-s,Hardware-s"

def nonce(n=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def wll_kgsa(method, path, query, device_id, appinfo, hardware, systeminfo):
    ts = int(time.time())
    n = nonce()
    kv = {
        "accessKeyId": ACCESS_KEY_ID,
        "appinfo-s": appinfo,
        "channel-s": "lianjiabeike",
        "device-id-s": device_id + ";;",
        "hardware-s": hardware,
        "host": HOST,
        "method": method,
        "nonce": n,
        "path": path,
        "query": query,
        "signedHeaders": SIGNED_HEADERS,
        "systeminfo-s": systeminfo,
        "timestamp": str(ts),
    }
    canon = "&".join(f"{k}={kv[k]}" for k in sorted(kv))
    sig = base64.b64encode(
        hmac.new(SECRET_WLL, canon.encode(), hashlib.sha256).digest()
    ).decode()
    return (
        f"LJAPPVI accessKeyId={ACCESS_KEY_ID}; nonce={n}; timestamp={ts}; "
        f"signedHeaders={SIGNED_HEADERS}; signature={sig}"
    )
```

拿抓包里同一秒、同一个 nonce 的请求重放，signature 必须 **bit-level 一致**。不一致就打印 `canon` 逐字段 diff，九成是 `;;` 或者 query 顺序。

---

## 8、第六步：`Authorization` = `20180111_ios` + SHA1

这套更老，也更绕。header 值是 Base64，解开来是：

```text
20180111_ios:{40 位 hex SHA1}
```

`20180111_ios` 是写死的前缀（像个协议版本号），不是密钥。SHA1 的输入才是：

```text
SHA1( secret_auth + "".join(k + "=" + v for k, v in sorted(query_params.items())) )
```

注意和 WLL 的三点不同：

| | WLL-KGSA 的 `query` | Authorization 的拼接 |
| --- | --- | --- |
| 分隔符 | `k=v&k=v` | `k=vk=v`，**没有 `&`** |
| 覆盖范围 | URL + 一堆设备头 | **只有 query 参数** |
| 算法 | HMAC-SHA256 | SHA1（密钥当前缀拼进去） |

所以 hook `CC_SHA1` 时，输入长这样（已打码）：

```text
********************************city_id=310000condition=zrn0feed_query_id=limit=30offset=0request_ts=1710000000tabId=1
```

前 32 个字符就是 `secret_auth`。它**可能跟登录会话有关**——WLL 的 HMAC 密钥是 app 常量，这个不是。某天请求突然 `status=-1` / `40301` / 「无权限」，优先怀疑它，重新 hook 一次即可。

```python
def authorization(params: dict, secret_auth: str) -> str:
    concat = "".join(f"{k}={params[k]}" for k in sorted(params))
    digest = hashlib.sha1((secret_auth + concat).encode()).hexdigest()
    token = f"20180111_ios:{digest}"
    return base64.b64encode(token.encode()).decode()
```

`params` 的 key 集合必须和 URL query **完全一致**，包括空字符串的字段（`feed_query_id=` 这种也要进拼接，不能省略）。少一个空字段，SHA1 立刻对不上。

---

## 9、第七步：10+ 行之外的那点胶水

两套签名会了，发请求还差设备档案。这些**不进密钥**，但进 header / cookie / 规范串的 value：

- `UUID` / `lianjia_uuid`
- `Device-id-s` / `Lianjia-Device-Id` / `lianjia_udid`（就是带 `;;` 的那个）
- `duid`、`idfv`
- `AppInfo-s`、`SystemInfo-s`、`Hardware-s`、`User-Agent`

从任意一条合法抓包里抄一份即可。`lat` / `lng` 头是加密值，**不参与两套签名**，不发也行。

拼起来打 list：

```python
params = {
    "city_id": "310000",
    "condition": "zrn0",
    "feed_query_id": "",
    "limit": "30",
    "offset": "0",
    "request_ts": str(int(time.time())),
    "tabId": "1",
}
query = "&".join(f"{k}={params[k]}" for k in sorted(params))
path = "/Rentplat/v3/house/list"
headers = {
    "Host": HOST,
    "User-Agent": "Beike 3.06.21;iPhone10,3;iOS 16.3.1;",
    "AppInfo-s": "Beike;3.06.21;3.06.21.0",
    "SystemInfo-s": "iOS;16.3.1",
    "Hardware-s": "iPhone10,3",
    "Channel-s": "lianjiabeike",
    "Device-id-s": DEVICE_ID + ";;",
    "WLL-KGSA": wll_kgsa("GET", path, query, DEVICE_ID,
                         "Beike;3.06.21;3.06.21.0",
                         "iPhone10,3", "iOS;16.3.1"),
    "Authorization": authorization(params, SECRET_AUTH),
}
url = f"https://{HOST}{path}?{query}"
# requests.get(url, headers=headers, cookies=...)
```

自测标准就一条：**同一份 params + 同一份 nonce/timestamp，本地算出来的两个头和抓包逐字节一致**，再谈打真实接口。

---

## 10、成果：一条能看的租房 JSON

签名对了之后，`/Rentplat/v3/house/list` 回来就是明文。清洗一下大概长这样（`house_code` 已打码）：

```json
{
  "status": 0,
  "data": {
    "total": 38000,
    "list": [
      {
        "house_code": "SH****************",
        "house_title": "整租·某某小区 1室1厅",
        "rent_price_listing": 4800,
        "rent_area": 32.5,
        "rent_type": "200600000001",
        "district_name": "徐汇",
        "bizcircle_name": "斜土路",
        "resblock_name": "日晖六村",
        "frame_orientation": "南",
        "sub_desc": "距离4号线-大木桥路站148m"
      }
    ]
  }
}
```

几个协议层的观察，避免你后续走弯路：

- `rent_type`：`200600000001` 整租、`200600000002` 合租、`200600000000` 品牌公寓。
- `condition` 是筛选 token。区是 `d<区政务码>`（徐汇 `d310104`、浦东 `d310115`），商圈是 `b<bizcircle_id>`，价格档 `rp<n>`，7 日新上 `in1`。**乱猜的 token 会被服务端静默忽略**，回落成没过滤。
- 这条 list 是**个性化 feed**，单个 `condition` 翻页有上限（大约两千多套），不是全城 dump。这是接口形态，不是签名问题。
- 详情走 `/Rentplat/v2/house/detail?house_code=...`，同样两套签名；里面才有精确坐标、全图、通勤。
- 品牌公寓是另一条库：`/Rentplat/v2/apartment/list`，数据在 `listv5`。

到这里，「越狱机能跑 + 请求能自己签」就算闭合了。

---

## 11、踩坑清单

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| spawn 后 5 秒闪退 | patch 没 replace 到，或 JGBSDK 加载晚于脚本 | 50ms 轮询 `Process.findModuleByName('JGBSDK')`；确认 `0xc710` 仍是总闸 |
| 只装 Shadow 仍闪退 | Frida 端口探测 + svc 自毁不吃文件隐藏 | 必须 replace 总闸 |
| attach 活进程 timeout | 定时器已经排队 | spawn 挂起再注入 |
| HMAC 对不上 | `device-id-s` 少 `;;`，或 query 顺序/编码不一致 | 打印 canon 和抓包逐字段 diff |
| SHA1 对不上 | 空字段被省略，或误加了 `&` | 全量 `sorted(params)`，`k=v` 直接拼接 |
| 线上 403，本地 self-test 却过 | `secret_auth` 过期，或设备档案和密钥不是一对 | 重新 hook `CC_SHA1` 输入前缀 |
| `lat`/`lng` 没发，担心签名失败 | 这两列不进 canon | 可以不发 |
| 换 app 版本 `0xc710` 没反应 | 总闸偏移变了 | 重新搜 `dispatch_after` + theos 字符串 |

另外：

- **nonce 每请求新开**，timestamp 用秒。重放旧 `WLL-KGSA` 整段，短时间可能行，换 query 必挂。
- **不要把 `Authorization` 当 HTTP Basic 去拆用户名密码**——冒号前面是协议前缀，后面是 hex。
- frida-server 和本机 frida **大版本必须一致**，17 vs 16 混用各种玄学。

---

## 12、局限（说清楚边界）

这篇解决的是：**越狱检测总闸**，以及 **list/detail 请求头两套签名的离线构造**。

还没在本文承诺的：

1. **LJShell 加固壳内部**——业务签名用不到它，检测在 JGBSDK，所以没拆
2. **Authorization 密钥的派生过程**——只确认它会出现在 `CC_SHA1` 输入前缀，没追到密钥怎么从登录态算出来
3. **经纬度头的加密**——`cipher-encrypt-fields` 标了 `lat`/`lng`，不参与签名，未展开
4. **feed 个性化 / 翻页上限 / 风控**——签过了不等于可以全城扫；并发一高就会空列表（临时限流，未必是封禁）

安全研究场景下，一条合法抓包当种子 + 纯算两套签名，足够把协议层读懂。工程化采集还要自己处理频控、会话和合规边界。

---

## 13、常见问题

**Q1: 有没有可能不越狱搞？**  
A: 有，重签 ipa 塞 Frida.Gadget，或者 Theos/ellekit 把 `0xc710` 做成常驻 tweak。门槛比越狱机高一截，原理一样。

**Q2: 为什么不 hook SSL_read 看明文？**  
A: 响应本来就是 JSON，HTTPS 解开就是明文。这题的阻塞点是请求侧签名，不是响应侧加密。

**Q3: 小程序 / PC 网页能套这套签名吗？**  
A: 别指望。`20180111_ios` 这个前缀已经写明端。Web 端是另一套，没在本文验证。

**Q4: `condition=zrn0` 是什么？**  
A: 抓包里的默认筛选 token。当「什么都不筛」的底稿用，再叠加 `d`/`b`/`rp`/`in1`。不要臆造新 token。

**Q5: 这套方法能套到链家二手房 / 贝壳其它业务线吗？**  
A: 网关 header 形态很像（都是 `WLL-KGSA` + `LJAPPVI`），**当思路模板**。path、query 字段、Authorization 前缀都可能不同，换业务先 hook 再下结论。

---

## 14、小结

1. 贝壳 iOS 闪退是 **JGBSDK** 干的，不是 LJShell 壳本身。
2. 总闸在 **`JGBSDK + 0xc710`**（3.06.21）：theos → cycript → Frida:`127.0.0.1:27042` → 其它，命中就 `dispatch_after(5s)` + `svc #0x80` 自毁。
3. **replace 总闸** 比逐个 nop 检测函数干净，UI 不受影响。
4. 业务请求两套签名都在 CommonCrypto 里，hook `CCHmac` / `CC_SHA1` 就能拿到规范串和密钥。
5. **`WLL-KGSA`** = `Base64(HMAC-SHA256(secret, 字母序 canon))`，注意 `device-id-s` 的 `;;`。
6. **`Authorization`** = `Base64("20180111_ios:" + hex(SHA1(secret || 无 & 的 k=v 拼接)))`。
7. 自测标准：对抓包样本 **两个头 bit-level match**，再打真实接口。

越狱检测是门，签名是锁。门拆掉才能看到锁，锁还原了才能离开真机。到这里这条 iOS 协议链路就算走通了。

---

> **免责声明**：本文内容仅供安全研究与学习交流。请遵守《网络安全法》《数据安全法》，不要对任何线上业务造成干扰。文章中所有密钥、设备 id、token、完整可运行利用链均未提供或已打码；若需复现请自行动手从合法抓包样本推导。
>
> White | [haloowhite.com](https://haloowhite.com)
