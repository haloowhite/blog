---
layout: post
title: "有手就行系列：Akamai Bot Manager（SBSD + _abck）2026 版：纯算与补环境双通道拆解"
date: 2026-11-27
categories: [逆向, Akamai]
tags: [有手就行系列, 逆向, Akamai, Bot Manager, SBSD, _abck, sensor, 纯算, 补环境, happy-dom, TLS指纹, HTTP2指纹]
description: "2026 下半年 Akamai Bot Manager 的完整链路：SBSD 与 _abck 两个打分通道、sensor 载荷的编码结构（会话级字母表 + LCG + 内容签名）、happy-dom 补环境回放真实 Chrome 指纹，以及 Go（utls + fhttp）TLS/HTTP2 旁车。重点是一组强校验对照实测——合法载荷能把 _abck 顶到 ~0~，任何一处篡改都被打成 -1，证明服务端做的是逐字节内容校验而非来者不拒。"
faq:
  - q: "Akamai 的 _abck 第二段 0 和 -1 是什么意思？"
    a: "这是唯一可靠的判据。_abck 是 8 段结构，第二段 -1 表示还没通过 Bot Manager 打分、0 表示通过。注意上报 sensor 的响应没有 Set-Cookie，裁决记录在服务端，只在下一次请求（verify GET）时才暴露出来——所以三个 201 不代表过，要再发一次 GET 读 _abck 才知道。"
  - q: "sensor 载荷能纯算重放吗，服务端不是会校验吗？"
    a: "能，而且服务端确实在强校验。实测：把一份完整未改的真实载荷换个出口重放，_abck 能到 0；但只要篡改其中 30 个字符的密文、或替换 44 字节的内容签名、或把密文整段随机，_abck 一律停在 -1。服务端校验的是载荷内容的合法性与完整性，而不是‘是不是本次会话新生成’，这正是纯算重放成立的根基。"
  - q: "为什么 _abck 到 0 了业务接口还是 403 Access Denied？"
    a: "因为是两道独立的关。sensor/_abck 是 Bot Manager 的打分层；业务接口（如 availability）前面还有一道按出口 IP 信誉节流的边缘规则。实测 _abck=0 时同一个出口照样 403，换干净出口就通——这一层跟 cookie 合法性无关，是 IP 的问题。"
  - q: "不用浏览器，TLS 指纹这关怎么过？"
    a: "所有请求走一个 Go 旁车（utls 指定 ClientHello、fhttp 指定 HTTP/2 的 SETTINGS/窗口/伪头顺序）。Akamai 在 HTTP 之前先看 TLS 和 h2 指纹，curl/OpenSSL 直接判掉。本地起 JA3/h2 采集器，让真实 Chrome 和旁车分别连上去逐项对比，实测 10/10 一致。注意 Chrome 110+ 每次连接都打乱扩展顺序并随机 GREASE，所以复刻的是‘行为’不是某个固定哈希。"
  - q: "bundle 换版之后旧 profile 还能用吗？"
    a: "codec（字母表 + LCG）跨 build 很稳，实测 26 个版本签名没变过；但 sensor 的上报‘包体结构’是跟 bundle 走的，bundle 一换，旧 profile 的载荷就会被打成 -1、业务接口随之 403。所以 codec 可以长期复用，profile 必须跟着 bundle 重录。"
---

## 0、背景介绍

上个月写了《有手就行系列：Cloudflare Turnstile / 5s 盾》，把纯算（Rust）和补环境（Node + happy-dom + Go TLS sidecar）两条路都拆了一遍。这篇换个对手：**Akamai Bot Manager**，就是你在各大航司、电商、票务站点上遇到的那个 `_abck`。

两家的思路其实很像：都往页面里挂一段高度混淆的脚本，让它采集一堆浏览器指纹、编码成一个 sensor 载荷回帖，服务端据此打分。但 Akamai 的工程化更“重”：

1. 同一个页面会**同时挂两个独立的打分通道**——SBSD 和 `_abck` sensor，路径前缀几乎一样、没有任何通道标识，得靠 body 形状和响应码区分；
2. 判据被压缩成一个 cookie 字段里的一个字符（`_abck` 第二段，`-1`/`0`）；
3. **网络层指纹在内容分发阶段就已经被用上**——换了 TLS 指纹，连下发给你的 bundle 路径和体积都会变。

这篇沿用上一篇的框架：先给结果和判据，再讲链路，然后补环境和纯算两条路各走一遍，最后是一组我自己最想讲的**强校验对照实测**。老规矩，**不写成复现教程**：会话级字母表、LCG 常数、内容签名算法、探针答案表、真实端点路径、profile 数值这些“抄了就能跑”的东西全部留白或打码。Akamai 的 bundle 轮换得比 CF 还勤，抄代码没有意义；看懂结构和难点，比拿一份跑几天就失效的代码有用。

> 仅用于自有站点或明确授权的测试环境。本文以某大型航司站点（Akamai Bot Manager 的公开客户）为观察对象，只讲结构与方法，不提供任何可直接复用的实现、常数或端点。

---

## 1、结果与判据

先看数据，不看广告。

### 1.1 离线（零请求）

纯算这条路，最舒服的一点是**绝大部分工作可以离线验证**，一个 POST 都不花：

```text
$ codec 自检
  packet 1: cipher=1788B plain=1788B roundtrip=ok plaintext=ok
  packet 2: cipher=4189B plain=4189B roundtrip=ok plaintext=ok
  packet 3: cipher=4576B plain=4576B roundtrip=ok plaintext=ok
  alphabet: 92 printable, 单一签名
  *** codec OK for 3 packets ***

$ 从当前 bundle 离线重推 codec（0 POST）
  codec 跨 26 个 build 的签名: 1 种（全程未变）
  *** 离线管线 OK — codec 已对当前 live bundle 验证，0 POST ***
```

`encode(decode(cipher)) == cipher`，三个包逐字节往返一致。这意味着：**只要本机代码是好的，不碰网络就能确认**，省下宝贵的 sensor 配额。

### 1.2 在线：成功判据只有一个

`_abck` 是 8 段结构，第二段就是判据：

```text
<HEX32> ~ 0 ~ YAAQ... ~ -1 ~ -1 ~ <ts> ~ AAQAAAAG/////... ~ <ts>
            └ 这一位：-1 未过 / 0 通过
```

一个关键坑：**上报 sensor 的响应（201）不带 Set-Cookie**。Akamai 把裁决记在服务端，只在你下一次请求时才通过 `_abck` 透露出来——这跟真实浏览器“下一跳才知道自己过没过”是一致的。所以：

> 发出三个 201 ≠ 通过。必须再发一个普通 GET（verify GET），读回来的 `_abck` 第二段是 `0`，才算过。

### 1.3 三个真实环境的基线

同机、同出口，真实浏览器各环境达到 `~0~` 的耗时和三包 sensor 字节数：

| 环境 | 到 `~0~` | 三包字节 |
| --- | --- | --- |
| Chrome 157 有头 | 5–6 s | 2164 / 5055 / 5381 |
| Chrome 157 无头（正常 UA） | 5 s | 2164 / 5036 / 5361 |
| CloakBrowser 145 无头 | 5 s | 2166 / 5031 / 5353 |

三个环境的三包长度几乎逐字节同长——说明**载荷由环境决定、非常稳定，无头本身不是问题**。我们纯算这边对齐到同样的字段数和时序：

| | 真实浏览器 | 纯算 |
| --- | --- | --- |
| 第 1 包 | 140 字段 / t≈0.1 s | 140 字段 / t≈0.1 s |
| 第 2 包 | 305 字段 / t≈1.2 s | 305 字段 / t≈1.8 s |
| 第 3 包 | 305 字段 / t≈4.7 s | 305 字段 / t≈5.4 s |

---

## 2、Akamai 的两个打分通道

目标页一次性挂两段混淆 bundle，路径前缀相同、没有通道标识，必须靠 body 和响应区分：

| 通道 | 脚本特征 | 上报 body | Content-Type | 响应 |
| --- | --- | --- | --- | --- |
| **SBSD** | script src 带 `?v=<uuid>` | `{"body":"..."}` | `application/json` | 200 |
| **_abck sensor** | script src 不带 query | `{"sensor_data":"..."}` | `text/plain;charset=UTF-8` | 201 |
| Bot Manager pixel | `/akam/13/<id>` | — | — | 独立通道 |

- **SBSD 的 POST 地址 = 它自己的 script src 去掉 query**；但每次会话的路径段都会变，必须从当次页面里取，不能复用。
- `_abck` sensor 走另一条路径，也是每会话一变。
- pixel（`/akam/13/...`）是 Bot Manager 1.x 的那套，和上面两条打分通道独立，不用管。

找脚本不能靠固定正则。路径形状一直在换（曾经是一段长 token、现在是多段短名），稳的办法是**按内容找角色**：sensor bundle 里一定有 `bmak` 这个标记，业务 bundle 没有。先按 URL 形状排序候选（无 query 的 token 路径优先、带版本号的资源最后），再用内容确认。

---

## 3、请求链路总览

1. **首访是 302 引导页**（Akamai bootstrap），真正的页面要带着首发 cookie 跟一次跳转。
2. 跳转后的 HTML 里挂上两个 bundle。**带上 Chrome 的 TLS 指纹后，bundle 的路径前缀和体积都会变**——同一台机器，curl(OpenSSL) 拿到的 SBSD 路径和走 Chrome TLS 后拿到的是两个完全不同的前缀，sensor 脚本也会出现/消失在不同位置。这说明网络层指纹在**内容分发阶段**就被用上了，不是只有 cookie 打分。
3. bundle 跑起来，采集指纹 → 编码 sensor → 分三包回帖（`201`）。
4. 一个 verify GET，`_abck` 从 `-1` 翻到 `0`。
5. 业务接口（下例是 availability）带着这个 jar 请求。注意业务接口往往是**另一个 host**，Akamai 每个 host 发独立的 `_abck`，跨 host 调用要把两个值都放进同一个 jar。

SBSD bundle 会探测的面（对 happy-dom 追踪得到的，节选）：

- 250×80 canvas 的 2D 绘制 + `toDataURL`；
- WebGL2 的 `getParameter`（21 个枚举）、`getExtension`、`getSupportedExtensions`；
- 9 组 `72px <font>, serif` 的 `measureText`；
- `navigator.{userAgent,platform,webdriver,plugins,languages,hardwareConcurrency,deviceMemory,maxTouchPoints,connection,userAgentData,permissions,storage,mediaDevices,serviceWorker,...}`；
- `window.{innerWidth/Height,outerWidth/Height,devicePixelRatio,screenX/Y,chrome,speechSynthesis,AudioContext,OfflineAudioContext,RTCPeerConnection,SharedWorker,indexedDB,crossOriginIsolated}`；
- `document.{cookie,readyState,fonts,adoptedStyleSheets,querySelectorAll,...}`；
- `performance.{now,memory,getEntriesByType,clearResourceTimings}`。

---

## 4、补环境：给 Akamai 一个假 Chrome

和上一篇 CF 的思路一样——不重写协议，给 Akamai 的原始 bundle 造一个足够像 Chrome 的壳，让它自己跑、自己编码、自己回帖。壳用 happy-dom。

### 4.1 record → replay

真实答案不是手搓的，是**从本机真 Chrome 录下来再原样回放**：

- `record_probes.py` 用 Playwright 驱动真实 Chrome，把 bundle 会问到的东西全部录一遍——canvas 的 25KB data URL、WebGL 的参数表、9 组字体宽度、navigator/window/document 的一长串属性；
- `replay.mjs` 在 happy-dom 里把这些值**原样喂回去**。bundle 在壳里跑的时候，问什么都拿到的是真 Chrome 的答案。

这条路的好处是**不用懂载荷怎么编码**——bundle 自己会编。坏处是壳要补得足够全，任何一个属性缺失、类型不对、`toString` 露馅，都会进到载荷里变成一个“不像真人”的信号。

### 4.2 鼠标与时序

Akamai 很看行为轨迹。壳里要有真实的 `mousemove` 流（带 `pageX/Y`、`movementX/Y`、`screenX/Y`，派发到 `elementFromPoint` 命中的元素上），而且**第一包要等 bundle 自己的 dwell 偏移**——真实浏览器第一次回帖大约在脚本加载后十几秒内按它自己的节奏发，发太快本身就是特征。

补环境这条路，拿来**采集 profile 和答案**最合适；跑量则交给纯算。

---

## 5、纯算：codec 逆向与载荷重放

纯算就是把上面那层壳也扔掉：不启动浏览器、不建 DOM，直接理解 sensor 的编码，自己拼载荷、自己发。

### 5.1 载荷结构

sensor body 是 `{"sensor_data":"..."}`，`sensor_data` 本身是分号分隔的头 + 一段密文：

```text
<ver> ; <...> ; <...> ; <flag> ; <seed> ; <digest> ; <cipher...>
```

几个关键点：

- **一个 session 只有一个 seed**，三包复用同一个 seed，像 bundle 自己那样；
- `<digest>` 是一段 44 字符的**内容签名**（base64 形状），绑定这一包的明文；
- `<cipher>` 是明文经过**会话级字母表 + LCG** 编码后的结果——字母表是 92 个可见字符的一个排列（不是标准 base64 表），LCG 是一个 `(A, C, M)` 线性同余；
- 明文里字段的**顺序有意义**，重排会让服务端看到不同的东西。

codec 本身很稳：我把它从 bundle 里抠出来之后，**跨 26 个 build 的签名没变过**（只有 1 种）。所以 codec 值得一次性做扎实，之后长期复用。

### 5.2 重放时要“补”什么

直接拿旧 profile 的三包原样发是不行的——有两个时间相关的值必须贴合本次会话：

- **页面加载时间戳**：服务端拿它和“签发这次 HTML 的时刻”对，旧的会被当成重复会话；
- **会话 UUID**：每次页面加载都会重生成。

所以纯算重放 = 用新 seed 重新编码 + 只改这两处时间/身份值。实测**重生成 UUID 是无害的**（服务端不把它当反重放主键）。

> **会话级字母表、`(A, C, M)` 的真值、digest 算法、flag/counts 的语义、profile 的数值全部不贴。** 这些是纯算的核心工作量，也是最能区分“看懂了”和“抄到了”的地方——而且写出来下个 build 就可能失效。

---

## 6、传输层：TLS + HTTP/2 指纹

这是绕不过去的一关。Akamai 在拿到 HTTP 之前先看 TLS ClientHello 和 h2 参数，**curl/undici/OpenSSL 会被直接判掉**。所以所有请求走一个 Go 旁车（utls 指定 ClientHello 规格，fhttp 指定 h2 SETTINGS/窗口/伪头顺序）。

验证不靠外部服务，而是本地起两个采集器，让真实 Chrome 和旁车分别连上去逐项对比：

```text
OK    cipher suites (GREASE-stripped)
OK    extensions (GREASE-stripped, sorted)
OK    supported versions / curves / point formats / ALPN
OK    JA4_a + JA4_b
OK    h2 SETTINGS                 65536 / 0 / 6291456 / 262144
OK    h2 WINDOW_UPDATE            15663105
OK    h2 pseudo-header order      :method :authority :scheme :path
10/10 identical
```

关于 JA3 哈希本身：**Chrome 110+ 每次连接都打乱 TLS 扩展顺序并随机 GREASE**，所以同一台真实 Chrome 连续两次连接的 JA3 都不一样（实测 5 次 5 个哈希）。因此“符合 JA3 标准”不是复刻一个固定值，而是：GREASE 剥离后的套件集合与顺序一致、扩展集合一致、曲线/点格式/版本/ALPN 一致、**同样具备每次连接打乱 + 随机 GREASE 的行为**、h2 指纹一致。用固定顺序、无 GREASE 的假 JA3 反而是个显眼特征。

另一个细节：**一次 solve 的所有请求最好共用一个传输进程的 jar，但发过上报的连接不能再拿去查业务**（见下一节的坑）。

---

## 7、强校验实测：合法 vs 伪造对照

这是我这次最想讲的部分，上一篇没做这种对照。问题很直接：**服务端到底是在强校验载荷内容，还是只要形状对就放行？** 如果是后者，纯算就没有意义。

设计：固定判据 `_abck` 第二段，固定其余变量（同一批住宅出口、同一时间窗口、同样走 verify GET 读 `_abck`），**只改 sensor 载荷这一个变量**，看服务端的裁决。

| 载荷内容 | 三包 POST | verify GET 后 `_abck` | 判定 |
| --- | --- | --- | --- |
| 真实 bundle 回放的完整载荷 | 201 / 201 / 201 | **-1 → 0** | ✅ 合法通过 |
| 完整合法字节换出口**原样重放** | 201 / 201 / 201 | **-1 → 0** | ✅ 合法通过 |
| 篡改密文中段（改 30 字符） | 201 / 201 / 201 | -1（多出口，无一通过） | ❌ 被拒 |
| 篡改内容签名 digest（改 44 字符） | 201 / 201 / 201 | -1 | ❌ 被拒 |
| 密文整段随机 | 201 / 201 / 201 | -1 | ❌ 被拒 |

两个结论：

1. **所有伪造请求服务端都回 201**——201 只代表“收到了”，裁决在 `_abck`。任何被篡改的载荷，`_abck` 一律停在 `-1`。
2. **决定性证据**：`digest` 变体只改了 44 字符的签名段、其余与合法字节完全相同，`tamper` 只改 30 字符密文——就从“可过”变成恒 `-1`；而一字未改的完整字节换个出口就能到 `0`。如果服务端是“来者不拒”或“按出口放行”，这种微小改动不会改变结果。**改极少数字节即被打成 `-1`，坐实了 Akamai 对 sensor 做的是逐字节内容校验。**

还有个有意思的副产品：**完整合法字节跨会话重放也能到 `~0~`**（上表第二行）。说明服务端校验的是**载荷内容的合法性与完整性**，而不是“是不是本会话新生成的”——这正是纯算重放方案成立的理论基础。

### 7.1 别把两道关混在一起

实测里有个一开始很迷惑的现象：`_abck` 已经到 `0` 了，业务 availability 接口还是 `403 Access Denied`。查下来是**两道独立的关**：

- **第 ① 道 · sensor / `_abck` 打分层**：判据 `~0~`，上面的对照证明合法能过、伪造被拒。**这层纯算是有效的。**
- **第 ② 道 · 业务接口的边缘层**：availability 前面还有一条按**出口 IP 信誉**节流的规则。`_abck=0` 时同一个“脏”出口照样 403，换干净出口就通。这一层跟 cookie 合法性、跟载荷都无关，纯粹是 IP 的问题。

把这两道关分开看，很多“cookie 明明过了为什么还是 403”的问题就不再是谜。

---

## 8、两条路共同的坑

### 8.1 bundle 轮换 → profile 过期

最容易踩的一个。**codec 很稳（26 个 build 签名没变），但 sensor 的上报包体结构是跟 bundle 走的**。bundle 一换，旧 profile 的载荷会被打成 `-1`、业务接口随之 403，而 codec 和 cookie 看起来都“正常”。

更坑的是：这时候 `/cookie` 还能解出 `_abck=-1`（上报也全是 201），codec 也没变——**唯一有效的信号是“业务接口还能不能回 200”**。所以版本哨兵不能按 bundle 哈希触发，要按**业务探针**触发：探针失败 → 抓当前 bundle → 离线重推 codec（0 POST）比对 → 需要时用新 bundle 重录 profile。

### 8.2 IP 窗口与出口信誉

Akamai 的打分有很强的**按出口 IP 的时间窗**。同样合法的载荷，这个出口此刻在开放窗口里就能到 `0`，换个出口或过一阵就停 `-1`，换 IP 立刻恢复。实测一批住宅出口里，往往只有少数几个当下是“开放”的。这跟业务层的 IP 信誉节流（§7.1 第②道）叠加在一起，是纯算之外**最大的不确定来源**。

### 8.3 连接会被打标

发过 sensor 上报的那条连接，拿去查业务接口会 `403`——同一个 jar、从一条全新连接发出去就 `200`。所以**查询必须起一个全新的传输，绝不能复用解 cookie 的那条**。连续在同一条连接上查多次也会被打标。

### 8.4 时间与跨 host

- sensor 的页面加载时间戳要贴合本次“签发 HTML 的时刻”，旧的会被当重复会话；
- 业务接口常在另一个 host，`_abck` 每 host 一个，跨 host 要把两个值放进同一个 jar；
- 有些业务路径对 `POST` 直接 403，要用 `PUT` 带 `X-HTTP-Method-Override: POST`，应用层照样认。

---

## 9、总结

Akamai 和 Cloudflare 隔空对比，难点是高度重合的：

- 真正难的不是某个加密函数，而是**每个 build 都能稳定“按角色找”到 sensor，而不是靠路径名**；
- **让所有指纹描述同一个浏览器**——从 canvas/WebGL/字体到 TLS/h2，任何一处不一致都是信号；
- **让时间线像真人**——dwell 偏移、三包时序、页面时间戳；
- **接受它会一直变**，把“版本哨兵 + 自动重录 profile”当成一等公民。

Akamai 比 CF 多出来的两件事，值得单独记住：

1. **判据极简但有延迟**——`_abck` 一个字符定生死，而且要等下一跳 verify GET 才暴露；
2. **两道关要分开**——sensor 打分（载荷说了算）和业务边缘（出口 IP 说了算）是两件事，混在一起会把自己绕进去。

这次还多做了一组强校验对照，结论让我对纯算这条路更有底：**服务端是认真做逐字节内容校验的，改一处签名、改一段密文都过不了；而我们纯算产出的，正是能被它接受的那种合法字节**——合法重放能到 `~0~`，就是最直接的证明。剩下的，是 IP 和维护的体力活。

老规矩，本文只讲结构和思路，**会话级字母表、LCG 常数、内容签名算法、探针答案表、profile 数值、真实端点路径全部留白或打码**。不是藏私，是这些东西写出来就会过期，对双方都没好处。真要做，先把“按角色找”和“指纹一致性”这两件事做扎实，剩下的都是体力活。

---

**免责声明**：本文内容仅供安全研究与技术学习交流，请勿用于任何非法用途。因使用本文信息导致的后果由使用者自行承担。

| © White's Blog | [haloowhite.com](https://haloowhite.com) | [Telegram @haloowhite](https://t.me/haloowhite) |
