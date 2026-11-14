---
layout: post
title: "有手就行系列：Cloudflare Turnstile / 5s 盾 2026 下半年版：纯算（Rust）与补环境两条路线全拆解"
date: 2026-11-09
categories: [逆向, Cloudflare]
tags: [有手就行系列, 逆向, Cloudflare, Turnstile, 5s盾, 纯算, Rust, 补环境, JSVMP, TLS指纹, happy-dom]
description: "2026 下半年 Cloudflare Turnstile 与 5s 盾（Challenge Page）的完整链路、新版加密信封（DEFLATE + XTEA + 会话级 RSA）、JSVMP 静态反汇编思路，以及纯算（Rust）与补环境（Node + happy-dom + Go TLS sidecar）两条路线的原理、指纹面、实测数据与取舍。"
faq:
  - q: "Turnstile 能纯算吗？"
    a: "能。token 虽然由服务端下发（finisher 程序跑完后通过 postMessage 抛出），但客户端要做的只是构造出被接受的 payload。开源项目 cfsolve 用静态反汇编 VM + 原生作答的方式，在 non-interactive / invisible / managed 三种模式下都实测通过。代价是 CF 每次改 VM 结构都要跟着改代码。"
  - q: "纯算一定比补环境快吗？"
    a: "不一定。同机同 IP 32 并发实测，纯算 2.98 QPS、补环境 4.21 QPS；单 token CPU 分别约 3.8s 和 2.8s。纯算每个会话都要反混淆到不动点并符号化反汇编整个 VM 程序，V8 JIT 直接跑 CF 的 collector 只要两三百毫秒。纯算的优势在内存（约 146MB vs 350MB）和可解释性。"
  - q: "Turnstile token 和 cf_clearance 绑 IP 吗？"
    a: "实测 Turnstile token 不绑 IP，求解 IP 和使用 IP 可以不同，单次有效、约 5 分钟过期；cf_clearance 绑定求解时的出口 IP 和 User-Agent，换任一个都会被重新挑战。"
  - q: "为什么 TLS 指纹那么关键？"
    a: "payload 再对，ClientHello 不像 Chrome 也会被边缘直接 400。我们早期一个 Rust 版本用 CF 官方测试 sitekey 做对照实验依旧 400，最终定位是 TLS 库最高只能模拟 Chrome 136。另外一次 solve 必须只用一个 TLS 会话：复用会触发会话恢复，ClientHello 多出 pre_shared_key，JA4 的扩展数从 17 变 18。"
---

## 0、背景介绍

今年 4 月写过一篇《有手就行系列：Cloudflare 5s 盾逆向实战（AST 反混淆 + 加密还原）》，从请求链路、AST 反混淆到 LZW/TEA/RSA 还原都拆了一遍。那篇的结论是：协议方案能做，但跟 build 很累；最后说 JSVMP 的部分“后续单独写”，这篇算是补上。

半年过去，Cloudflare 又变了不少：5 秒盾的 VM 换了，字符串表和 opcode 每个 build 都在轮换，Turnstile 也分出了 managed / non-interactive / invisible 几种模式，`cf_clearance` 除了绑 IP 和 UA，还要和 TLS/HTTP2 指纹对得上。继续用老办法一个个补 DOM 属性，维护成本只会越来越高。

所以我们把两条路都做完了：

1. **纯 Rust 协议实现（纯算）**：不启动浏览器、不跑 JS 引擎、不建 DOM，直接把 Cloudflare 的脚本拉下来做反混淆，还原它自己的寄存器 VM，解析返回的字节码程序，按程序的要求现场采集探针数据，自己编码、自己发包。Turnstile token 和 5 秒盾 `cf_clearance` 都能出。
2. **Node + happy-dom 补环境**：不重写协议，给 Cloudflare 的原始脚本造一个足够像 Chrome 的壳，让它自己跑、自己发请求、自己回调 token。壳里该补的 DOM、WebGL、Canvas、Audio、WebRTC、IDL、`Function.prototype.toString` 全部补齐。

这篇把两条路的实现逻辑、关键细节、实测数据和踩过的坑完整讲一遍。**但不会写成复现教程**：密钥派生、VM handler 表、探针答案表、profile 数值这些“抄了就能跑”的东西全部留白。原因很简单——Cloudflare 两三个 build 就轮换一次，抄代码没有意义；而且这类东西传播得越广，死得越快。看懂结构和难点，比拿到一份跑两周就失效的代码有用。

> 仅用于自有站点或明确授权的测试环境。Turnstile token 一次性、约 5 分钟寿命；`cf_clearance` 绑出口 IP、UA 和客户端指纹，换 IP 或换客户端就废。

---

## 1、结果与路线

先看数据，不看广告。

### 1.1 纯 Rust

Windows Server 2022，AMD EPYC 9254，16C/32T，60 GB，单公网 IP，`target-cpu=native`：

| 场景 | 结果 |
| --- | --- |
| 单个 token | 2.96 s wall，2.56 CPU-s |
| 8 并发 | 8/8，4.95 s，1.63 QPS，约 98 CPM |
| 16 并发 | 16/16，6.37 s，2.51 QPS，约 151 CPM |
| 32 并发 | 32/32，10.75 s，2.98 QPS，约 179 CPM |
| 48 并发 | 能完成，但超过 5 分钟；单 IP 直接塌 |
| 同机 Node 版 32 并发 | 32/32，7.61 s，4.21 QPS，约 252 CPM |

Rust 版单发约 2.56 CPU-s；服务端把并发调度和重试算进去，每个成功 token 约 3.8 CPU-s。Node 单发路径约 2.8 CPU-s。看着 Node 的 QPS 更高，但 Rust 单进程内存小、没有 350 MB 的 Node + happy-dom + sidecar 开销，适合堆机器横向扩。单 IP 的瓶颈不在 CPU，而在 Cloudflare 对同一出口的行为判断。

一次典型运行的输出（token 已打码）：

```text
$ ./clean-solver-rs token 0x4AAAAAAABS7vwvV6VFfMcD \
    https://peet.ws/turnstile-test/non-interactive.html
1.***.***.***
# wall 2.96 s, CPU 2.56 s
```

对应的两轮：

```text
round 1  200  461233 B  accepted-with-program
round 2  200    2992 B  accepted
```

### 1.2 Node 补环境

macOS arm64，Node 25，2026-10-30，走 VPN，到 Cloudflare 的 RTT 0.3–1 s，UDP 被封：

| 场景 | 结果 |
| --- | --- |
| 单次 token（peet.ws non-interactive） | 2.66 / 2.78 / 3.13 s；冷缓存 4.14 s |
| 挑战页 `cf_clearance`（nexusmods） | 7.98 / 8.17 / 8.98 s |
| 挑战页里的 widget | 4.1–4.5 s |
| 6 路并发 | 12/12 token，约 55 token/min |
| 3 路并发 | 3/3，7.2–8.3 s |

质量指标比速度更重要：两轮都 `accepted`，challenge errors 为 0，GL/canvas 覆盖完整，call stack 来自实际服务的 `api.js`，ICE facts 形状一致。自有站点上用 siteverify 验过 9/9；挑战页 managed 8/8、interactive 3/3、non-interactive 4/4，每个都用第二次请求确认过 cookie 生效。

### 1.3 成功判据

- Token：必须以 `1.` 开头，四个点分段，不含 `$`。其他形状一律当失败。
- `cf_clearance`：拿到 cookie 不算完，必须用同一个出口 IP、同一个 UA 再请求一次目标页，返回 200 且不再挑战，才算过。
- 失败重试：网络错误、`Rejected`、不支持的 VM 变体可以重试；`Blocked`（站点直接返回错误页）和 `NotChallenged` 不要重试。

---

## 2、两条路线怎么选

|  | 纯 Rust 协议 | Node 补环境 |
| --- | --- | --- |
| 核心 | 反混淆 + 还原 VM + 解析字节码 + 自己实现探针 | 跑 Cloudflare 原始 JS，补齐浏览器表面 |
| 依赖 | Rust、BoringSSL、SWC 解析器 | Node、happy-dom、Go sidecar |
| 单次 CPU | 约 2.5 CPU-s（单发） | 约 1.1 s（主线程）+ 网络等待 |
| 内存 | 几十 MB 级 | 约 350 MB/进程 |
| 抗 build 轮换 | 靠“按角色找”，build 换名要改解析 | 脚本自己跑，换名基本无感；新探针要补 |
| 最难的部分 | VM、编码、探针答案 | DOM/IDL/GL/时间的“像” |
| 适合 | 大规模、成本敏感、能持续维护 | 快速上线、build 变化频繁、机器资源充足 |

两条路共享三件事：传输层指纹、设备 profile、token/cookie 的生命周期管理。区别只在于“谁来执行 Cloudflare 的脚本”。

一个很重要的认知：**浏览器不是敌人，是参考实现**。纯算不是把 JS 翻译成 Rust，而是把 JS 的行为观察清楚，再用 Rust 复现它的输入输出。补环境也不是“骗过检测”，而是让脚本在一个行为足够一致的宿主里正常跑完。

---

## 3、请求链路总览

先把请求链路走一遍。下面用 `0x0`、`0x1` 的编号，读起来清楚一点。两条链路的骨架先放这里：

```text
Turnstile widget
  GET 页面
   └─ api.js 302 → /turnstile/v0/<channel>/<build>/api.js
       └─ iframe /cdn-cgi/challenge-platform/h/<channel>/turnstile/if/...
           ├─ 内联脚本：_cf_chl_opt + VM + 首包模板
           ├─ POST /fo/... （首包）      → 程序：几十个探针
           ├─ POST /fo/... （探针包）    → finisher / 点击程序
           └─ postMessage complete       → token

5 秒盾挑战页
  GET 目标页 → 403 "Just a moment..."
   ├─ 内联脚本：_cf_chl_opt + replaceState + 加载 orchestrator
   ├─ GET  /cdn-cgi/challenge-platform/h/<channel>/orchestrate/chl_page/v1?ray=...
   ├─ POST orchestrator 首包            → 程序：turnstile.render(...)
   ├─ widget 会话（同上）
   ├─ POST orchestrator 第二包          → 程序：构造 clearance form
   └─ POST 表单                         → Set-Cookie: cf_clearance
```

### 3.1 Turnstile widget

**0x0 页面加载 `api.js`**

页面里的 `https://challenges.cloudflare.com/turnstile/v0/api.js` 会 302 到：

```text
/turnstile/v0/<channel>/<build>/api.js
```

这个 302 同时暴露两件事：当前 channel（`g`、`b` 之类，Cloudflare 按连接挑）和 build hash。两者都不能写死。2026-10 之后就见过 `g` 和 `b` 来回切，写死 channel 的代价是每次多一次文档重取。

`api.js` 根据 sitekey、模式、页面参数拼出 iframe 地址，大致是：

```text
/cdn-cgi/challenge-platform/h/<channel>/turnstile/if/ov2/av0/rcv0/0/<widget>/<sitekey>/light/.../auto/
```

**0x1 iframe 文档**

iframe 的 HTML 里有一段内联脚本。它做几件事：

- 生成 `window._cf_chl_opt`，里面是 sitekey、ray、模式、回调名、各种运行时字段；
- 定义一个寄存器 VM 的类，以及 `runProgram` 之类的入口；
- 准备首包模板、时间戳、资源计时、POST 日志这些状态。

字段名每个 build 都会换。所以纯算和补环境都不能按名字找，得按“角色”找：sitekey 的值一定是 `0x...`，ray 是 16 位 hex，模式是 `managed` / `non-interactive` / `invisible`，POST 路径一定带 `/fo/`，`cf-chl` token 一定和路径最后一段相同。

**0x2 首包 POST**

首包发到 iframe 同源的挑战接口，路径形如：

```text
/cdn-cgi/challenge-platform/h/<channel>/fo/<ray>/<token>
```

请求头里带 `cf-chl`、`content-type: text/plain;charset=UTF-8`、`origin`、`referer` 等。body 不是 JSON，是一段编码后的字符串：种子、填充、密文，具体后面讲。

响应也不是 JSON，而是一段“程序”——VM 字节码，外面可能还套了一层简单的掩码。解开之后交给 VM 执行。

**0x3 探针轮**

第一段程序不直接给 token，它按顺序跑几十个探针：navigator、WebGL、Canvas、Audio、WebRTC、字体、Intl、DOM 结构、performance entries、`new Error().stack`、时钟精度、benchmark、环境审计……每个探针写一条记录，记录外面有统一的信封字段：计数器、token、input、status、message、started、finished、duration。

探针跑完，客户端把记录组装成第二包，再 POST 一次。这一包的时间戳不是“现在”，而是按脚本里的间隔和每个探针的耗时排出来的；发送时间要落在“浏览器可能跑完所有探针”之后。

**0x4 点击轮（managed）**

如果 Cloudflare 觉得需要交互，第二包会返回一段更大的点击程序（非交互 key 上出现 100 KB 级别的程序，基本就是被判可疑了）。程序会在 shadow root 里创建 checkbox，挂 pointer/mouse 事件，点击后跑一段 SHA-256 的 proof-of-work，再发第三包。

non-interactive 和 invisible 通常两轮结束；managed 正常三轮。

**0x5 token 回来**

最后一轮响应让 iframe 通过 `postMessage` 把结果交给 `api.js`：

```js
{ source: 'cloudflare-challenge', event: 'complete', token: '1....' }
```

token 就是 `1.` + 四段。拿到之后站点自己 POST 给后端做 siteverify。

### 3.2 5 秒盾挑战页

**0x0 403 页面**

请求目标页，返回 403，但 body 是一整页 HTML，标题 “Just a moment…”。内联脚本生成 `_cf_chl_opt`，然后：

- `history.replaceState` 把地址临时改成带 `__cf_chl_rt_tk=...` 的形式；
- 创建一个 `<script>`，src 是本站的 `/cdn-cgi/challenge-platform/h/<channel>/orchestrate/chl_page/v1?ray=...`；
- 加载完成后把地址换回去。

**0x1 orchestrator**

这个脚本是页面侧的另一个会话，和 widget 的 iframe 不是一套 context。它有自己的首包、自己的编码器、自己的 VM。

**0x2 orchestrator 首包**

首包 POST 之后返回一段程序。程序不直接清挑战，而是调用 `turnstile.render(...)` 渲染一个 widget，参数里带 sitekey、action、cData、`chlPageData`、retry 和 refresh 开关。`chlPageData` 是把页面上下文绑进 token 的关键。

**0x3 widget 会话**

接下来就是前面 3.1 的流程。widget 完成后，把 token 和结果交回 orchestrator。

**0x4 orchestrator 第二包**

orchestrator 把 widget 的结果写进一条记录，再 POST 一次。响应程序会创建 form，塞入若干 hidden input，字段名和值都来自程序。

**0x5 提交表单**

表单 POST 到带 `__cf_chl_f_tk=...` 的地址。这里有个容易漏的点：`referer` 里的 `__cf_chl_f_tk` 要替换成 `__cf_chl_tk`，否则 cookie 拿不到。响应头 `Set-Cookie` 里就是 `cf_clearance`。

上一篇数了 13 个请求；现在取决于是否点击、worker fetch 和图片探针，常见 8–12 个。数量不是重点，重点是每个请求的角色和依赖顺序不能乱。

---

## 4、纯 Rust：把浏览器拆成协议

这一节讲 `cfsolve` 这一层的思路。它不执行 Cloudflare 的 JS，只用 SWC 把脚本解析成 AST，然后做重写、抽取和符号执行。

### 4.1 脚本获取与“按角色找”

第一步不是解析，而是把“这个 build 长什么样”确定下来：

- 从 `api.js` 的 302 拿 channel 和 build；
- 从文档里抽内联脚本；
- 从内联脚本里抽 `_cf_chl_opt`、`cf-chl` token、首包 URL、模式、回调名；
- 从 `api.js` 的源码里推导 `cs` call stack 的偏移（补环境路线用；纯算路线不依赖 `api.js`，直接从脚本位置重建 stack）。

所有抽取都遵循一个原则：**不按名字，按角色和值形状**。名字每轮都换，角色不换。比如：

- 值是 `0x` 开头、长度固定 → sitekey；
- 值是 16 位 hex → ray；
- 值是 `managed` / `non-interactive` / `invisible` → widget 模式；
- 字符串里包含 `/fo/`，且最后一段等于 `cf-chl` token → 首包路径；
- 对象字面量有 20 个以上字段 → payload 模板，而不是普通 options。

这一层做不稳，后面全白搭。Cloudflare 的 build 轮换最先打的就是名字。

### 4.2 反混淆：多轮定点重写

脚本本身是混淆过的：字符串加密、helper 套娃、控制流平坦化、状态机、死分支、寄存器数组、memoized string、合并函数……直接读基本没法读。

做法是写一组“定点重写”，每轮按顺序跑：

```text
解码字符串
  → 内联 helper
  → 还原控制流 / 状态机
  → 清理死分支、死属性
  → 还原寄存器数组、参数数组
  → 合并/拆解函数
  → 常量折叠、copy propagation
  → 清理未使用绑定
  → 命名去冲突
```

每一轮都可能让下一轮的改写生效：名字解出来之后才能内联 helper，内联之后才能看清控制流，控制流清楚之后才能发现更多调用。跑到“所有步骤都不再改变程序”为止。

这里有两个工程点：

1. **不执行脚本**。所有变换都在 AST 上做，避免把不可信的 JS 跑进进程。
2. **保留原始位置**。改写会打乱 span，但 VM 的 switch case 位置、stack 探针的 line:col、`new Error()` 的帧位置都依赖原始脚本。所以反混淆时要把 case 的原始偏移单独记下来，后面 stack 恢复和 opcode 映射都要用。

反混淆需要深递归，默认栈不够，所以有一个固定大小的 8 MiB deep-stack 线程池。不是每个 solve 新建线程，而是进程级复用，避免高并发下线程和地址空间爆掉。

### 4.3 VM 还原（重难点）

这是纯算里最硬的一块。

脚本里有一个寄存器机类，`run` 方法负责取指、解码 opcode、查 handler、执行。每个 session 的 opcode、handler 表、掩码都不一样，所以不能硬编码指令集。

恢复流程大致是：

1. 在 AST 里找到“有 `run` 方法、且 dispatch 循环形状符合预期”的类；
2. 抽出类体、`run`、dispatch 表、初始化代码；
3. 用符号执行的方式解释 handler：对程序字节做抽象求值，恢复每条指令的读寄存器、写寄存器、副作用和后继；
4. 从 entry 开始做 worklist，遇到分支就把后继入队；
5. 有些分支的目标被字符串 hash 掩码过，先记成 hidden，等字符串池里出现候选后再重试；
6. 同一个 pc 被两个 dispatch key 到达就停，因为 listing 里一个 pc 只能放一条指令；这说明这个 build 的 handler 形状不支持；
7. 解不出来的字节记成 failure，但继续解后面的。

最后得到一份 listing：指令、效果、后继、函数入口、字符串池、hidden 分支、失败位置。后面的探针发现、payload 布局、stack 恢复，全部从这份 listing 上读。

**这里的具体 handler 表、opcode 掩码和 hash 还原不展开。** 不同 build 的差异很大，贴出来也只是一份过期样本。

### 4.4 加密载荷

首包和二包的 body 是同一套编码，只是密钥材料不同：

```text
有序 JSON
  → 必要时压缩
  → 加帧头 / 版本
  → 补齐到分组边界
  → 用种子派生的密钥做分组加密
  → 用 128 字节种子做 RSA（e=65537）包装
  → 按 session 自带的 64 字符表做 base64
```

几个关键点：

- **JSON 的字段顺序有意义**。载荷模板按脚本里的赋值顺序生成，重新排序会让服务端看到不同的东西。
- **压缩是有条件的**。小于阈值的 payload 不压缩，压缩后更大也不压。这个判断在脚本里，不能想当然。
- **分组加密的密钥不是固定值**。它由随机种子、padding 和一个 16 字节的 key-transform secret 派生。secret 藏在脚本的 VM 初始化程序里，要靠反混淆和符号执行把它抠出来。
- **RSA 模数每个 session 都可能不同**。它也在脚本里。种子的第一个字节有特殊约定，保证数值小于模数。
- **base64 字母表每个 session 都可能不同**。不是标准表，必须从脚本里读出来。
- **响应也有掩码**，但比请求简单，解一层就能拿到 VM 程序字节。

**key 派生函数、帧格式细节、RSA 模数和字母表都不贴。** 这些是纯算的核心工作量，也是最能区分“看懂了”和“抄到了”的地方。

### 4.5 首包：模板、状态和时序

首包不是简单拼几个字段。它要复现脚本在浏览器里启动后积累的状态：

- payload 模板的字段和顺序；
- 初始 VM 程序安装的 options 和 window 全局；
- `Date.now()` 标记、交互计数器、POST 日志；
- 资源计时（iframe 导航、api.js、图片、首包本身）；
- getter 读出来的值、由常量构造出来的函数名；
- 每个字段的时间戳差值。

时间戳尤其麻烦。脚本里有一组 `intervals`（initialise / handoff / collect / send），首包的时间戳要按这些间隔排，不能全用同一个 `now`。二包的探针记录也要按每个探针的耗时排，发送时间不能早于“所有探针跑完 + pending 时间”。

纯算里有一个 `Timer` 专门维护三种时间：

- epoch 毫秒：记录和 options 用；
- `Instant` 时长：资源计时用；
- iframe 的 performance clock：输入事件和 proof 用。

三种时间不能混。混了就会出现“记录时间比导航还早”或者“`performance.now()` 和 `Date.now()` 对不上”这种一眼假的数据。

### 4.6 第二包：探针

第二包是纯算里工作量最大的一块。返回的程序里有 38 个左右的探针，每个探针有三个 dispatcher 状态：建记录、采集、完成计时。build 会重命名、重排这些状态，所以不能按顺序硬编码，要从状态转移图里恢复执行顺序。

分析流程：

1. 用 session 的 VM 反汇编程序，建索引；
2. 找 dispatcher：一组间隔很近的 hidden 比较，数量在 20 个以上；
3. 从状态转移图里发现探针，记录每个探针的三个状态、token、input、采集函数入口、字符串、写入字段；
4. 用“稳定字符串”把当前 session 的探针和参考 build 的探针对齐（Jaccard 相似度 + 字符串序列对齐 + 双向投票）；
5. 识别探针家族：能靠参考字符串识别的按参考 build 命名，结构清晰的直接读 listing；
6. 恢复记录信封、payload 布局、controller trace；
7. 生成 `stage2.json`，后面按这个计划采集和组装。

探针大致分几类：

| 类别 | 例子 | 处理方式 |
| --- | --- | --- |
| Worker / 网络 | worker navigator、worker fetch、WebSocket echo、host reachability | 现场发请求或按记录回放 |
| 媒体 | WebRTC SDP / candidates、mediaCapabilities、codec | 现场刷新 + 记录 |
| 图形 | Canvas2D、WebGL、SVG、字体、emoji、computed style | 记录 + 软件渲染 |
| DOM / 布局 | shadow root、rects、DOM mutation、document structure | 记录 + 现场测量 |
| 计时 | clock resolution、performance entries、benchmark | 现场算 |
| 语言 / 环境 | Date、Intl、Math、storage、isolation、console、native inspection | 记录 |
| 审计 | environment audit、environment、UA-CH、behavior、keyboard | 记录 + 现场补 |

参考 build 的 38 个探针里，23 类走回放，12 类现场测量，3 个是只改状态和时间的空壳；另外还有 benchmark、host reachability、WebSocket echo 这类不占参考编号、按程序结构现场算的家族。回放不是“把旧答案原样贴回去”，而是要按当前 session 刷新：

- iframe URL、`document.lastModified`；
- trace 成员和导航尺寸；
- 资源计时的 URL 和大小；
- worker navigator 的 UA 相关字段。

现场测量的探针包括：图片尺寸、worker fetch 的结果、WebSocket echo 的 `performance.now()`、host reachability、clock resolution、benchmark、stack、performance entries。

**每条记录的字段名、顺序、哪些字段在时间戳之前写、哪些在之后写，都要和程序一致。** 信封是固定的八件套：counter、token、input、status、message、started、finished、duration。status 从 0 走到 3，message 成功时为空。采集函数写入的字段分 early / late 两组，late 字段来自比探针活得更久的回调，必须放在时间戳之后。

### 4.7 点击与 proof-of-work

managed 模式会返回点击程序。纯算要把这套交互也复现出来：

- 从程序里恢复 checkbox 的 DOM 计划、CSS、事件序列、点击坐标、proof 参数；
- 生成 pointerover / pointerenter / pointermove / pointerdown / pointerup / mousedown / mouseup / click 的事件序列；
- 点击后等待脚本里的 delay，再跑 proof；
- proof 是 SHA-256 的 nonce 搜索，按前导零打分，多个 worker 一起跑，取最优；
- 关键不是“算得快”，而是“算得像浏览器”：每个 digest 的耗时按记录值节流，worker 启动时间、消息往返时间都要对上。

这里如果直接开满 CPU 疯狂算，反而会因为时间太短被看出来。纯算里用记录的 `digest_us` 和 `startup_ms` 做采样，让 proof 的节奏接近真实设备。

### 4.8 5 秒盾编排

挑战页在纯算里是另一个 session：

- 解析 403 页面，找 orchestrator 路径、loading token、回答后的地址；
- 构造 orchestrator 首包，带上 frame check、时间戳、页面 options；
- 解析返回程序，恢复 `turnstile.render` 的参数（sitekey、theme、action、cData、chlPageData、retry、refresh）；
- 跑 widget 会话；
- 把 widget 结果写进 orchestrator 的第二包；
- 解析响应里的 form：action、字段顺序、hidden input 的 name/value；
- 提交表单，处理 `Set-Cookie`，拿 `cf_clearance`；
- 可选地再请求一次目标页验证。

表单提交的细节很容易翻车：`content-type`、`origin`、`referer` 的替换、字段顺序、`content-length` 都要对。少一个，cookie 可能照样返回，但用不了。

### 4.9 传输层和 profile

纯算不发“普通 HTTP”。它用打了补丁的 BoringSSL 和 HTTP/2 栈，按浏览器 profile 发请求：

- TLS ClientHello：cipher suites、extension 顺序、GREASE、key share、sigalgs、证书压缩、ALPN；
- HTTP/2：SETTINGS、initial window、header table size、stream priority；
- 请求头：每种请求（导航、iframe、script、image、POST、worker fetch、form、WebSocket）有自己的顺序和取值；
- Cookie jar、redirect policy、referer policy；
- **每次 solve 一条新连接**，不复用 TLS session。复用了会带 `pre_shared_key`，指纹就变了。

profile 是一个 JSON，包含：

```text
engine           chromium / webkit
transport        TLS/H2 模板、UA、header order
browser          视口、widget 位置
timeline         页面加载各阶段时间
intervals        首包时间戳间隔
orchestrator     挑战页编排节奏
interaction      点击坐标、checkbox 尺寸、DPR、touch
resource_timing  资源计时各阶段比例
second           设备 facts、document、image、durations、startup/pending
answers          回放答案文件
challenge_page_answers  挑战页专用答案
```

一份 `answers.json` 大约 90–100 KB，来自真实设备/浏览器的抓包。采集方式不是“跑一遍脚本打印答案”，而是起一个 CONNECT MITM 代理：

- 代理替换 iframe HTML 里的 RSA 模数，换成自己的；
- 浏览器用代理的模数加密种子，代理再用原始模数重新包一遍转发；
- 代理因此能解出浏览器的明文 payload；
- 同时记录 ClientHello、HTTP/2 连接、请求头、响应体；
- 最后用 `build_profile` 把 capture 填进 profile。

这套采集需要真机/真浏览器、装 CA、配代理。iOS Safari 这种纯算驱动不了的，就靠它。

### 4.10 和旧版文章对一下

如果你看过我之前那篇《有手就行系列：Cloudflare 5s 盾逆向实战（AST 反混淆 + 加密还原）》，里面写的是 LZW + TEA-CTR + 固定 RSA 密钥。那是 2026-04 的 build，现在已经不能照搬。把两版放在一起看，变化大致是：

| 项 | 旧版（2026-04） | 当前（2026-10/11） |
| --- | --- | --- |
| 路径前缀 | `/h/g/` | 由 `api.js` 的 302 决定，`g` / `b` 都会出现 |
| 字符串表 | `!` 分隔，1509 段 | 每个 build 都换，长度和分隔符都变 |
| 压缩 | LZW | 条件压缩，不一定压 |
| 分组加密 | TEA-CTR | 分组加密，密钥由种子 + secret 派生 |
| RSA | 固定模数、固定密钥 | 每个 session 可能不同 |
| Base64 | 65 字符表 | 64 字符表，每个 session 不同 |
| 核心逻辑 | AST 里基本可见 | JSVMP，opcode / handler 每个 session 都变 |
| 字段名 | 相对稳定 | 每个 build 轮换 |

结论：旧文章里的“固定密钥 / 固定模数”只对那个 build 有效；现在的纯算不能依赖任何固定值，所有材料都要从当前脚本里现抠。这也是为什么本文只讲 pipeline，不贴具体数值。

---

## 5、补环境：给 Cloudflare 一个假 Chrome

补环境路线不重写协议，核心是“让 Cloudflare 的脚本自己跑”。跑得起来的前提是宿主足够像浏览器。

### 5.1 总体结构

- 用 happy-dom 建一个 parent page，再建一个 iframe；
- iframe 的 HTML 用真实挑战文档的 shell（去掉内联脚本，脚本单独 eval）；
- 在 iframe window 上装几十个 shim；
- eval Cloudflare 的原始脚本；
- 拦截并代理它发出的 fetch / XHR / WebSocket / 图片 / worker；
- 驱动 DOM 事件和 postMessage；
- 抓到 payload 后用 Go sidecar 按 Chrome 的 TLS/H2/header order 发出去；
- 把响应喂回脚本；
- 等 `complete` 回调拿 token。

为什么不用 Node 的 `vm` 裸跑？因为脚本要的东西太多了：DOM、CSSOM、layout、canvas、WebGL、audio、WebRTC、worker、iframe realm、事件循环、`performance`、`Function.prototype.toString`、IDL 属性描述符……裸 `vm` 补到能跑的成本，比 happy-dom 高一个数量级。

### 5.2 Realm：页面、父页、iframe 要分开

Cloudflare 会检查：

- `window.parent` / `window.top` 是不是真的 window；
- `iframe.contentWindow` 和 `contentDocument` 是否一致；
- `frameElement` 是否指回宿主 iframe；
- `postMessage` 在非 window 上调用是否同步抛 `Illegal invocation`；
- `srcdoc` iframe 的 CSP 和 `eval` 行为；
- shadow root 里的 iframe 是否有独立的 realm。

happy-dom 在这些地方有缺口，所以要单独补：

- `postMessage` 的 brand check：Chrome 在传错 receiver 时立刻抛错，happy-dom 会排队到定时器里才炸，导致整个 run 挂掉；
- `frameElement`：sandbox iframe 里 happy-dom 不设，脚本会拿它做身份判断；
- shadow root 里的 iframe：happy-dom 不建独立 context，用一个 stand-in realm 顶住；
- `srcdoc`：CSP、`script-src`、`eval` 的报错文本都要像 Chrome。

### 5.3 原生表面：`Function.prototype.toString` 只是第一关

这是补环境里最容易被低估的部分。Cloudflare 不只看一个 `toString`，它有一整套原生性检查：

- `fn.toString()` 是不是 `function name() { [native code] }`；
- `fn instanceof win.Function` 是否成立；
- `fn.name`、`fn.length`、`fn.prototype` 的描述符；
- `Object.getOwnPropertyNames(fn)` 是不是只有 `length` 和 `name`；
- `Object.getOwnPropertyDescriptor(fn, 'toString')` 是不是 `undefined`；
- `Function.prototype.toString.call(fn)`、`(fn + '')`、`fn.toLocaleString()`；
- `Object.create(fn).toString()` 会不会露出 `Object.toString` 的栈帧；
- `Object.prototype.toString.call(fn)` 的 tag；
- 原型链上每一层的 `toString` 归属；
- 是不是被 Proxy 包过；
- 枚举顺序、可枚举性、`Symbol.toStringTag`。

所以 shim 不是简单替换 `toString`，而是：

1. 遍历 realm 里所有平台函数；
2. 给每个函数登记“原生”标记；
3. 替换 `Function.prototype.toString`，按登记返回 native code；
4. 校正 `name` / `length` / 描述符 / 原型链；
5. 处理 Proxy 和 `Object.create` 的边界；
6. 定期校验描述符有没有被脚本改掉。

`window-surface.mjs` 再做窗口成员的全量普查：Chrome 有而 happy-dom 没有的，按 spec 值补；实在不知道的，用“抛错桩”而不是“返回 undefined”，因为后者更容易被识别。所有被碰过的桩都记录下来，跑完看 `stubs` 列表，空了才算干净。

`interface-members.mjs` 处理 `document` / `navigator` / `screen` / `screen.orientation` 的成员、getter/setter、调用记录；`idl-enumerability.mjs` 处理可枚举性；`enum-order.mjs` 处理 `for...in` / `Object.keys` 的顺序；`named-properties.mjs` 处理 window/document 上的命名属性访问；`html-idl-facts.mjs` 处理反射属性、事件、`all`、flat tree。

这些不是“可选优化”。Cloudflare 的环境审计会把这些组合起来看，单点像没用，要整体一致。

### 5.4 DOM、布局和 CSS

happy-dom 不做真实布局，但 Cloudflare 会读：

- `getBoundingClientRect()`、`getClientRects()`；
- `offsetWidth` / `offsetHeight` / `clientWidth` / `clientHeight`；
- `scrollWidth` / `scrollHeight`；
- `getComputedStyle()` 的一堆属性；
- `document.elementFromPoint()`；
- range / selection 的 rect；
- iframe 的位置和视口。

做法是“录制 + 规则”：

- `layout-probe-rects.json` 存一组测量好的 rect；
- `css-facts.json` 存 computed style 的事实；
- `layout-rects.mjs` 按元素特征和 CSS 规则匹配；
- `css-facts.mjs` 按 longhand 属性表补；
- `getClientRects` 对隐藏元素、`display:none`、`width=0` 等边界单独处理。

上一篇里那个 10 个 `div` 的 `srcdoc` iframe 探针，就是典型：它用一堆极端 CSS（超大 scale、matrix、负 margin、pt/rem 混用）测布局，然后把 `DOMRect` 序列化、`TextEncoder` 编码、`crypto.subtle.digest('SHA-256')` 哈希。补环境必须让这些 rect 和真实 Chrome 的浮点结果对得上，差一点哈希就变了。

### 5.5 Canvas、WebGL、Audio、媒体

这是补环境里第二硬的部分。

**Canvas / WebGL** 不是返回假数据，而是让真实渲染栈或软件后端算出来：

- `canvas-webgl.mjs` 在 JS 侧拦截 Canvas/WebGL 调用，把参数编码成操作，发给 GL bridge；
- `gl-bridge.mjs` 默认起一个 headless Chrome（默认 ANGLE，Windows 上走 D3D11），通过 CDP 在真实 GPU 栈上执行这些操作，把返回值编码回来；
- `gl-soft.mjs` / `canvas2d-soft.mjs` 是纯软件后端，在没有可用浏览器或需要确定性结果时兜底，实现 WebGL 状态机、shader 编译/链接、纹理、framebuffer、`readPixels`、Canvas2D 绘制和 `getImageData`；
- `gl-offline.mjs` 回放真实 Chrome 录制的 GL transcript；
- `gl-render.mjs` 根据对象路径选择 2D / WebGL / audio 后端；
- `gl-frame-facts.mjs` 校正 context attributes。

WebGL 的坑在于：`getParameter` 的返回值、extension 列表、精度、最大纹理尺寸、shader 编译日志、`readPixels` 的字节，全都要和录制的 GPU 一致。不同机器不同 GPU 的答案不一样，所以 profile 是绑设备的。

Canvas 的坑在于文字渲染。16×16 的文本探针每个 build 都可能换内容，而且不同平台的字体 rasterizer 不同。补环境用录制的 bitmap 层 + 软件渲染兜底；纯算路线则直接回放录制答案。

**Audio** 用 `OfflineAudioContext` 的 `PeriodicWave` 做带限波表。Blink 内部是 float32 的逆 FFT，SIMD kernel 还按 CPU 选，进程里没法完全复现。这里用解析式波表逼近，和真实值差 1–2 个 float32 ulp。`audio-soft.mjs` 还实现 `AnalyserNode`、`BiquadFilter`、`DynamicsCompressor` 的频响。

**媒体** 包括 `mediaCapabilities.decodingInfo`、`MediaRecorder`、codec 支持、WebRTC 的 SDP / candidates / data channel。WebRTC 的 candidate 不是编的：`ice-candidates.mjs` 真的绑 UDP、发 STUN binding，按 RFC 8489 的重传节奏（0 / 250 / 750 / 1750 ms）拿 host 和 srflx candidate。UDP 被封时，会记一个 10 分钟的“STUN blocked”memo，下次直接返回 host facts，但后台仍会重试；一旦通了就清 memo。

### 5.6 网络、设备、时间和事件

**网络**：

- `fetch` / XHR 按脚本期望返回：worker fetch 可能是 401，图片是真实的宽高，`/pat/` 是 401；
- `subresource-loads.mjs` 记录并回放子资源加载；
- `performance-entries.mjs` 提供 resource timing、server timing、navigation timing；
- WebSocket 要真的建连并 echo `performance.now()`；
- `host_reachability` 要按浏览器的失败/成功结果返回。

**设备**：

- `navigator.connection` 的 effectiveType / rtt / downlink；
- `navigator.deviceMemory`、`hardwareConcurrency`；
- Battery Status API；
- `performance.memory`；
- `navigator.userAgentData` 的 brands / fullVersionList / platform；
- OPFS / storage 的配额和目录结构；
- `screen` 的尺寸、availWidth/Height、colorDepth、pixelDepth；
- `Intl` 的时区、locale、DateTimeFormat 输出；
- 字体枚举和 `document.fonts.check`。

**时间**：

- `performance.now()` 的量化粒度（Chrome 的 clock quantum）；
- `Date` 的时区和当前时间；
- 定时器的顺序和最小延迟；
- `performance.timeOrigin` 和 resource timing 的基准。

这里有个原则：**不要用虚拟时间**。把定时器提前触发会让 Cloudflare 看到的两轮间隔变短，短期可能更快，长期更容易被标记。补环境只去掉“模拟器自己多加的等待”，不改脚本本来该有的节奏。

**事件**：

- checkbox 的点击不是 `element.click()` 一下就完事，要按真实 pointer/mouse 序列发；
- 每个事件的 `clientX/Y`、`pageX/Y`、`screenX/Y`、`offsetX/Y`、`movementX/Y`、`pressure`、`pointerType`、`isTrusted`、`timeStamp` 都要合理；
- `click-gesture.mjs` 从 `click-facts.json` 读事件形状和常量；
- 点击后 `disabled`、`aria-checked`、`class` 的变化也要跟上。

### 5.7 录制、一致性和维护

补环境不是“写死一套答案”。它靠录制：

- `recordings/bypasscity-gl.jsonl` 是真实 Chrome 的 GL/canvas/audio/WebRTC 答案链；
- 每个 build 的 16×16 文本探针单独一层；
- `gl-transcript*.jsonl` 是不同 Chrome 版本的链；
- `answers.json` / `parent-page-facts.json` / `layout-probe-rects.json` / `css-facts.json` 是各类事实。

一致性是硬要求：

- UA、`sec-ch-ua`、`navigator.userAgentData`、GL 答案、字体、TLS 指纹必须描述同一个浏览器；
- 改一个就要全改；
- 每个 solve 一个 sidecar，避免 TLS session resumption 改变指纹；
- Chrome major 从录制文件第一行读，不要手写。

维护时看 meta 文件：

- `build` / `channel` 是否和 STATE 一致；
- 两轮是否都 `accepted`；
- round 2 是不是 3 KB 左右的 finisher；
- `challengeErrors` 是否为 0；
- `stubs` 是否为空；
- `glMisses` 是否为空。

如果非交互 key 的 round 2 出现 100 KB 级别，基本就是指纹被判可疑，先查一致性，再查出口 IP。

---

## 6、两条路共同的坑

这一节是踩坑清单，不分纯算还是补环境。

### 6.1 build 轮换

Cloudflare 每隔一段时间换 build，换的东西包括：

- 内联脚本、VM 字节码、opcode/handler 表、加密字符串表；
- `_cf_chl_opt` 的字段名；
- `api.js` 的 build hash 和 channel；
- `cs` call stack 的 line:col；
- 16×16 文本探针的内容；
- 新的 API brand check、DOM 一致性检查。

所以两条路都必须“按角色找”，不能按名字。纯算还要能识别“不支持的 VM 变体”并重试/降级；补环境要能记录新探针并补 shim。

### 6.2 指纹一致性

Cloudflare 不只看单点。它会交叉验证：

- UA 说 Chrome 154，`sec-ch-ua` 说 153 → 假；
- `navigator.userAgentData` 的 fullVersionList 和 UA 对不上 → 假；
- WebGL 说 ANGLE/D3D11，但 Canvas 字体是 Linux → 假；
- TLS/JA4 和 UA 描述的浏览器族不一致（比如 UA 是 Chrome，TLS 却是 Firefox 的形状）→ 假；
- `performance.now()` 的粒度和 Chrome 对不上 → 假；
- 两轮间隔太短，探针耗时全是 0 → 假。

纯算的 profile 和补环境的 shim 都要围绕“同一个浏览器”来维护。这是最容易忽略、也最容易翻车的地方。

### 6.3 时间

时间是最容易被低估的信号：

- 记录时间戳和导航时间的前后关系；
- 每个探针的耗时；
- 两包之间的间隔；
- `performance.now()` 的量化；
- proof 的节奏；
- 点击前的 delay。

纯算用 `intervals` 和 `durations` 排时间；补环境用真实的定时器和 `performance` 时钟。两边都不能“全用 0”或“全用现在”。

### 6.4 IP、UA、TLS 绑定

`cf_clearance` 绑：

- 出口 IP；
- UA；
- 客户端 TLS/HTTP2 指纹。

所以：

- 用哪个代理解，就用哪个代理访问；
- 不要用 curl 随便带 cookie 试；
- 换 IP 要重新解；
- 多 IP 池要保证每个 IP 的指纹一致。

Turnstile token 虽然不像 clearance 绑得那么死，但也是单次使用、约 5 分钟寿命，站点后端还会校验 sitekey、action、cData、hostname。

### 6.5 限流和错误处理

- `/fo/` 返回 400 大概率是限流，不是判定失败，应该退避；
- 单 IP 并发 32 是甜点，48 开始塌；
- 挑战页失败要区分 `retry` / `no_cookie` / `unverified` / `not_challenged` / `internal`；
- 纯算的 `Unsupported`（新 build / 新 VM 变体）不要无限重试，记下来等适配；
- 补环境有一个已知的偶发崩溃：Cloudflare 自己的脚本里 `JSON.parse` 读到 `un:stun1.l...`，约 1/12 的概率，重试即可。

### 6.6 资源

- Node 版每个 worker 约 350 MB，`CONCURRENCY` 不要超过物理核数；
- 纯算 deep-stack 线程池是进程级的，不要每个 solve 建；
- 每个 solve 一个 sidecar，别复用；
- token stock 是可选的，开了要接受“token 已经在老化”。

---

## 7、性能：时间到底花在哪

### 7.1 纯算

单 token 2.96 s wall，2.56 CPU-s。CPU 主要花在：

- 反混淆（多轮 AST 重写）；
- VM 反汇编（handler 符号执行是大头）；
- 探针分析和答案组装；
- 编码和加密。

网络往返占 wall time 的大部分。优化方向不是“把加密写得更快”，而是：

- 减少不必要的请求；
- 复用连接（但不能复用 TLS session）；
- 并发处理独立的探针（ICE、worker fetch、WebSocket）；
- 用 semaphore 控制并发，避免单 IP 打爆；
- 给每次 solve 设超时，别让卡住的请求占着 permit；
- 可重试错误重试，不可重试错误快速失败。

### 7.2 补环境

一次 one-shot 4.2 s wall 的 CPU profile：

| 本地工作 | 时间 |
| --- | --- |
| Cloudflare 自己的脚本 | 约 280 ms |
| 指纹表面（native toString、window 成员、IDL 可枚举性、枚举顺序） | 约 300 ms |
| 模块加载 | 约 200 ms |
| happy-dom、GC、其他 | 约 150 ms |

主线程忙约 1.1 s，剩下 3.1 s 在等网络。零延迟网络下大约 1 s 能完成。剩下的都是往返：连接预热、api.js、挑战文档、两轮 `/fo/`、worker 的 `/i/` 和 `/pat/`、图片。

做过的优化（都不改变 Cloudflare 看到的内容）：

- channel 记忆：把上次服务的 channel 写进缓存，下次直接猜；
- STUN 并行 + blocked memo；
- site call frame 缓存；
- clearance 跳过父页 call frame 查询；
- clearance 预启动 widget 进程；
- sidecar 自动选择。

故意没做的：

- 跳过 api.js 请求；
- 跳过 clearance 表单 POST；
- 用虚拟时间压缩两轮间隔。

这三个都能再省 0.1–1 s，但都会改变 Cloudflare 的观察结果，不值得。

---

## 8、总结

两年前那篇《cloudflare 5s 盾流程分析》，最后一句是“模拟浏览器他是臭的吗？指纹浏览器他不香吗？”。现在我的答案会稍微复杂一点：

- 如果只是少量、低频、要求快速上线，补环境 + 真实浏览器/指纹浏览器仍然是最省心的；
- 如果要上量、控成本、长期维护，纯算值得做，但它的成本不在“写代码”，而在“跟 build”；
- 两条路不是互斥的。可以用补环境采集 profile 和答案，用纯算跑量；也可以用纯算做快速验证，用补环境兜底新 build。

真正难的从来不是某个加密函数，而是：

1. 每个 build 都能稳定地找到“角色”，而不是“名字”；
2. 让所有指纹描述同一个浏览器；
3. 让时间线和真实浏览器的行为一致；
4. 接受 Cloudflare 会一直变，维护是一等公民。

最后再强调一次：本文只讲结构和思路，**关键表、密钥派生、探针答案、profile 数值都做了留白**。不是藏私，是这些东西写出来就会过期，而且对双方都没好处。真要做，先把“按角色找”和“指纹一致性”这两件事做扎实，剩下的都是体力活。

---

**免责声明**：本文内容仅供安全研究与技术学习交流，请勿用于任何非法用途。因使用本文信息导致的后果由使用者自行承担。

| © White’s Blog | [haloowhite.com](https://haloowhite.com) | [Telegram @haloowhite](https://t.me/haloowhite) |
