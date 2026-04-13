---
layout: post
title: "有手就行系列——Cloudflare 5s 盾逆向实战（AST 反混淆 + 加密还原）"
date: 2026-04-13
categories: [逆向, Cloudflare]
tags: [逆向, Cloudflare, AST, 反混淆, TEA, RSA, LZW, JSVMP, Babel]
description: "深入解析 Cloudflare 5s 盾（Challenge Page）的完整请求链路、AST 反混淆流水线（字符串解密、花指令消除、控制流还原）、TEA-CTR + RSA + LZW 加密算法还原，以及 2026 年新版 JSVMP 变化分析。"
excerpt: "从混淆 JS 到明文，手把手拆解 Cloudflare 5s 盾的 AST 反混淆全流程与加解密算法还原。全部经过实际抓包和代码运行验证。"
faq:
  - q: "Cloudflare 5s 盾的加密算法多久更新一次？"
    a: "加密算法核心（RSA + TEA + LZW + Base64）经实测从 2025.08 到 2026.04 未变。变化的主要是混淆方式（字符串分隔符、JSVMP 引入）和字段名。"
  - q: "为什么不直接 Puppeteer 过盾？"
    a: "简单场景可以用，但 Cloudflare 检测无头浏览器。大规模场景下协议方案效率高出几个数量级——一次请求 vs 启动一个完整浏览器实例。"
  - q: "AST 反混淆工具推荐？"
    a: "Babel 是 JavaScript AST 最佳选择。核心库：@babel/parser（解析）、@babel/traverse（遍历）、@babel/generator（代码生成）、@babel/types（节点类型判断）。配合 Bun 运行速度很快。"
---

## 0、背景介绍

Cloudflare 的 5s 盾（Challenge Page）大家应该都不陌生，访问被保护的站点时会出现那个经典的 "Just a moment..." 页面。本质上是 Cloudflare 通过下发一段高度混淆的 JavaScript 脚本（ray JS），在浏览器端执行环境检测、指纹采集、加密计算后，将结果 POST 回服务端校验，通过后种上 `cf_clearance` Cookie 放行。

本文以实际目标站点为例，从请求链路分析到 AST 反混淆，再到加解密算法还原，完整记录逆向过程。文中涉及的加密算法、字段名均经过实际抓包和代码运行验证。

> **声明**：本文仅供安全研究与技术学习交流，请勿用于任何非法用途。

## 1、请求链路总览

整个挑战流程拆分为 4 步：

```
┌──────────────────────────────────────────────────────────────────┐
│  Step 1: GET /                                                   │
│  → 拿到 HTML，提取 window._cf_chl_opt 参数                       │
│  → 提取 ray JS 文件路径                                          │
├──────────────────────────────────────────────────────────────────┤
│  Step 2: GET /cdn-cgi/challenge-platform/h/{g|b}/orchestrate/... │
│  → 下载混淆 ray JS（~200KB）                                     │
│  → 提取动态路径、Base64 字符集、追加参数                           │
├──────────────────────────────────────────────────────────────────┤
│  Step 3: POST /cdn-cgi/challenge-platform/h/.../flow/ov1/...     │
│  → 构造挑战数据 → LZW 压缩 → TEA-CTR 加密 → 自定义 Base64 编码   │
│  → 提交第一次 POST（挑战响应）                                    │
├──────────────────────────────────────────────────────────────────┤
│  Step 4: POST（同上 URL）                                        │
│  → 构造 Turnstile 数据，同样加密流程提交第二次 POST               │
│  → 获取 cf_clearance Cookie                                      │
└──────────────────────────────────────────────────────────────────┘
```

### 1.1 第一步：获取 HTML 与关键参数

GET 请求目标站点，403 响应返回一个简洁的 HTML 挑战页面。关键信息在一段 `<script>` 中：

```javascript
window._cf_chl_opt = {
    cvId: '3',
    cZone: 'fastlink.so',
    cType: 'interactive',       // 挑战类型：interactive / managed
    cRay: '9eb833680f13fcf8',   // 请求 Ray ID
    cH: 'j9_nAkRY.6cKOoF...',  // 挑战哈希
    cFPWv: 'g',                 // 路径前缀标识：g 或 b
    cITimeS: '1776059505',      // 服务器时间戳
    md: '...',                  // 挑战元数据（超长字符串）
    cTplC: 0,
    cTplO: 0,                   // 新增属性
    cTplV: 5,
    cTplB: '0',
    // ...
};
```

提取方式，正则 + demjson3（因为 key 无引号，不是标准 JSON）：

```python
match_pattern = r'window\._cf_chl_opt = (.*?);'
_cf_chl_opt = re.findall(match_pattern, html)
_cf_chl_opt_dict = demjson3.decode(_cf_chl_opt[0])
```

同时从 HTML 中提取 ray JS 路径：

```html
<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=9eb833680f13fcf8"></script>
```

注意路径中的 `/h/g/` —— 这个 `g` 对应 `cFPWv` 的值，历史版本中有 `b` 和 `g` 两种。

### 1.2 第二步：下载并解析 ray JS

ray JS 是核心，一段约 **200KB** 的单行混淆 JavaScript。通过实际抓包分析，需要从中提取三个关键信息：

**提取动态路径**：POST 接口 URL 的组成部分

```python
# 新版中直接在引号内匹配
# 格式: /b/ov1/数字:数字:字符串/
pattern = r"'/([bg])/ov(\d)/([^']+)'"
# 示例结果: /b/ov1/711151733:1776056853:IDzOwF4DX3yC2T8JbE817xeJkiLURBMtj2aOzyTbIdg/
```

> ⚠️ 注意：旧版（2025年8-9月）中动态路径和 Base64 字符集用 `~` 符号包裹，新版（2026年4月实测）已经去掉了 `~`，改为直接赋值给变量。如果你用旧版正则匹配不到，大概率是这个原因。

**提取自定义 Base64 字符集**（65 个字符，每次请求都不同）：

```python
# 新版中赋值给变量 Qs（变量名可能变化）
# Qs='yXBun2Wgm6lrbakMe-VYDQx5Njwf0H478q$IKiGsPcO1UvtJZzpCRLo3dTAh9E+FS'
pattern = r"([A-Za-z][A-Za-z0-9])='([A-Za-z0-9+/\$\-]{64,66})'"
```

**提取追加的 `_cf_chl_opt` 属性**：

ray JS 会向 `window._cf_chl_opt` 追加新属性。当前版本追加了 `rbGs2`、`kGHpy2`、`dNKln0`、`OpmT8`、`qRrUl6` 等属性，其中 `qRrUl6` 包含翻译文本和 metadata。

POST 接口完整路径拼装：

```python
# cdn-cgi/challenge-platform/h/ + 路径前缀处理 + /b/ov1/ + 动态路径 + cRay + / + cH
url = f"/cdn-cgi/challenge-platform/h/.../{dynamic_path}{cRay}/{cH}"
```

### 1.3 第三步：构造并加密挑战数据

构造一个 JSON 对象作为挑战响应。字段名是混淆后的，但通过逆向可以理解含义：

```python
raw_post_data = {
    'fWZgU3': _cf_chl_opt_dict['cType'],  # 挑战类型
    'WVeU0':  _cf_chl_opt_dict['cvId'],   # 版本 ID
    'Oslmb8': 26.19,                       # JS 执行耗时（秒）
    'uuGY6':  1.3,                         # 初始化耗时
    'AZJj6':  _cf_chl_opt_dict['cITimeS'],# 服务器时间戳
    'GkHb5':  _cf_chl_opt_dict['md'],     # 挑战元数据
    'yWqY6': {                             # 事件计数器
        'dwtA3': 0,     # keydown
        'OdVjC8': 1,    # pointermove
        'VAgA8': 2,     # pointerover
        'OwKv1': 0,     # touchstart
        'OQkk2': 1,     # mousemove
        'Qadr2': 0,     # click
        'WWsp6': 0,     # wheel
        'BVVCR5': 4     # 总计
    },
    'XHHJ5': False,                        # window.top !== window.self
    'Pemqu1': ['window.frameElement'],     # DOM 查询结果
    'TRGB0': 'iDOoK3',                    # 固定值
    'EXKd3': 'sTgPn7',                    # 固定值
    # ...
}
```

> 这些字段名会随版本变化，但含义基本稳定。**事件计数器不需要精确**——设合理非零值就行。

### 1.4 第四步：Turnstile 二次验证

第一次 POST 成功后还需要第二次，载荷中 `fWZgU3` 变成 `chl_api_m`，附加 Turnstile 特有字段：

```python
raw_post_data_2 = {
    'fWZgU3': 'chl_api_m',
    'wqqTZ2': 'managed',                   # chlApiAction
    'CRawX7': '97a52a911cd8e2e0',          # chlApicData
    'cyhaB5': '0x4AAAAAAADnPIDROrmt1Wwj',  # Turnstile sitekey
    'HPjL8': 'new',                        # 固定值
    'jSSVF8': 970.5,                       # 性能计时（ms）
    # ... 更多时间指标和会话 token
}
```

## 2、加密算法还原

这部分是最有意思的。加密链路经实际代码运行验证：

```
JSON 对象 → 自定义 JSON 序列化（字节级） → LZW 压缩 → TEA-CTR 加密 → 自定义 Base64 编码
                                                          ↑
                                                     RSA 密钥交换
```

### 2.1 自定义 JSON 序列化

Cloudflare **没有**用 `JSON.stringify()`，而是手写了字节级序列化。直接操作字节数组，逐字符写入 ASCII 码：

```javascript
// null → [110, 117, 108, 108]  即 "null"
// true → [116, 114, 117, 101]  即 "true"
// string → 引号包裹 + UTF-8 编码 + JSON 转义处理
// object → {key:value} 递归，用 hasOwnProperty 遍历
```

转义字符映射也是手写的（`Lq` 数组），包含 `\b`、`\t`、`\n`、`\f`、`\r`、`\"`、`\\` 的映射。

### 2.2 LZW 压缩

序列化后的字节经过 LZW 压缩。初始字典 0-255 单字符，动态建立新词条。输出是 16-bit 对齐的位流，位宽随字典增长动态增加。

### 2.3 RSA 密钥交换

混合加密：RSA 用于交换 TEA 密钥。

```javascript
// 硬编码的 RSA 公钥（实测 2025.08 和 2026.04 完全一致）
n = BigInt('0x00e9d3dca1328a49ad3403e4badda37a6a...')  // 128 字节模数
e = BigInt(65537)

// 生成 128 字节随机密钥 Lw
let Lw = new Uint8Array(128);
crypto.getRandomValues(Lw);
Lw[0] = 0;  // 确保 < n

// RSA 加密：LH = Lw^e mod n（快速幂）
```

**但是**有一个关键发现：在当前的代码中，动态生成的 `Lw` 和 `LH` 紧接着就被**固定值覆盖**了：

```javascript
// 动态生成后立即覆盖
Lw = new Uint8Array([0, 171, 50, 168, 12, 105, 110, 252, ...]);
LH = [109, 128, 145, 132, 21, 62, 137, 240, ...];
```

这意味着 RSA 密钥交换在这个版本中实际上是"摆设"——每次使用固定的密钥对。这是逆向中的重要发现，意味着**只要这组固定值不变，加解密就是确定性的**。

> 经验证，这组固定值在 2025.08 至 2026.04 的版本中保持不变。

### 2.4 TEA-CTR 加密

数据加密使用 TEA（Tiny Encryption Algorithm），32 轮 Feistel 网络，DELTA 常量 `0x9E3779B9`（即 2654435769）。

但不是标准 ECB 模式，而是**自定义的 CTR 模式**：

```javascript
// 对第 i 个 8 字节块：
// 1. 生成两个 counter
counter1 = [0, 0, 0, 0, 0, 0, 0, i & 0xFF]
counter2 = [0, 0, 0, 0, 0, 0, 0, (i+1) & 0xFF]

// 2. TEA 加密 counter 生成密钥流
TEA_Encrypt(counter1, keySlice)   // → 8 字节
TEA_Encrypt(counter2, keySlice)   // → 8 字节

// 3. 拼成 16 字节作为密钥，再次 TEA 加密数据块
teaKey = counter1.concat(counter2)
TEA_Encrypt(dataBlock, teaKey)
```

密钥选取：从 `Lw` 128 字节数组中按 `9 * padding + 40` 偏移截取 16 字节。

实际运行验证 TEA 加密（Bun 环境）：

```
加密前: [1, 2, 3, 4, 5, 6, 7, 8]
加密后: [24, 76, 70, 253, 111, 118, 182, 253]  ✅
```

### 2.5 TEA 中的小数点混淆

仔细看 TEA 函数会发现奇怪的小数：

```javascript
P[1] << 16.02   // 等价于 P[1] << 16
F >>> 8.76      // 等价于 F >>> 8
255.45 & O      // 等价于 255 & O
```

JavaScript 位运算会先将操作数转为 32 位整数，所以 `16.02` 和 `16` 效果完全一样。纯粹增加阅读难度的混淆。

### 2.6 自定义 Base64

最后一步，标准 Base64 逻辑（3 字节 → 4 个 6-bit 索引），但查表用每次请求不同的 65 字符集。这使得不同请求产生的密文即使内容相同也完全不同。

**加密输出结构**：

```
┌──────────────┬──────────┬──────────────────────────┐
│  LH (128B)   │ padding  │  TEA-CTR 加密后的压缩数据  │
│  RSA 密文     │  长度    │                           │
└──────────────┴──────────┴──────────────────────────┘
                ↓ 整体自定义 Base64 编码 ↓
            最终提交的字符串（约 400-2000 字符）
```

实际运行验证完整加密：

```
输入: {"fWZgU3":"interactive","WVeU0":"3",...}
加密输出长度: 386
输出: fNB-qXD+$7BugwMUc2Qv0jAuHu9jQE$rBwQ559gg...  ✅
```

## 3、AST 反混淆实战

这是本文重头戏。Cloudflare 的 ray JS 使用**多层混淆**，直接阅读不可能理解逻辑。反混淆流程基于 Babel AST，分阶段处理。

### 3.0 混淆特征识别

先看混淆后的代码片段：

```javascript
~function (yG, JU, Jz, ...) {
  for (yG = I, function (J, T, DF, ya, l, D) {
    for (DF = { J: 1107, T: 1295, ... }, ya = I, l = J(); !![];) try {
      if (D = parseInt(ya(DF.J)) / 1 * (parseInt(ya(DF.T)) / 2) + ...) break;
      else l.push(l.shift())
    } catch (C) { l.push(l.shift()) }
  }(U, 471818), ...
```

识别出的混淆手法：

| 手法 | 特征 | 处理策略 |
|------|------|---------|
| **字符串数组** | 大字符串 split 成数组，通过索引访问 | 提取 → 计算偏移 → 替换 |
| **数组 shuffle** | push/shift 循环打乱顺序 | 本地执行 shuffle 还原 |
| **花指令（运算）** | `function(a,b) { return a + b }` | 内联展开 |
| **花指令（字符串）** | `obj['xAxKe'] = 'xooAt'` 间接引用 | 建映射表 → 替换 |
| **花指令（函数）** | `obj.fn(realFn, arg1, arg2)` 间接调用 | 分析参数 → 内联 |
| **死代码** | `if ('abc' === 'def') { ... }` | 常量折叠 → 删死分支 |
| **控制流平坦化** | `switch(order[i++])` 分发循环 | 提取顺序 → 按序展开 |
| **JSVMP** ⭐新版 | `this.h[]` + `this.g` 寄存器式 VM | 动态分析为主 |

### 3.1 字符串数组提取与还原

混淆的第一道防线。所有有意义的字符串被收集到数组中，通过索引访问。

**新旧版差异**：
- 旧版（2025.08）：用 `|` 分隔，如 `"str1|str2|str3".split('|')`
- 新版（2026.04）：用 `!` 分隔，1509 段，总长 35488 字符

```javascript
// Babel AST 遍历：寻找 "xxx".split("!") 模式
traverse(ast, {
  AssignmentExpression(path) {
    const { left, right } = path.node;
    if (t.isCallExpression(right) &&
        right.callee.property?.name === "split" &&
        right.callee.object.value?.length > 100) {
      global.stringArray = right.callee.object.value.split(right.arguments[0].value);
      // 找到了，数组长度 1509
    }
  }
});
```

**提取偏移量**：字符串访问函数 `return y = y - 291, T = arr[y], T` 中的 `291` 即偏移：

```javascript
traverse(ast, {
  ReturnStatement(path) {
    const exprs = path.node.argument?.expressions;
    if (exprs?.length === 3 && exprs.slice(0,2).every(t.isAssignmentExpression)) {
      global.offsetIndex = exprs[0].right.right.value;  // 如 291
    }
  }
});
```

**还原数组顺序**：数组被 shuffle 函数打乱了。方法是把 shuffle 代码提取出来本地执行：

```javascript
// 提取 shuffle 函数 + 辅助函数，本地 eval 执行
const runCode = `
let ${funcName} = function() {
   let arr = ${JSON.stringify(stringArray)};
   ${funcName} = () => arr;
   return arr;
};
${helperFunction}
!${shuffleCode}
${funcName}()
`;
stringArray = eval(runCode);  // 得到正确顺序
```

### 3.2 字符串解密替换

拿到正确的数组和偏移后，替换所有字符串引用。两种形式：

```javascript
// 形式 A：通过中间变量映射
NK = { W: 1186, J: 735 }
obj[decode(NK.W)]  →  obj["addEventListener"]

// 形式 B：直接函数调用
yG(533)  →  "document"
```

对应的 AST 处理：

```javascript
traverse(ast, {
  CallExpression(path) {
    const { callee, arguments: args } = path.node;
    // yG(533) → 直接替换
    if (t.isIdentifier(callee) && args.length === 1 && t.isNumericLiteral(args[0])) {
      path.replaceWith(t.stringLiteral(decodeString(args[0].value)));
    }
  }
});
```

### 3.3 花指令消除（运算型）

大量简单运算被包装成函数调用：

```javascript
// 混淆前定义
'pXsvz': function(f, j) { return f & j; }
// 混淆后调用
J['pXsvz'](C, 255)  // 实际就是 C & 255
```

处理：识别只有单个 return 语句的函数定义，建立字典，遍历调用处内联展开。

```javascript
function isObfuscatedFunction(node) {
  return node.type === "FunctionExpression" &&
         node.body.body.length === 1 &&
         node.body.body[0].type === "ReturnStatement" &&
         ["BinaryExpression", "LogicalExpression", "UnaryExpression"]
           .includes(node.body.body[0].argument.type);
}
```

**关键：需要多轮迭代**。花指令可能嵌套引用：`A['fn1'](B['fn2'](x, y), z)`，展开 `fn1` 后内部的 `fn2` 才暴露出来。代码中循环 3 次确保清除。

### 3.4 花指令消除（函数调用型）

更复杂的一种 —— 包装函数调用而非运算符：

```javascript
// 定义
'TqoiZ': function(n, P) { return n(P); }
// 调用
K['TqoiZ'](realFunc, arg1)  →  realFunc(arg1)
```

处理时需要分析参数对应关系 —— 第一个参数替换 callee，其余替换函数参数：

```javascript
if (paramList.length - 1 === newExpr.arguments.length) {
  newExpr.callee = t.cloneNode(paramList[0], true);
  for (let i = 1; i < paramList.length; i++) {
    newExpr.arguments[i - 1] = t.cloneNode(paramList[i], true);
  }
  path.replaceWith(newExpr);
}
```

### 3.5 死代码消除

混淆器插入大量永假条件分支：

```javascript
if ('abc' === 'def') { /* 垃圾代码 */ } else { /* 真实逻辑 */ }
```

识别两侧都是字面量的比较，直接折叠：

```javascript
traverse(ast, {
  IfStatement(path) {
    const { test, consequent, alternate } = path.node;
    if (t.isBinaryExpression(test) && bothSidesAreLiterals(test)) {
      const result = evaluateConstant(test);
      result ? path.replaceWithMultiple(consequent.body)
             : alternate ? path.replaceWithMultiple(alternate.body) : path.remove();
    }
  }
});
```

### 3.6 控制流平坦化还原

经典 Split-Switch 模式：

```javascript
// 混淆后
for (c = "4|5|0|2|3|1".split('|'), J = 0; !![];) {
  switch (c[J++]) {
    case '0': step0(); continue;
    case '1': step1(); continue;
    // ...
  }
  break;
}
// 还原后，按 4→5→0→2→3→1 顺序展开
step4(); step5(); step0(); step2(); step3(); step1();
```

实现逻辑：从 init 中提取顺序数组，建立 case→代码块映射，按序展开，替换整个 for 语句。

### 3.7 反混淆流水线

完整的处理流程：

```
raw.js                     ← 原始 ray JS
  ↓ handle.js              ← 主 AST（字符串解密 + 花指令 + 死代码 + 控制流）
result.js
  ↓ 二次处理.py             ← 正则清理残留格式
output.js
  ↓ handle-去除花指令.js     ← 二次 AST（深层花指令 + 字符串映射花指令）
final_output.js            ← 可读代码
```

## 4、新版变化：JSVMP 的引入

**2026 年 4 月实测**，最新的 ray JS 相比 2025 年 8-9 月版本有几个显著变化：

### 4.1 不变的部分

- **RSA 模数**：`0x00e9d3dca1328a49ad3403e4badda37a6a...`（260 位十六进制，完全未变）
- **RSA 公钥指数**：65537
- **TEA 算法**：DELTA=2654435769，32 轮，CTR 模式
- **加密链路**：JSON 序列化 → LZW → TEA-CTR → 自定义 Base64

### 4.2 变化的部分

| 特征 | 旧版 (2025.08) | 新版 (2026.04) |
|------|---------------|---------------|
| 路径前缀 | `h/b/`（cFPWv=b） | `h/g/`（cFPWv=g） |
| 特殊标记 | `~` 包裹 Base64/路径 | 去掉 `~`，直接赋值 |
| 字符串分隔符 | `\|` | `!` |
| 字符串表规模 | ~数百段 | 1509 段，35KB |
| 新增参数 | - | `cTplO`、`OpmT8` 等 |
| **JSVMP** | 无 | **205+ 处 `this.h[]` 引用** |
| 加密字符串 | 无 | 26 个 `$` 分隔的密文 |
| `runProgram` | 无 | 3 次调用 |

### 4.3 JSVMP（JS 虚拟机保护）

这是最大的变化。新版 ray JS 中出现了大量 JSVMP 特征：

```javascript
// 寄存器访问 (205次)
this.h[131 ^ this.g][3]
this.h[this.g ^ 234]

// 字节码读取
this.h[131 ^ this.g][1]["charCodeAt"](this.h[131 ^ this.g][0]++)

// 操作码分发
if (Q === 175) { /* 操作 A */ }
else if (24 !== Q) {
  if (101 === Q) { /* 操作 B */ }
} else { /* 操作 C */ }
```

这是一个**寄存器式虚拟机**：
- `this.h[]`：寄存器组
- `this.g`：寄存器偏移/密钥
- 字节码从字符串中按字节读取
- 操作码通过 XOR 解码后分发

JSVMP 使得**纯 AST 静态分析变得困难**——因为核心逻辑被编译成了字节码，AST 只能看到解释器框架，看不到实际业务逻辑。

**应对思路**：
1. **动态分析**：hook VM 的寄存器读写和操作码分发，trace 出执行日志
2. **补环境执行**：构造模拟浏览器环境，直接执行原始 JS
3. **字节码反编译**：提取字节码字符串和操作码映射表，写反编译器

这已经是另一个话题了，后续单独写。

## 5、一些实用经验

1. **事件计数器是弱校验**：`yWqY6` 里的值不需要精确，设合理非零值即可
2. **DOM 查询结果会变**：当前版本查 `window.frameElement`，历史版本查页面元素 ID
3. **Base64 字符集是一次性密钥**：即使截获密文，不知字符集无法解码
4. **Bun 比 Node.js 执行更快**：加密脚本跑 Bun 体验好很多
5. **curl_cffi 是必须的**：需要 TLS 指纹模拟，普通 requests 会被识别
6. **花指令多轮处理**：一轮不够，3 轮基本能清干净

## FAQ

### Q: Cloudflare 5s 盾的加密算法多久更新一次？

A: 加密算法核心（RSA + TEA + LZW + Base64）经实测从 2025.08 到 2026.04 未变。变化的主要是混淆方式（字符串分隔符、JSVMP 引入）和字段名。

### Q: 为什么不直接 Puppeteer 过盾？

A: 简单场景可以用，但 Cloudflare 检测无头浏览器。大规模场景下协议方案效率高出几个数量级——一次请求 vs 启动一个完整浏览器实例。

### Q: AST 反混淆工具推荐？

A: Babel 是 JavaScript AST 最佳选择。核心库：`@babel/parser`（解析）、`@babel/traverse`（遍历）、`@babel/generator`（代码生成）、`@babel/types`（节点类型判断）。配合 Bun 运行速度很快。

---

**免责声明**：本文内容仅供安全研究与技术学习交流，请勿用于非法用途。因使用本文信息导致的后果由使用者自行承担。

© White's Blog | [haloowhite.com](https://haloowhite.com) | [Telegram @haloowhite](https://t.me/haloowhite)
