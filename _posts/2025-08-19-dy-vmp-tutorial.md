---
layout: post
title: "有手就行系列——抖音最新bdms_1.0.1.19_fix参数构造a_bogus"
date: 2025-08-18
categories: [JSVMP, 逆向]
tags: [有手就行系列，逆向, JSVMP, 抖音]
excerpt: "本文将简单直接地带你一起通过补环境的方式，实现某音最新的a_bogus参数构造，并实现验证请求返回对应数据..."
---

## 0、背景介绍

本文将简单直接地带你一起通过补环境的方式，实现某音最新的a_bogus参数构造，并实现验证请求返回对应数据。

目标参数使用JSVMP 技术来实现关键的加密逻辑混淆。关于JSVMP，简单来说，就是用js在前端实现了一个栈式虚拟机，通过js实现相关的原子操作（类似汇编里的汇编机器语句）。相关的更详细的资料可参考这篇论文 [《基于 WebAssembly 的 JavaScript 代码虚拟化保护方法研究与实现》](https://pub-df7ca5ef070b4d47a2a7c8b98941cb71.r2.dev/Research%20and%20Implementation%20of%20JavaScript%20Code%20Virtualization%20Protection%20Method%20Based%20on%20WebAssembly.pdf) 。

![《基于 WebAssembly 的 JavaScript 代码虚拟化保护方法研究与实现》论文封面](https://pub-df7ca5ef070b4d47a2a7c8b98941cb71.r2.dev/Research%20and%20Implementation%20of%20JavaScript%20Code%20Virtualization%20Protection%20Method%20Based%20on%20WebAssembly%20.png)

这类JSVMP的特征为，在源码中会有一个又臭又长的字符串和一个又臭又长的函数，里面是又臭又长的循环switch结构，其本质是环境初始化的字节码和对应的解释器。

与之类似采用JSVMP手段的，还有知乎的`x-zse-96` 参数、腾讯滑块、快手sig3等



## 1、大致流程

一般的JSVMP也好，高强度混淆也好，只要补环境补好了，都可以直接无视相关的内部的执行或实现逻辑细节。只需要把js运行中缺失的环境或源码中进行检测的浏览器相关环境给补全即可，然后再添加一个对应的加密函数构造入口，实现能够构造对应参数。

本文面对的抖音JSVMP可能难度会更高一些，等你真正实际上手的时候，发现几乎所有的逻辑都在走 `return X(e, this, arguments, r)` ，以及解释器函数 `function d()` 中不断循环。一般有几种解决方法，一是在 `d函数` 中将关键的函数调用、运算逻辑，以及堆栈变化等插桩打日志，然后根据打印的日志进行分析相关的逻辑和参数构造；还有一个是反编译，将关键的函数执行等分析出来再复现；再有就是，我们本文用的补环境大法，实现补齐代码中用到的浏览器环境，并构造相关的加密入口实现参数生成。



## 2、补环境细节

我这里就直接给出需要补的环境的细节，直接按下面的参数补即可。

```javascript
/// 安装依赖
// bun add xhr2

// 基础全局对象设置
global.XMLHttpRequest = require('xhr2');

// Window对象（避免循环引用）
const window = {
  onwheelx: {_Ax: '0X21'},
  innerHeight: 1547,
  innerWidth: 1917,
  outerWidth: 3200,
  outerHeight: 1668,
  requestAnimationFrame: function() {},
  addEventListener: function() {},
  screen: {
    availHeight: 1668,
    availLeft: 0,
    availTop: 25,
    availWidth: 3200,
    colorDepth: 24,
    height: 1800,
    isExtended: true,
    orientation: {
      angle: 0,
      onchange: null,
      type: "landscape-primary",
    },
    pixelDepth: 24,
    width: 3200
  }
};

// 设置parent引用
window.parent = window;

// Location对象
const location = {
  href: "https://www.douyin.com/jingxuan"
};

// Document对象
const document = {
  all: {},
  createElement: function(tag_name) {
    return {
      classList: {}
    };
  },
  documentElement: {},
  createEvent: function() { return {}; },
  addEventListener: function() {}
};

// Navigator对象
const navigator = {
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
};

// LocalStorage对象
const localStorage = {
  getItem: function(key) {
    if (key === "xmst") {
      return '放置你自己的xmst值';
    }
    return null;
  }
};

// Screen对象
const screen = {};

// 全局引用设置
globalThis.window = window;
globalThis.location = location;
globalThis.document = document;
globalThis.navigator = navigator;
globalThis.localStorage = localStorage;
globalThis.screen = screen;

console.log("环境初始化完成");
```

先把 `/* V 1.0.1.19-fix.01 */` 整个源码copy下来放在本地，将上面这段环境初始化放在复制的源码最前面，这样就能够过相关的环境监测（后续有机会可以专门讲下相关的补环境细节和流程）。

接下来，我们现在来好好解释一下参数的构造入口以及需要注意的点。有一个思路的关键点还是在于`X(e, this, arguments, r)`，原理就是，我们需要断在真正参数构造的时候，根据相关的几个参数`e`、`argument`、`this`、`r` 这几个参数的特征，然后通过判断条件构造加密入口，例如，我这里直接给出关键源码，就能够构造将加密方法暴露在`window.encrypt`中，直接调用，传入对应的参数即可得出目标参数`a_bogus` 。

```javascript
var n = function () {
  // 通过特征值判断是否为目标加密函数
  if (
    JSON.stringify(e[0]) ===
    "[34,54,0,3,34,30,214,41,212,34,30,214,30,70,54,0,4,74,0,4,30,218,54,0,5,74,0,5,30,72,54,0,6,33,74,2,33,74,0,6,0,1,54,0,7,74,0,7,41,5,74,0,6,53,11,60,161,74,0,6,60,216,30,178,59,2,54,0,8,74,0,8,30,162,18,30,219,73,165,0,1,29,17,5,74,2,3,30,150,41,18,74,0,8,30,162,18,30,163,73,165,74,2,3,30,150,0,2,26,74,0,8,30,162,18,30,219,73,220,0,1,29,41,45,33,74,3,14,0,0,26,33,74,2,37,74,0,8,30,162,18,30,9,0,0,74,0,2,0,2,54,0,9,74,0,8,30,162,18,30,163,73,220,74,0,9,0,2,26,74,0,7,29,41,10,74,0,5,74,0,8,30,178,20,72,34,30,214,18,30,51,63,108,0,1,26,33,74,2,36,74,0,8,30,215,0,1,41,7,33,74,2,5,0,0,26,34,73,214,25,26,74,1,4,18,30,126,34,74,0,2,39,1,0,2,26,33,76]"
  ) {
    console.log("找到加密函数入口!");
    window.encrypt = n;
  }
  return X(e, this, arguments, r);
};

```

这里，我们还可以用另一种方法，确实是在抖音里这比较取巧的方式（因地适宜），构造XMLHttpRequest对象，并且通过send函数触发相应的参数构造，然后在合适的地方进行截取，将生成的加密参数给存在全局变量里。关键位置在下面，我就直接给出对应的关键结果了，原理还是和上面一样。

```javascript
var m = n.apply(d, e); // 原始代码
// 以下是我们添加的截取代码
if (e.length == 2 && e[0] === "a_bogus") {
  console.log("got e !!!");
  window.a_bogus = e[1];
  console.log("window.a_bogus", window.a_bogus);
  process.exit(0); // 退出进程
}
v[++p] = m; // 原始代码
```

这里有个细节，在获取到参数后，执行了`process.exit(0);` ，不然程序会继续执行然后报错，我只需要将截取到的参数拿出来即可，形式不重要，目的才是关键！



## 3、验证参数参数有效性

有了上述完整的参数生成逻辑，就能够通过根据相关的请求信息生成目标加密参数了。我这里拿热搜接口作为测试，当然你也可以使用其他的接口进行测试。

![验证成功照片](https://pub-df7ca5ef070b4d47a2a7c8b98941cb71.r2.dev/blog-dy-%20verify.png)

如图所示，不仅生成参数成功，还返回了相关的数据，说明我们构造的参数是合理可用的。有了参数后，可能后续需要注意的就是相关的风控，比如设备、环境信息、还有IP、msToken等。不过只要有足够耐心，并细心，总能初探成果，祝你顺利！



## :) 题外话

等之后有时间精力了，我再写一篇详细讲述一下抖音a_bogus生成中用到的魔改rc4、sm3、魔改base64算法，最主要的还是中间的数组校验位。
先挖一个坑，等有空了再更新吧，如果你遇到相关的爬虫、自动化或开发相关的疑难杂症，也欢迎联系我。