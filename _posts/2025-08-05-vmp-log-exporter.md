---
layout: post
title: "一个用于解决JSVMP海量日志导出技巧"
date: 2025-08-05
categories: [JSVMP, 逆向]
tags: [逆向, JSVMP, 日志导出, JavaScript, 调试工具]
description: "解决 JSVMP 逆向分析中海量日志导出难题：一段 JS 代码实现 console 日志自动收集、批量导出到本地文件，支持自动分批和定时导出。"
excerpt: "在运行之前将以下这段代码贴进console中运行，然后执行需要的逻辑，待日志完全打印，手动在console执行 `console.save()`，即可立马将所有的日志导出为本地文件..."
faq:
  - q: "为什么需要导出 JSVMP 日志？"
    a: "JSVMP 虚拟机执行时会产生海量日志（通常上万行），在浏览器 console 中直接分析非常困难。导出为本地文件后可以用文本编辑器搜索和分析，大幅提升逆向效率。"
  - q: "如何使用这个日志导出工具？"
    a: "在浏览器 console 中先粘贴运行导出代码，然后执行你需要分析的业务逻辑，等日志打印完毕后在 console 中执行 console.save() 即可将所有日志导出为本地文件。"
---

在运行之前将以下这段代码贴进console中运行，然后执行需要的逻辑，待日志完全打印，手动在console执行 `console.save()`，即可立马将所有的日志导出为本地文件

接下来就可以安安心心在本地分析日志内容了
```javascript
class VmpLogExporter {
    constructor(config = {}) {
        this.config = {
            maxConsoleLines: config.maxConsoleLines || 800,
            exportBatchSize: config.exportBatchSize || 500,
            autoExportInterval: config.autoExportInterval || 60000, // 1分钟
            enableAutoExport: config.enableAutoExport !== false,
            logPrefix: config.logPrefix || 'VMP_LOG',
            keepInConsole: config.keepInConsole || 100 // 控制台保留行数
        };
        
        this.logBuffer = [];
        this.fileCounter = 1;
        this.consoleLineCount = 0;
        this.isExporting = false;
        
        this.init();
    }
    
    init() {
        this.hijackConsole();
        if (this.config.enableAutoExport) {
            this.startAutoExport();
        }
        console.log(`🚀 VMP日志导出系统已启动 - 将自动保存日志避免浏览器崩溃`);
    }
    
    hijackConsole() {
        const originalMethods = {};
        ['log', 'warn', 'error', 'info', 'debug'].forEach(method => {
            originalMethods[method] = console[method];
            
            console[method] = (...args) => {
                // 记录到缓冲区
                this.addToBuffer(method, args);
                
                // 检查是否需要清理console
                this.consoleLineCount++;
                if (this.consoleLineCount >= this.config.maxConsoleLines) {
                    this.manageConsole();
                }
                
                // 正常输出到console
                return originalMethods[method].apply(console, args);
            };
        });
        
        this.originalMethods = originalMethods;
    }
    
    addToBuffer(level, args) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            args: this.serializeArgs(args),
            raw: args
        };
        
        this.logBuffer.push(logEntry);
        
        // 如果缓冲区过大，自动导出
        if (this.logBuffer.length >= this.config.exportBatchSize) {
            this.exportLogs();
        }
    }
    
    serializeArgs(args) {
        return args.map(arg => {
            if (typeof arg === 'object' && arg !== null) {
                try {
                    return JSON.stringify(arg, null, 2);
                } catch (e) {
                    return '[Circular Reference Object]';
                }
            }
            return String(arg);
        });
    }
    
    manageConsole() {
        if (this.isExporting) return;
        
        console.log(`📤 正在导出日志避免浏览器卡死...`);
        
        // 导出当前日志
        this.exportLogs();
        
        // 清理console但保留最新的一些日志
        console.clear();
        
        // 重新显示最近的重要日志
        const recentLogs = this.logBuffer.slice(-this.config.keepInConsole);
        recentLogs.forEach(log => {
            this.originalMethods[log.level].apply(console, [
                `[${log.timestamp}]`, 
                ...log.raw
            ]);
        });
        
        console.log(`🔄 Console已清理，保留了最近${recentLogs.length}条日志`);
        this.consoleLineCount = recentLogs.length;
    }
    
    async exportLogs() {
        if (this.isExporting || this.logBuffer.length === 0) return;
        
        this.isExporting = true;
        
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${this.config.logPrefix}_${timestamp}_part${this.fileCounter}.json`;
            
            const exportData = {
                exportInfo: {
                    timestamp: new Date().toISOString(),
                    partNumber: this.fileCounter,
                    totalLogs: this.logBuffer.length,
                    source: 'VMP_Logger'
                },
                logs: this.logBuffer
            };
            
            // 创建并下载文件
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
                type: 'application/json' 
            });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log(`✅ 已导出 ${this.logBuffer.length} 条日志到文件: ${filename}`);
            
            // 清空缓冲区
            this.logBuffer = [];
            this.fileCounter++;
            
        } catch (error) {
            console.error('❌ 导出日志失败:', error);
        } finally {
            this.isExporting = false;
        }
    }
    
    startAutoExport() {
        setInterval(() => {
            if (this.logBuffer.length > 0) {
                console.log(`⏰ 定时导出日志: ${this.logBuffer.length} 条`);
                this.exportLogs();
            }
        }, this.config.autoExportInterval);
    }
    
    // 手动导出当前缓冲区
    manualExport() {
        console.log('🖱️ 手动导出日志...');
        this.exportLogs();
    }
    
    // 导出所有日志的合并版本
    exportAllLogs() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${this.config.logPrefix}_COMPLETE_${timestamp}.txt`;
        
        const allLogs = this.logBuffer.map(log => {
            return `[${log.timestamp}] ${log.level.toUpperCase()}: ${log.args.join(' ')}`;
        }).join('\n');
        
        const blob = new Blob([allLogs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        
        console.log(`📄 已导出完整文本日志: ${filename}`);
    }
    
    // 获取状态信息
    getStatus() {
        return {
            bufferSize: this.logBuffer.length,
            consoleLines: this.consoleLineCount,
            fileCounter: this.fileCounter,
            isExporting: this.isExporting
        };
    }
    
    // 恢复原始console
    restore() {
        ['log', 'warn', 'error', 'info', 'debug'].forEach(method => {
            console[method] = this.originalMethods[method];
        });
        console.log('🔄 已恢复原始console行为');
    }
}

// 使用示例和配置
const vmpLogger = new VmpLogExporter({
    maxConsoleLines: 1000000,      // console最大行数
    exportBatchSize: 1000000,      // 批量导出大小
    autoExportInterval: 60000, // 60秒自动导出
    enableAutoExport: false,    // 启用自动导出
    logPrefix: 'VMP_REVERSE',  // 文件前缀
    keepInConsole: 1000000      // console保留行数
});

// 全局访问接口
window.vmpLogger = vmpLogger;

// 添加快捷命令
console.save = () => vmpLogger.manualExport();
console.saveAll = () => vmpLogger.exportAllLogs();
console.status = () => console.table(vmpLogger.getStatus());

console.log(`
🎯 VMP逆向日志系统使用说明:
• 系统会自动管理console日志，避免浏览器卡死
• 所有日志都会保存，不会丢失任何VMP算法信息
• 快捷命令:
  - console.save() : 手动导出当前日志
  - console.saveAll() : 导出完整文本日志
  - console.status() : 查看系统状态
• 日志文件会自动下载到Downloads文件夹
• 每个JSON文件包含完整的时间戳和元数据
`);
```

