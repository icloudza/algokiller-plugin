# GumTrace × Frida 实战教程

把 [GumTrace](https://github.com/lidongyooo/GumTrace)（@lidongyooo 基于 frida-gum Stalker 写的 ARM64 trace 工具）部署到越狱 iOS 设备，对目标 App 做指令级动态追踪，产物可直接喂给 AlgoKiller plugin 做密文 / 流程分析。

本目录附两个已验证脚本：

| 脚本 | 用途 | hook 入口 | 验证产物 |
|---|---|---|---|
| `wechat-correct.js` | 根因验证版（最小可用） | `-[UIView layoutSubviews]` 第一次触发 | 36 KB / 436 行 |
| `wechat-startup-trace.js` | 启动期完整 trace（推荐） | `-[MicroMessengerAppDelegate applicationDidBecomeActive:]` + autotrigger | 115 MB / 1,125,561 行 |

---

## 1. GumTrace 是什么

GumTrace 把 frida-gum 的 Stalker 单独编译成一个 dylib（iOS）/ so（Android），暴露 3 个 C 导出符号：

```c
void init(const char *modules, const char *trace_path, int thread_id, GUM_OPTIONS *opt);
void run();
void unrun();
```

- `modules`：逗号分隔的模块名（要 trace 的模块），如 `"WeChat,mmcronet"`
- `trace_path`：trace 文件落盘路径（必须 App 沙盒内可写）
- `thread_id`：**关键参数**——`0` 表示当前线程，非 0 表示指定 tid
- `opt`：8 字节 struct，第一字段 `mode`，可选 `0 (Stand) / 1 (Debug) / 2 (Stable)`

输出格式（每条指令一行）：

```text
[module] 0xABS!0xREL mnemonic operands; observed_inputs -> observed_outputs
call func: <symbol>(<args>)
class : <ObjC class name>
ret: <value>
```

这正是 AlgoKiller `bind_trace` 直接消化的格式。

---

## 2. 部署到越狱 iOS（Dopamine / palera1n）

### 2.1 编译

GumTrace 仓库自带 `build_ios.sh`，依赖：
- macOS + Xcode CLT
- CMake 3.18+
- frida-gum iOS 头文件（仓库已带 `libs/FridaGum-IOS-17.8.3.h`）

```bash
cd /path/to/GumTrace
./build_ios.sh
# 产物：build_ios/libGumTrace.dylib
```

### 2.2 推到设备

GumTrace.dylib 通过 ellekit / TweakInject 注入到目标 App：

```bash
# 1) USB iproxy 起 SSH 通道（如已配置可跳过）
iproxy 2222 22 &

# 2) 推 dylib 到 TweakInject 目录（Dopamine 路径）
scp -P 2222 build_ios/libGumTrace.dylib root@localhost:/var/jb/usr/lib/TweakInject/GumTrace.dylib

# 3) ldid 签名（确保有 entitlements）
ssh -p 2222 root@localhost "ldid -S /var/jb/usr/lib/TweakInject/GumTrace.dylib"

# 4) 让 TweakInject 重新扫描（kill SpringBoard）
ssh -p 2222 root@localhost "killall -9 SpringBoard"
```

> ⚠️ 不要给 WeChat 主二进制重签名 / 加 entitlements——会破坏 Apple Distribution 证书链，导致 FBS 拒绝 launch。要让 dylib 在 WeChat 内运行，**只依赖 ellekit 注入链**即可。

### 2.3 验证注入

```bash
frida -U -n WeChat -e "console.log(Process.enumerateModules().filter(m => /GumTrace/i.test(m.path)))"
```

输出应能看到 `libGumTrace.dylib` 已在进程模块表里。

---

## 3. 正确的使用范式（⚠️ 关键陷阱）

读源码 `src/GumTrace.cpp:411-415`：

```cpp
void GumTrace::follow() {
    trace_thread_id > 0
        ? gum_stalker_follow(_stalker, trace_thread_id, _transformer, nullptr)   // ← iOS 不可靠
        : gum_stalker_follow_me(_stalker, _transformer, nullptr);                // ← 装当前线程 TLS
}
```

两条分支在 iOS 沙盒 + ellekit 注入环境下表现**完全不同**：

| 分支 | 触发条件 | iOS 行为 |
|---|---|---|
| `gum_stalker_follow(stalker, tid, ...)` | `thread_id > 0` | 异步抢占目标线程的 stalker state，受沙盒 / AMFI 干扰，**经常静默失败**（不报错、但 buffer 永空、trace 0 字节） |
| `gum_stalker_follow_me(stalker, ...)` | `thread_id == 0` | 把 stalker 装到**当前调用线程的 TLS**，立即生效 |

**所以必须用 `thread_id = 0` 走 `follow_me`**，再配合**让 init+run 跑在目标线程的上下文**。

### 错误姿势（会 trace 0 字节）

```javascript
// ❌ setImmediate 跑在 frida JS thread，不是 WeChat main thread
// ❌ thread_id 传 mainTid，走 gum_stalker_follow(tid) 不工作
setImmediate(() => {
    const mainTid = Process.enumerateThreads()
        .reduce((a, b) => a.id < b.id ? a : b).id
    init(modules, path, mainTid, opt)   // ← 双重错误
    run()
})
```

### 正确姿势

```javascript
// ✅ Interceptor.attach 的 onEnter 回调跑在目标符号所在线程
// ✅ thread_id = 0 → follow_me 装当前线程
let started = false
Interceptor.attach(targetObjCMethod.implementation, {
    onEnter() {
        if (!started) {
            started = true
            init(modules, path, 0, opt)   // ← thread_id = 0
            run()                          // ← stalker 装到 onEnter 当前线程
        }
    }
})
```

参考作者 `example_ios.js` 第 37 行：`let threadId = 0   // 0 = 当前线程`。这一行没读 → 14 次失败的根因。

---

## 4. 怎么挑 hook 入口符号

要保证 init+run 在 **App 的业务主线程**上下文里执行。挑选原则：

1. **必须跑在 main thread**：ObjC UI 方法基本都是，避开 GCD 队列回调
2. **App 启动后能稳定触发**：attach 模式下 didFinishLaunching 已过期，挑 didBecomeActive / layoutSubviews 这类
3. **避免 reentrancy**：不要 hook 在 init+run 自己路径上会调用的符号，否则爆栈

### 用 Binary Ninja 找 AppDelegate

WeChat 主二进制反编译，搜 `MicroMessengerAppDelegate`：

```
+[MicroMessengerAppDelegate GlobalInstance]                        0x1041b45c8
-[MicroMessengerAppDelegate application:didFinishLaunchingWithOptions:]  0x1041b8c48  ← spawn 模式入口
-[MicroMessengerAppDelegate continueMainLaunching:]                0x1041b4950
-[MicroMessengerAppDelegate initHighPhaseLaunchTask]               0x1041b0d78
-[MicroMessengerAppDelegate didFinishLoad]                         0x1041b8ad8  ← 启动完成
-[MicroMessengerAppDelegate applicationDidBecomeActive:]           0x1041bdccc  ★ 推荐
-[MicroMessengerAppDelegate applicationWillEnterForeground:]       0x1041bd610
```

★ `applicationDidBecomeActive:` 是 attach 模式下的最佳入口：每次切前台都触发，可反复测试。

---

## 5. 自动触发：绕开物理切前后台

Attach 模式下脚本上来时 `applicationDidBecomeActive` 早过去了。两个办法：

**A. 物理操作**：iPad 上 home swipe 出 WeChat，再点回去（依赖手）
**B. 程序模拟**（推荐）：通过 ObjC.schedule 把当前 App 的 `applicationDidBecomeActive:` 直接调一次

```javascript
setTimeout(() => {
    ObjC.schedule(ObjC.mainQueue, () => {
        const app = ObjC.classes.UIApplication.sharedApplication()
        const del = app.delegate()
        del.applicationDidBecomeActive_(app)
    })
}, 1500)
```

`ObjC.schedule(mainQueue, fn)` 保证 fn 在 main thread 跑——onEnter 回调里 `Process.getCurrentThreadId()` 就是 main tid（如 259）。

---

## 6. 完整运行流程

```bash
# 1) iPad 重启 WeChat，等其进入 active 状态
ssh -p 2222 root@localhost "killall -9 WeChat 2>/dev/null; sleep 2; uiopen weixin://"
sleep 12   # GumTrace ellekit 注入 + WeChat 初始化窗口

# 2) 拿 PID 后 attach
PID=$(frida-ps -U | awk '/WeChat$/{print $1}' | head -1)
(sleep 35; echo) | frida -U -p "$PID" -l wechat-startup-trace.js > /tmp/frida.log 2>&1

# 3) 拉 trace 文件回来
scp -P 2222 root@localhost:'/var/mobile/Containers/Data/Application/*/Documents/wechat-startup.trace.log' \
            ~/captures/wechat-startup.trace.log

# 4) 喂给 algokiller
# 在 Claude Desktop 里调 algokiller.bind_trace(path=..., mode='general')
```

> 用 `(sleep 35; echo) | frida ...` 给 stdin 喂超时管道——避免 frida REPL 收 EOF 立即退出导致 setTimeout 没机会跑完。

---

## 7. Mode 选择（GUM_OPTIONS）

```javascript
const opt = Memory.alloc(8); opt.writeU64(<mode>)
```

| mode | 名称 | flush 频率 | 适用 |
|---|---|---|---|
| 0 | Stand | buffer 满 (~64K) 才 flush | 生产采样，trace 大 |
| 1 | Debug | 每 ~20 条指令 flush | 调试 / 早期观测，文件能立刻看到内容 |
| 2 | Stable | 启用安全范围检查（RW 段过滤） | 跑长时间避免崩溃，性能略低 |

调试期推荐 `1`，生产采样推荐 `0` 或 `2`。

---

## 8. trace 喂给 AlgoKiller plugin

trace 文件落到 macOS 后，在 Claude Desktop 里：

```
algokiller.bind_trace(path="/Users/<you>/captures/wechat-startup.trace.log", mode="ciphertext")
```

- `mode="ciphertext"`：恢复密码学管线（密钥派生 → 加密 → 输出）
- `mode="general"`：流程分析、字段语义、模块边界

后续直接对话即可，plugin 会管 trace_search / trace_context 调度。

---

## 9. 常见坑

| 现象 | 根因 | 解法 |
|---|---|---|
| trace 文件 0 字节 | thread_id 传错 / init+run 不在目标线程 | 改用 `Interceptor.attach.onEnter` + `thread_id=0` |
| `frida: Failed to attach: unexpected early end-of-stream` | frida-server 异常 / 上轮 session 残留 | `launchctl unload/load /var/jb/Library/LaunchDaemons/re.frida.server.plist` |
| `frida: Spawning... unexpectedly timed out` | dylib 被 ldid resign 破坏了主二进制签名 | 重装 App，**只签 GumTrace.dylib 不要签主二进制** |
| trace 写入失败 / `stat 失败` LOGE | 路径不在沙盒 Documents | 通过 `NSString.stringByExpandingTildeInPath` 取沙盒路径 |
| WeChat 进程被秒杀 | hook 高频符号导致 GumTrace 启动期 reentrant 死锁 | 换 hook 点，避免 init+run 路径会调用的符号（如 `objc_msgSend`） |
| 反汇编搜函数 BN MCP 超时 | 443MB 大二进制 | 改用 binassist MCP，超时阈值更宽 |

---

## 10. 附录：AppDelegate 启动生命周期（按调用顺序）

```text
0x1041b8bec  application:willFinishLaunchingWithOptions:
0x1041b8c48  application:didFinishLaunchingWithOptions:    ← spawn 模式黄金 hook 点
0x1041b4950  continueMainLaunching:
0x1041b0c88  initRootServiceObject
0x1041b0d34  initServiceLaunchTask
0x1041b0d78  initHighPhaseLaunchTask
0x1041b0f94  initNormalPhaseLaunchTask
0x1041b1e94  initLazyPhaseLaunchTask
0x1041b88e8  mainUISettingOnce
0x1041b8ad8  didFinishLoad                                  ← 启动完成
0x1041bdccc  applicationDidBecomeActive:                    ← attach 模式黄金 hook 点
0x1041bd610  applicationWillEnterForeground:
0x1041bc8e4  applicationWillResignActive:
0x1041bca3c  applicationDidEnterBackground:
0x1041be0a4  applicationWillTerminate:
```

地址基于本测试设备 ASLR slide 之前的 BN 静态地址，运行时需加 `Process.findModuleByName('WeChat').base - <BN image base>` 偏移。脚本中直接用 `ObjC.classes.MicroMessengerAppDelegate['- xxx'].implementation` 取 IMP 即可避开 ASLR。

---

## 11. 上游

- GumTrace 仓库：<https://github.com/lidongyooo/GumTrace>
- 作者范例：仓库根目录的 `example.js` / `example_ios.js`
- AlgoKiller plugin 主仓库：本仓库根目录
