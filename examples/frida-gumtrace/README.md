# GumTrace × Frida 实战教程

把 [GumTrace](https://github.com/lidongyooo/GumTrace)(@lidongyooo 基于 frida-gum Stalker 写的 ARM64 trace 工具)部署到越狱 iOS 设备,对**任意目标 App** 做指令级动态追踪,产物可直接喂给 AlgoKiller plugin 做密文 / 流程分析。

本目录两个示例脚本:

| 脚本 | 用途 | hook 入口 |
|---|---|---|
| `targetapp-correct.js` | 最小可用版(单 hook 点 + 简单验证) | `-[UIView layoutSubviews]` 首次触发 |
| `targetapp-startup-trace.js` | 启动期完整 trace(推荐用作生产模板) | `-[<AppDelegate> applicationDidBecomeActive:]` + autotrigger |

> **重要**:这两个脚本顶部都有 `TARGET_APP_NAME` / `TARGET_APP_DELEGATE_CLASS` 占位符。**用之前必须改成你目标 App 的实际 module 名 + AppDelegate 类名**。脚本本身是算法/品牌无关的模板。

---

## 1. GumTrace 是什么

GumTrace 把 frida-gum 的 Stalker 单独编译成一个 dylib(iOS)/ so(Android),暴露 3 个 C 导出符号:

```c
void init(const char *modules, const char *trace_path, int thread_id, GUM_OPTIONS *opt);
void run();
void unrun();
```

- `modules`:逗号分隔的模块名(要 trace 的模块),如 `"TargetApp,LibFoo"`
- `trace_path`:trace 文件落盘路径(必须 App 沙盒内可写)
- `thread_id`:**关键参数** —— `0` 表示当前线程,非 0 表示指定 tid
- `opt`:8 字节 struct,第一字段 `mode`,可选 `0 (Stand) / 1 (Debug) / 2 (Stable)`

输出格式(每条指令一行):

```text
[module] 0xABS!0xREL mnemonic operands; observed_inputs -> observed_outputs
call func: <symbol>(<args>)
class : <ObjC class name>
ret: <value>
```

这正是 AlgoKiller `bind_trace` 直接消化的格式。

---

## 2. 部署到越狱 iOS(Dopamine / palera1n)

### 2.1 编译

GumTrace 仓库自带 `build_ios.sh`,依赖:
- macOS + Xcode CLT
- CMake 3.18+
- frida-gum iOS 头文件(仓库已带 `libs/FridaGum-IOS-17.8.3.h`)

```bash
cd /path/to/GumTrace
./build_ios.sh
# 产物:build_ios/libGumTrace.dylib
```

### 2.2 推到设备

GumTrace.dylib 通过 ellekit / TweakInject 注入到目标 App:

```bash
# 1) USB iproxy 起 SSH 通道(如已配置可跳过)
iproxy 2222 22 &

# 2) 推 dylib 到 TweakInject 目录(Dopamine 路径)
scp -P 2222 build_ios/libGumTrace.dylib root@localhost:/var/jb/usr/lib/TweakInject/GumTrace.dylib

# 3) ldid 签名(确保有 entitlements)
ssh -p 2222 root@localhost "ldid -S /var/jb/usr/lib/TweakInject/GumTrace.dylib"

# 4) 让 TweakInject 重新扫描(kill SpringBoard)
ssh -p 2222 root@localhost "killall -9 SpringBoard"
```

> ⚠️ **不要给目标 App 主二进制重签名 / 加 entitlements** —— 会破坏 Apple Distribution 证书链,导致 FBS 拒绝 launch。要让 dylib 在目标进程内运行,**只依赖 ellekit 注入链**即可。

### 2.3 验证注入

把 `<TARGET_APP_NAME>` 替换成你的目标 App 的 frida-ps 进程名:

```bash
frida -U -n <TARGET_APP_NAME> -e "console.log(Process.enumerateModules().filter(m => /GumTrace/i.test(m.path)))"
```

输出应能看到 `libGumTrace.dylib` 已在进程模块表里。

---

## 3. 正确的使用范式(⚠️ 关键陷阱)

读源码 `src/GumTrace.cpp:411-415`:

```cpp
void GumTrace::follow() {
    trace_thread_id > 0
        ? gum_stalker_follow(_stalker, trace_thread_id, _transformer, nullptr)   // ← iOS 不可靠
        : gum_stalker_follow_me(_stalker, _transformer, nullptr);                // ← 装当前线程 TLS
}
```

两条分支在 iOS 沙盒 + ellekit 注入环境下表现**完全不同**:

| 分支 | 触发条件 | iOS 行为 |
|---|---|---|
| `gum_stalker_follow(stalker, tid, ...)` | `thread_id > 0` | 异步抢占目标线程的 stalker state,受沙盒 / AMFI 干扰,**经常静默失败**(不报错、buffer 永空、trace 0 字节) |
| `gum_stalker_follow_me(stalker, ...)` | `thread_id == 0` | 把 stalker 装到**当前调用线程的 TLS**,立即生效 |

**所以必须用 `thread_id = 0` 走 `follow_me`**,再配合**让 init+run 跑在目标线程的上下文**。

### 错误姿势(会 trace 0 字节)

```javascript
// ❌ setImmediate 跑在 frida JS thread,不是目标 app 业务线程
// ❌ thread_id 传 mainTid,走 gum_stalker_follow(tid) 不工作
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

参考作者 `example_ios.js` 第 37 行:`let threadId = 0   // 0 = 当前线程`。这一行没读 = 大概率十几次试 trace 都是 0 字节的根因。

---

## 4. 怎么挑 hook 入口符号

要保证 init+run 在 **App 的业务主线程**上下文里执行。挑选原则:

1. **必须跑在 main thread**:ObjC UIKit 方法基本都是,避开 GCD 异步队列回调
2. **App 启动后能稳定触发**:attach 模式下 `didFinishLaunching` 已过期,挑 `applicationDidBecomeActive:` / `layoutSubviews` 这类
3. **避免 reentrancy**:不要 hook 在 init+run 自己路径上会调用的符号,否则爆栈

### 用 Binary Ninja 找 AppDelegate

反编译目标 App 主二进制,搜 `AppDelegate`(具体类名因 App 而异),典型生命周期方法:

```
+[<AppDelegate> GlobalInstance]
-[<AppDelegate> application:didFinishLaunchingWithOptions:]  ← spawn 模式入口
-[<AppDelegate> continueMainLaunching:]
-[<AppDelegate> didFinishLoad]                                ← 启动完成兜底
-[<AppDelegate> applicationDidBecomeActive:]                  ★ attach 模式推荐
-[<AppDelegate> applicationWillEnterForeground:]
```

★ `applicationDidBecomeActive:` 是 attach 模式下的最佳入口:每次切前台都触发,可反复测试。

### 如何运行时找 AppDelegate 类名

如果你不知道目标 App 的 AppDelegate 实际类名,可以先 frida 接进去问一句:

```bash
frida -U -n <TARGET_APP_NAME> -e "console.log(ObjC.classes.UIApplication.sharedApplication().delegate().\$className)"
```

输出就是 AppDelegate 的实际类名,填回脚本顶部 `TARGET_APP_DELEGATE_CLASS`。

---

## 5. 自动触发:绕开物理切前后台

Attach 模式下脚本上来时 `applicationDidBecomeActive` 早过去了。两个办法:

**A. 物理操作**:从屏幕左下角上滑出 App switcher,再点回目标 App(依赖手)
**B. 程序模拟(推荐)**:通过 `ObjC.schedule` 把当前 App 的 `applicationDidBecomeActive:` 直接调一次

```javascript
setTimeout(() => {
    ObjC.schedule(ObjC.mainQueue, () => {
        const app = ObjC.classes.UIApplication.sharedApplication()
        const del = app.delegate()
        del.applicationDidBecomeActive_(app)
    })
}, 1500)
```

`ObjC.schedule(mainQueue, fn)` 保证 fn 在 main thread 跑 —— onEnter 回调里 `Process.getCurrentThreadId()` 就是 main tid。

---

## 6. 完整运行流程

把 `<TARGET_APP_NAME>` 替换为你目标 App 的 frida-ps 进程名,`<URL_SCHEME>` 替换为目标 App 的 URL scheme(可省略 `uiopen` 一步改为手动点 icon):

```bash
# 1) iPad 重启目标 App,等其进入 active 状态
ssh -p 2222 root@localhost "killall -9 <TARGET_APP_NAME> 2>/dev/null; sleep 2; uiopen <URL_SCHEME>"
sleep 12   # GumTrace ellekit 注入 + App 初始化窗口

# 2) 拿 PID 后 attach
PID=$(frida-ps -U | awk '/<TARGET_APP_NAME>$/{print $1}' | head -1)
(sleep 35; echo) | frida -U -p "$PID" -l targetapp-startup-trace.js > /tmp/frida.log 2>&1

# 3) 拉 trace 文件回来
scp -P 2222 root@localhost:'/var/mobile/Containers/Data/Application/*/Documents/targetapp-startup.trace.log' \
            ~/captures/targetapp-startup.trace.log

# 4) 喂给 algokiller
# 在 Claude Desktop 里调 algokiller.bind_trace(path=..., mode='general')
```

> 用 `(sleep 35; echo) | frida ...` 给 stdin 喂超时管道 —— 避免 frida REPL 收 EOF 立即退出导致 setTimeout 没机会跑完。

---

## 7. Mode 选择(GUM_OPTIONS)

```javascript
const opt = Memory.alloc(8); opt.writeU64(<mode>)
```

| mode | 名称 | flush 频率 | 适用 |
|---|---|---|---|
| 0 | Stand | buffer 满(~64K)才 flush | 生产采样,trace 大 |
| 1 | Debug | 每 ~20 条指令 flush | 调试 / 早期观测,文件能立刻看到内容 |
| 2 | Stable | 启用安全范围检查(RW 段过滤) | 跑长时间避免崩溃,性能略低 |

调试期推荐 `1`,生产采样推荐 `0` 或 `2`。

---

## 8. trace 喂给 AlgoKiller plugin

trace 文件落到 macOS 后,在 Claude Desktop 里:

```
algokiller.bind_trace(path="/Users/<you>/captures/targetapp-startup.trace.log", mode="ciphertext")
```

- `mode="ciphertext"`:恢复密码学管线(密钥派生 → 加密 → 输出)
- `mode="general"`:流程分析、字段语义、模块边界

后续直接对话即可,plugin 会管 trace_search / trace_context 调度。

---

## 9. 常见坑

| 现象 | 根因 | 解法 |
|---|---|---|
| trace 文件 0 字节 | thread_id 传错 / init+run 不在目标线程 | 改用 `Interceptor.attach.onEnter` + `thread_id=0` |
| `frida: Failed to attach: unexpected early end-of-stream` | frida-server 异常 / 上轮 session 残留 | `launchctl unload/load /var/jb/Library/LaunchDaemons/re.frida.server.plist` |
| `frida: Spawning... unexpectedly timed out` | dylib 被 ldid resign 破坏了主二进制签名 | 重装 App,**只签 GumTrace.dylib 不要签主二进制** |
| trace 写入失败 / `stat 失败` LOGE | 路径不在沙盒 Documents | 通过 `NSString.stringByExpandingTildeInPath` 取沙盒路径 |
| 目标进程被秒杀 | hook 高频符号导致 GumTrace 启动期 reentrant 死锁 | 换 hook 点,避免 init+run 路径会调用的符号(如 `objc_msgSend`) |
| 反汇编搜函数 BN MCP 超时 | 数百 MB 大二进制 | 改用 binassist MCP,超时阈值更宽 |

---

## 10. 附录:典型 UIKit App AppDelegate 启动生命周期(按调用顺序)

不管什么 App,UIKit 生命周期回调顺序基本一致:

```text
application:willFinishLaunchingWithOptions:
application:didFinishLaunchingWithOptions:    ← spawn 模式黄金 hook 点
continueMainLaunching:                         (App 自定义,非必有)
... (App 自己的 init phases)
didFinishLoad                                  (App 自定义启动完成回调,可有可无)
applicationDidBecomeActive:                    ← attach 模式黄金 hook 点
applicationWillEnterForeground:
applicationWillResignActive:
applicationDidEnterBackground:
applicationWillTerminate:
```

具体地址因每个 App 的 ASLR slide 和编译产物布局而异 —— 脚本中直接用 `ObjC.classes[<AppDelegate>]['- xxx'].implementation` 取 IMP 即可避开 ASLR 偏移计算。

---

## 11. 上游

- GumTrace 仓库:<https://github.com/lidongyooo/GumTrace>
- 作者范例:仓库根目录的 `example.js` / `example_ios.js`
- AlgoKiller plugin 主仓库:本仓库根目录
