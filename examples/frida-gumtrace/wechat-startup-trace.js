// wechat-startup-trace.js — hook 微信启动生命周期，trace App 启动期主线程执行
// BN 定位：MicroMessengerAppDelegate
//   - applicationDidBecomeActive: @ 0x1041bdccc  （每次切前台触发，main thread）
//   - didFinishLoad             : @ 0x1041b8ad8  （启动完成兜底）
// 范式：Interceptor.attach(目标).onEnter { init(threadId=0) + run() }
//   threadId=0 → gum_stalker_follow_me → 装当前线程（main thread）TLS

const NSLogPtr = Module.findGlobalExportByName('NSLog')
let nslogCount = 0
Interceptor.attach(NSLogPtr, { onEnter(args) {
    try {
        const fmt = new ObjC.Object(args[0]).toString()
        if (!/ERROR|GumTrace|gumtrace|module|trace_file|每20秒|未|失败/i.test(fmt)) return
        let i = 1
        const out = fmt.replace(/%[\.\-0-9]*[@sdiluxXp]/g, (m) => {
            try {
                const a = args[i++]
                if (m.endsWith('@')) { try { return new ObjC.Object(a).toString() } catch {} ; try { return a.readUtf8String() } catch {} ; return '<obj>' }
                if (m.endsWith('s')) return a.readUtf8String() || '?'
                if (/[diluxX]/.test(m)) return a.toInt32().toString()
                if (m.endsWith('p')) return '0x' + a.toString(16)
                return '?'
            } catch { return '?' }
        })
        nslogCount++
        if (nslogCount <= 50) console.log('[NSLog]', out.trim())
    } catch {}
}})

// 找 GumTrace dylib
const mod = Process.enumerateModules().find(m => /GumTrace/i.test(m.path))
if (!mod) throw new Error('libGumTrace.dylib not injected into WeChat')
console.log('[diag] GumTrace dylib:', mod.path, '@', mod.base)

const initFn  = new NativeFunction(mod.findExportByName('init'),  'void', ['pointer', 'pointer', 'int', 'pointer'])
const runFn   = new NativeFunction(mod.findExportByName('run'),   'void', [])
const unrunFn = new NativeFunction(mod.findExportByName('unrun'), 'void', [])

const home = ObjC.classes.NSString.stringWithString_('~').stringByExpandingTildeInPath().toString()
const tracePath = home + '/Documents/wechat-startup.trace.log'
console.log('[diag] trace path:', tracePath)

// 解析 WeChat 模块 base 来还原 BN 标定的绝对地址
const wechat = Process.findModuleByName('WeChat')
if (!wechat) throw new Error('WeChat module not found in process')
console.log('[diag] WeChat module @', wechat.base, 'size=', wechat.size)

// BN 中 _start 在 0x10982e018，运行时 base 一般是 0x10[base+offset]
// BN 的地址是 image_base + file_offset，跟运行时 module.base 对应 image_base
// 但 ASLR 会变。我们用 BN 地址 - BN 起点(image base) + 当前 module.base
// 实际：BN 显示的是 image-based VA，运行时是 image_base + ASLR_slide
// 简单：从 BN 取得 image base（看 entry point _start = 0x10982e018），其偏移到 BN image base
// 但我们没立刻拿到 BN image base。改用：直接通过 ObjC class 方法实现地址 hook，避开 ASLR 偏移计算
const cls = ObjC.classes.MicroMessengerAppDelegate
if (!cls) throw new Error('MicroMessengerAppDelegate class not found')

const m1 = cls['- applicationDidBecomeActive:']
const m2 = cls['- didFinishLoad']
console.log('[diag] hook target 1:', m1, 'impl @', m1.implementation)
console.log('[diag] hook target 2:', m2, 'impl @', m2.implementation)

let started = false

function startTraceInWeChatThread(tag) {
    if (started) return
    started = true
    console.log('[trigger:' + tag + '] currTid =', Process.getCurrentThreadId(), '— entering WeChat main thread')
    try {
        // trace 整个 WeChat 主二进制；要更细颗粒度可以传 'WeChat,mmcronet' 等
        const mn  = Memory.allocUtf8String('WeChat')
        const op  = Memory.allocUtf8String(tracePath)
        const opt = Memory.alloc(8); opt.writeU64(1)  // DEBUG = 频繁 flush，便于早期观测

        console.log('[trigger:' + tag + '] init(modules=WeChat, threadId=0, opt=DEBUG)')
        initFn(mn, op, 0, opt)
        console.log('[trigger:' + tag + '] init OK, calling run() — follow_me on this thread')
        runFn()
        console.log('[trigger:' + tag + '] run OK — stalker ACTIVE on tid=' + Process.getCurrentThreadId())
    } catch (e) {
        console.log('[trigger:' + tag + '] FAILED:', e.message, e.stack)
        started = false  // 允许下次重试
    }
}

Interceptor.attach(m1.implementation, {
    onEnter() { startTraceInWeChatThread('applicationDidBecomeActive') }
})

Interceptor.attach(m2.implementation, {
    onEnter() { startTraceInWeChatThread('didFinishLoad') }
})

console.log('[diag] hooks installed.')
console.log('[diag] auto-triggering applicationDidBecomeActive on mainQueue in 1.5s')
console.log('[diag] trace duration: 25s after trigger')

// 关键：attach 模式下 applicationDidBecomeActive 早过了
// 解法：自己通过 ObjC.schedule(mainQueue) 模拟调用 → onEnter 命中且当前线程=main thread
// 这等价于"切后台再回前台"但不依赖物理操作
setTimeout(() => {
    ObjC.schedule(ObjC.mainQueue, () => {
        try {
            const app = ObjC.classes.UIApplication.sharedApplication()
            const del = app.delegate()
            console.log('[autotrigger] delegate class =', del.$className, 'on tid =', Process.getCurrentThreadId())
            del.applicationDidBecomeActive_(app)
            console.log('[autotrigger] applicationDidBecomeActive: invoked')
        } catch (e) {
            console.log('[autotrigger] fail:', e.message)
        }
    })
}, 1500)

// 25s 后停 — 必须在 main thread 上 unrun (trace_file 在 main thread TLS)
setTimeout(() => {
    if (!started) {
        console.log('[stop] NO TRIGGER FIRED — hook 未命中，可能需要 kill+relaunch WeChat')
        return
    }
    console.log('[stop] scheduling unrun on main queue')
    ObjC.schedule(ObjC.mainQueue, () => {
        try {
            unrunFn()
            console.log('[stop] unrun done. NSLog hits total:', nslogCount)
        } catch (e) {
            console.log('[stop] unrun fail:', e.message)
        }
    })
}, 25000)
