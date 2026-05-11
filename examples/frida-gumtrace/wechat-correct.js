// 按 example_ios.js 作者本意的正确用法：
// 1) threadId = 0 走 gum_stalker_follow_me，把 stalker 装当前线程
// 2) Interceptor.attach 一个 WeChat 高频符号，让 onEnter 在 WeChat 业务线程上下文跑
// 3) 在 onEnter 里调 init + run —— 此刻当前线程才是要 trace 的线程

const NSLogPtr = Module.findGlobalExportByName('NSLog')
let nslogCount = 0
Interceptor.attach(NSLogPtr, { onEnter(args) {
    try {
        const fmt = new ObjC.Object(args[0]).toString()
        if (!/ERROR|GumTrace|gumtrace|module|trace_file|stat|未|每20秒|失败/i.test(fmt)) return
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
        console.log('[NSLog]', out.trim())
    } catch {}
}})

const mod = Process.enumerateModules().find(m => /GumTrace/i.test(m.path))
if (!mod) { throw new Error('libGumTrace.dylib not in process') }
console.log('[diag] GumTrace dylib:', mod.path, '@', mod.base)

const initFn  = new NativeFunction(mod.findExportByName('init'),  'void', ['pointer', 'pointer', 'int', 'pointer'])
const runFn   = new NativeFunction(mod.findExportByName('run'),   'void', [])
const unrunFn = new NativeFunction(mod.findExportByName('unrun'), 'void', [])

const home = ObjC.classes.NSString.stringWithString_('~').stringByExpandingTildeInPath().toString()
const tracePath = home + '/Documents/wechat-correct.trace.log'
console.log('[diag] trace path:', tracePath)

// 选 WeChat 模块的高频入口符号 — 用 objc_msgSend 是最稳的选择，每帧调用上万次
// 但 objc_msgSend 在系统 libobjc，不在 WeChat —— 我们要 hook 的是 WeChat 业务线程跑过的某个 ObjC method
// 更稳妥：hook `-[UIViewController viewDidAppear:]` 或 `-[UIView setNeedsLayout]`
// 这些都在 main thread 跑

let started = false
let stopScheduled = false

function startInWeChatThread() {
    if (started) return
    started = true
    console.log('[trigger] entering WeChat thread context, currTid =', Process.getCurrentThreadId())
    try {
        const mn  = Memory.allocUtf8String('WeChat')
        const op  = Memory.allocUtf8String(tracePath)
        const opt = Memory.alloc(8); opt.writeU64(1)  // DEBUG mode: flush 频繁，便于早期看到内容

        console.log('[trigger] calling init(modules=WeChat, threadId=0, opt=DEBUG)...')
        initFn(mn, op, 0, opt)
        console.log('[trigger] init returned')

        console.log('[trigger] calling run() — follow_me on current (WeChat) thread')
        runFn()
        console.log('[trigger] run returned, stalker should now be ACTIVE on this thread')
    } catch (e) {
        console.log('[trigger] FAILED:', e.message, e.stack)
    }
}

// 在主线程上挂一个高频 hook，捕获第一次入口
// 选 -[UIView layoutSubviews] —— main thread, 高频, WeChat 启动期一定触发
const targetCls = ObjC.classes.UIView
const targetMethod = targetCls['- layoutSubviews']
console.log('[diag] hooking', targetMethod)

Interceptor.attach(targetMethod.implementation, {
    onEnter() {
        if (!started) startInWeChatThread()
    }
})

// 15s 后停 trace —— 也必须在 WeChat 线程里 unrun（trace_file 是同一对象）
setTimeout(() => {
    if (started && !stopScheduled) {
        stopScheduled = true
        console.log('[stop] scheduling unrun via ObjC.schedule(mainQueue)')
        ObjC.schedule(ObjC.mainQueue, () => {
            try {
                unrunFn()
                console.log('[stop] unrun done. NSLog hits:', nslogCount)
            } catch (e) { console.log('[stop] unrun fail:', e.message) }
        })
    }
}, 15000)

console.log('[diag] script loaded, waiting for WeChat thread entry...')
