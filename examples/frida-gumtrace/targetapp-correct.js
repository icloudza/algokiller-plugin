// targetapp-correct.js — minimal "correct usage" GumTrace example
//
// This is the bare-minimum verification version: prove that GumTrace's
// follow_me path attaches the stalker correctly when triggered from the
// target app's business thread (typically main thread for UIKit apps).
//
// The full annotated startup-tracing script is targetapp-startup-trace.js.
//
// Correct-usage formula:
//   1) threadId = 0  →  gum_stalker_follow_me path (install stalker on the
//      current calling thread's TLS)
//   2) Interceptor.attach an ObjC method that genuinely runs on the target
//      app's business thread (NOT a frida JS callback)
//   3) Call init + run inside that onEnter callback
//
// Replace TARGET_APP_NAME / TARGET_HOOK_METHOD below for your specific
// reverse-engineering target. The example uses -[UIView layoutSubviews]
// because every UIKit app fires it constantly on the main thread.

// ----- 0. NSLog forward (catches GumTrace's own LOGE/LOGI to console) -----

const NSLogPtr = Module.findGlobalExportByName('NSLog')
let nslogCount = 0
Interceptor.attach(NSLogPtr, { onEnter(args) {
    try {
        const fmt = new ObjC.Object(args[0]).toString()
        if (!/ERROR|GumTrace|gumtrace|module|trace_file|stat|failed/i.test(fmt)) return
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

// ----- 1. Resolve injected GumTrace dylib -----

const mod = Process.enumerateModules().find(m => /GumTrace/i.test(m.path))
if (!mod) { throw new Error('libGumTrace.dylib not in process') }
console.log('[diag] GumTrace dylib:', mod.path, '@', mod.base)

const initFn  = new NativeFunction(mod.findExportByName('init'),  'void', ['pointer', 'pointer', 'int', 'pointer'])
const runFn   = new NativeFunction(mod.findExportByName('run'),   'void', [])
const unrunFn = new NativeFunction(mod.findExportByName('unrun'), 'void', [])

// ----- 2. Trace output path (sandbox Documents) -----

const home = ObjC.classes.NSString.stringWithString_('~').stringByExpandingTildeInPath().toString()
const tracePath = home + '/Documents/targetapp-correct.trace.log'
console.log('[diag] trace path:', tracePath)

// ----- 3. Configuration: edit these for your target -----
//
// TARGET_APP_NAME = the module name from `Process.enumerateModules()` that you
//                   want to trace. Pass to GumTrace init's `modules` param. You
//                   can pass multiple modules comma-separated:
//                       "TargetApp,LibFoo"
//
// TARGET_HOOK_METHOD = an ObjC method that:
//   - genuinely runs on the target app's business thread (usually main thread)
//   - fires reliably during the period you want to trace
//   - is NOT called by GumTrace's own init/run path (avoid reentrancy)
//   -[UIView layoutSubviews] is a safe default for any UIKit app.

const TARGET_APP_NAME = 'TargetApp'
const TARGET_HOOK_METHOD = ObjC.classes.UIView['- layoutSubviews']

console.log('[diag] hooking', TARGET_HOOK_METHOD,
            '(replace TARGET_HOOK_METHOD for your reverse-engineering target)')

// ----- 4. Trigger logic -----

let started = false
let stopScheduled = false

function startInTargetThread() {
    if (started) return
    started = true
    console.log('[trigger] entering target-app thread context, currTid =',
                Process.getCurrentThreadId())
    try {
        const mn  = Memory.allocUtf8String(TARGET_APP_NAME)
        const op  = Memory.allocUtf8String(tracePath)
        const opt = Memory.alloc(8); opt.writeU64(1)  // 1 = DEBUG (frequent flush)

        console.log('[trigger] init(modules=' + TARGET_APP_NAME + ', threadId=0, opt=DEBUG)...')
        initFn(mn, op, 0, opt)
        console.log('[trigger] init returned')

        console.log('[trigger] calling run() — follow_me on current thread')
        runFn()
        console.log('[trigger] run returned, stalker should now be ACTIVE on this thread')
    } catch (e) {
        console.log('[trigger] FAILED:', e.message, e.stack)
    }
}

Interceptor.attach(TARGET_HOOK_METHOD.implementation, {
    onEnter() {
        if (!started) startInTargetThread()
    }
})

// ----- 5. Stop after 15s — unrun on the same thread where run was called -----

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

console.log('[diag] script loaded, waiting for target-app thread entry...')
