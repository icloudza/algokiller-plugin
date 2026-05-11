// targetapp-startup-trace.js — hook the target app's startup lifecycle and
// capture the main thread instruction trace during the active-foreground
// phase.
//
// This is the production-grade version of targetapp-correct.js — it adds:
//   - Two hook points (didBecomeActive + didFinishLoad fallback) so the
//     attach-mode timing window is wider.
//   - An autotrigger that programmatically invokes applicationDidBecomeActive
//     on the main queue (since attach-mode usually arrives after the real one
//     already fired).
//   - 25-second trace window with main-queue-scheduled unrun.
//
// The "correct usage" formula is the same:
//   threadId=0 (follow_me) + init+run inside an onEnter callback that
//   genuinely runs on the target app's main thread.
//
// ============ Configuration: edit these for your target app ============

// 1) The module name of the target app's main binary, as seen in
//    Process.enumerateModules() (e.g. typically the app's bundle executable
//    name without the .app suffix). Pass to GumTrace init's `modules` param.
//    You can trace multiple modules at once with comma separation:
//        "TargetApp,LibFoo"
const TARGET_APP_NAME = 'TargetApp'

// 2) The AppDelegate class name. On UIKit apps this is the class that
//    implements UIApplicationDelegate. Find it via Binary Ninja
//    (look for symbol XXXAppDelegate) or via Frida runtime introspection:
//        ObjC.classes.UIApplication.sharedApplication().delegate().$className
const TARGET_APP_DELEGATE_CLASS = 'TargetAppDelegate'

// 3) Trace file output name (sandbox Documents).
const TRACE_FILE_NAME = 'targetapp-startup.trace.log'

// ============ End configuration ============

// ----- 0. NSLog forward (catch GumTrace's own LOGE/LOGI) -----

const NSLogPtr = Module.findGlobalExportByName('NSLog')
let nslogCount = 0
Interceptor.attach(NSLogPtr, { onEnter(args) {
    try {
        const fmt = new ObjC.Object(args[0]).toString()
        if (!/ERROR|GumTrace|gumtrace|module|trace_file|failed/i.test(fmt)) return
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

// ----- 1. Resolve injected GumTrace dylib -----

const mod = Process.enumerateModules().find(m => /GumTrace/i.test(m.path))
if (!mod) throw new Error('libGumTrace.dylib not injected into target process')
console.log('[diag] GumTrace dylib:', mod.path, '@', mod.base)

const initFn  = new NativeFunction(mod.findExportByName('init'),  'void', ['pointer', 'pointer', 'int', 'pointer'])
const runFn   = new NativeFunction(mod.findExportByName('run'),   'void', [])
const unrunFn = new NativeFunction(mod.findExportByName('unrun'), 'void', [])

const home = ObjC.classes.NSString.stringWithString_('~').stringByExpandingTildeInPath().toString()
const tracePath = home + '/Documents/' + TRACE_FILE_NAME
console.log('[diag] trace path:', tracePath)

// ----- 2. Locate the target app's main module + AppDelegate -----

const targetMod = Process.findModuleByName(TARGET_APP_NAME)
if (!targetMod) throw new Error(TARGET_APP_NAME + ' module not found in process')
console.log('[diag]', TARGET_APP_NAME, 'module @', targetMod.base, 'size=', targetMod.size)

// Using ObjC.classes[...].$methodName.implementation gives us the IMP
// directly — no need to fight ASLR slide arithmetic when picking hook
// points. If your target's AppDelegate class name differs, edit
// TARGET_APP_DELEGATE_CLASS above.
const cls = ObjC.classes[TARGET_APP_DELEGATE_CLASS]
if (!cls) {
    throw new Error('AppDelegate class "' + TARGET_APP_DELEGATE_CLASS + '" not found. ' +
                    'Run `ObjC.classes.UIApplication.sharedApplication().delegate().$className` ' +
                    'on the live process to discover the actual class name.')
}

const m1 = cls['- applicationDidBecomeActive:']
const m2 = cls['- didFinishLoad']  // Some apps expose a custom "load done" hook; ok if undefined
console.log('[diag] hook target 1:', m1, 'impl @', m1.implementation)
if (m2) console.log('[diag] hook target 2:', m2, 'impl @', m2.implementation)

// ----- 3. Trigger logic -----

let started = false

function startTraceInTargetThread(tag) {
    if (started) return
    started = true
    console.log('[trigger:' + tag + '] currTid =', Process.getCurrentThreadId(),
                '— entering target app main thread')
    try {
        const mn  = Memory.allocUtf8String(TARGET_APP_NAME)
        const op  = Memory.allocUtf8String(tracePath)
        const opt = Memory.alloc(8); opt.writeU64(1)  // 1 = DEBUG (frequent flush)

        console.log('[trigger:' + tag + '] init(modules=' + TARGET_APP_NAME + ', threadId=0, opt=DEBUG)')
        initFn(mn, op, 0, opt)
        console.log('[trigger:' + tag + '] init OK, calling run() — follow_me on this thread')
        runFn()
        console.log('[trigger:' + tag + '] run OK — stalker ACTIVE on tid=' + Process.getCurrentThreadId())
    } catch (e) {
        console.log('[trigger:' + tag + '] FAILED:', e.message, e.stack)
        started = false  // allow retry on next hook fire
    }
}

Interceptor.attach(m1.implementation, {
    onEnter() { startTraceInTargetThread('applicationDidBecomeActive') }
})

if (m2) {
    Interceptor.attach(m2.implementation, {
        onEnter() { startTraceInTargetThread('didFinishLoad') }
    })
}

console.log('[diag] hooks installed.')
console.log('[diag] auto-triggering applicationDidBecomeActive on mainQueue in 1.5s')
console.log('[diag] trace duration: 25s after trigger')

// In attach mode applicationDidBecomeActive: usually already fired before we
// got here. ObjC.schedule(mainQueue, fn) lets us invoke it programmatically
// from the main thread, so our onEnter hook fires with currTid = main tid.
setTimeout(() => {
    ObjC.schedule(ObjC.mainQueue, () => {
        try {
            const app = ObjC.classes.UIApplication.sharedApplication()
            const del = app.delegate()
            console.log('[autotrigger] delegate class =', del.$className,
                        'on tid =', Process.getCurrentThreadId())
            del.applicationDidBecomeActive_(app)
            console.log('[autotrigger] applicationDidBecomeActive: invoked')
        } catch (e) {
            console.log('[autotrigger] fail:', e.message)
        }
    })
}, 1500)

// Stop after 25s — unrun must run on the same thread where run() was called.
setTimeout(() => {
    if (!started) {
        console.log('[stop] NO TRIGGER FIRED — hook not hit. Try kill+relaunch the target app.')
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
