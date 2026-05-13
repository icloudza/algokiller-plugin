// targetapp-anti-jb-spawn.js
// ─────────────────────────────────────────────────────────────────────────
// 带"反越狱 bypass + 字符串混淆"的 spawn 模式 GumTrace 范式（Dopamine 兼容）
//
// 适用场景：
//   目标 App 主动检测越狱（扫 /var/jb / TweakInject / Cydia 等），在 main() 早期
//   自杀；Dopamine 自带的"隐藏越狱"开关又会让 GumTrace 也加载不进去。需要 JS
//   脚本里自己做反越狱 hook，让目标 App 看不到越狱，但 frida 还能 Module.load
//   GumTrace.dylib。
//
// 脚本结构：
//   1. 最早 IIFE：JS 侧反越狱 hook
//      - 文件检测 syscall：stat / lstat / access / open / fopen / opendir /
//        readlink / statfs（jb 路径返回 -1 或 NULL）
//      - dlopen 特殊处理：放过 GumTrace.dylib，其他 jb 路径返回 NULL
//      - getenv 隐藏 DYLD_INSERT_LIBRARIES
//      - ptrace 改 NOOP（PT_DENY_ATTACH 无效化）
//      - sysctl 清 kinfo_proc.kp_proc.p_flag 的 P_TRACED 位
//      - _dyld_get_image_name 把 jb 路径替换成系统 dylib
//   2. arc4random_buf hook + 15 层调用栈（找算法入口候选）
//   3. setTimeout 500ms 装 ObjC hooks：setValue:forHTTPHeaderField: +
//      NSURLSession dataTaskWithRequest:
//   4. 业务 URL 首次命中 dataTask → Module.load GumTrace → stalker 启动
//   5. 文件大小达 TARGET_TRACE_GB 自动 stop（双路 unrun 解决跨线程 unfollow）
//
// 越狱关键字（/var/jb / TweakInject / GumTrace 等）都通过 hex 字面量在运行时
// 解码，**不在 V8 constant pool 留字面量**。有些 App 会扫自己的 heap 找越狱
// 特征字符串，碰到立即 abort——这套做法能避开。
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 用之前必须改的占位符：
//   TARGET_MODULE        —— 主可执行模块名（Process.findModuleByName 用）
//   TARGET_URL_RE        —— 业务 URL 正则（用来过滤掉 CDN / 图片等噪音）
//   TARGET_HEADERS_RE    —— 要关注的签名 header 正则
//   （可选）想抓 Curve25519 / 服务器公钥等，自己加 scan + hook
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 跑法：
//   frida -U -f <bundle_id> -l targetapp-anti-jb-spawn.js 2>&1 | tee spawn.log

var TAG = '[TR]';

// ─────────────────────────────────────────────────────────────────────────
// 占位符 —— 改成你目标 App 的实际值
// ─────────────────────────────────────────────────────────────────────────

// 主可执行模块名
var TARGET_MODULE = 'TargetApp';

// 业务 URL 正则（CDN / 静态资源 URL 会被过滤掉）
var TARGET_URL_RE = /(api|gateway|auth)\.example\.com/i;

// 要关注的签名 header 正则
var TARGET_HEADERS_RE = /^x-(sign|nonce|trace|client)/i;

// stalker 文件大小阈值
var TARGET_TRACE_GB = 1.5;          // 软目标（达到自动 stop）
var MAX_TRACE_GB    = 5;             // 硬上限（强制 stop）

// trace 输出文件名（落到 App sandbox Documents）
var TRACE_NAME = 'targetapp-spawn.trace.log';

// ─────────────────────────────────────────────────────────────────────────
// hex 字符串解码 —— 把越狱关键字从 V8 constant pool 里剥离
// ─────────────────────────────────────────────────────────────────────────

function dec(hex) {
    var s = '';
    for (var i = 0; i < hex.length; i += 2)
        s += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return s;
}

// '/var/jb'
var P_JB        = dec('2f7661722f6a62');
// '/Library/MobileSubstrate'
var P_MS        = dec('2f4c6962726172792f4d6f62696c655375627374726174');
// '/Library/LaunchDaemons/jb.'
var P_JB_DAEMON = dec('2f4c6962726172792f4c61756e636844616d6f6e732f6a622e');
// '/Applications/Cydia.app'
var P_CYDIA     = dec('2f4170706c69636174696f6e732f4379646961');
// '/Applications/Sileo.app'
var P_SILEO     = dec('2f4170706c69636174696f6e732f53696c656f');
// '/usr/sbin/sshd'
var P_SSHD      = dec('2f7573722f7362696e2f73736864');
// 'TweakInject'
var TW          = dec('547765616b496e6a656374');
// 'GumTrace'
var GT          = dec('47756d5472616365');
// 'substrate'
var SUBSTRATE   = dec('737562737472617465');
// 'frida'
var FRIDA       = dec('6672696461');
// 'cydia'
var CYDIA_S     = dec('6379646961');

// '/var/jb/usr/lib/TweakInject/GumTrace.dylib' —— 运行时拼接
var DYLIB_PATH  = P_JB + dec('2f7573722f6c69622f') + TW + '/' + GT + dec('2e64796c6962');

function isJBPath(path) {
    if (!path) return false;
    if (path.indexOf(P_JB) === 0) return true;
    if (path.indexOf(P_MS) === 0) return true;
    if (path.indexOf(P_JB_DAEMON) === 0) return true;
    if (path.indexOf(P_CYDIA) === 0) return true;
    if (path.indexOf(P_SILEO) === 0) return true;
    if (path === P_SSHD) return true;
    var low = path.toLowerCase();
    if (low.indexOf(TW.toLowerCase()) >= 0) return true;
    if (low.indexOf(SUBSTRATE) >= 0) return true;
    if (low.indexOf(FRIDA) >= 0) return true;
    if (low.indexOf(CYDIA_S) >= 0) return true;
    return false;
}

// GumTrace 自己的路径要放过 —— frida 后面要 Module.load 它
function isGumTracePath(path) { return path && path.indexOf(GT) >= 0; }

// ─────────────────────────────────────────────────────────────────────────
// IIFE 1：反越狱 syscall hook（main() 之前生效）
// ─────────────────────────────────────────────────────────────────────────

(function antiJB() {
    var fileFns = [
        ['stat', false], ['lstat', false], ['access', false],
        ['readlink', false], ['statfs', false],
        ['open', false], ['fopen', true], ['opendir', true]
    ];
    fileFns.forEach(function (cfg) {
        try {
            var fn = cfg[0], retIsPtr = cfg[1];
            var addr = Module.findGlobalExportByName(fn);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (isJBPath(path)) this.block = true;
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    // fopen / opendir 返回 NULL，其他返回 -1（即 ENOENT 风格）
                    if (this.block) retval.replace(retIsPtr ? ptr(0) : ptr(-1));
                }
            });
        } catch (e) {}
    });

    // dlopen —— 关键：放过 GumTrace.dylib，让 frida 后面能加载
    try {
        var dlopenAddr = Module.findGlobalExportByName('dlopen');
        if (dlopenAddr) {
            Interceptor.attach(dlopenAddr, {
                onEnter: function (args) {
                    try {
                        if (args[0].isNull()) return;
                        var path = args[0].readUtf8String();
                        if (isJBPath(path) && !isGumTracePath(path)) this.block = true;
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.block) retval.replace(ptr(0));
                }
            });
        }
    } catch (e) {}

    // getenv —— 隐藏 DYLD 注入痕迹
    try {
        var envAddr = Module.findGlobalExportByName('getenv');
        var hideEnv = ['DYLD_INSERT_LIBRARIES', 'DYLD_FORCE_FLAT_NAMESPACE',
                       '_MSSafeMode', '_SafeMode'];
        if (envAddr) {
            Interceptor.attach(envAddr, {
                onEnter: function (args) {
                    try {
                        var name = args[0].readUtf8String();
                        if (hideEnv.indexOf(name) >= 0) this.hide = true;
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.hide) retval.replace(ptr(0));
                }
            });
        }
    } catch (e) {}

    // ptrace PT_DENY_ATTACH 反调试 bypass
    try {
        var pt = Module.findGlobalExportByName('ptrace');
        if (pt) Interceptor.replace(pt,
            new NativeCallback(function () { return 0; },
                'int', ['int', 'int', 'pointer', 'int']));
    } catch (e) {}

    // sysctl —— 清 kinfo_proc.kp_proc.p_flag 的 P_TRACED 位
    try {
        var sysctlAddr = Module.findGlobalExportByName('sysctl');
        if (sysctlAddr) {
            Interceptor.attach(sysctlAddr, {
                onEnter: function (args) {
                    try {
                        if (args[0].isNull()) return;
                        // CTL_KERN(1) → KERN_PROC(14) → KERN_PROC_PID(1) 的反调试探针
                        if (args[0].readU32() === 1 &&
                            args[0].add(4).readU32() === 14 &&
                            args[0].add(8).readU32() === 1) {
                            this.ip = args[2];
                        }
                    } catch (e) {}
                },
                onLeave: function () {
                    try {
                        if (this.ip && !this.ip.isNull()) {
                            var f = this.ip.add(32);            // kp_proc.p_flag 偏移
                            var v = f.readU32();
                            if (v & 0x800) f.writeU32(v & ~0x800);  // 清 P_TRACED
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // _dyld_get_image_name —— 把 jb 路径替换成系统 dylib，骗过 dyld 扫描
    try {
        var dyldNameAddr = Module.findGlobalExportByName('_dyld_get_image_name');
        var fakePath = null;
        if (dyldNameAddr) {
            Interceptor.attach(dyldNameAddr, {
                onLeave: function (retval) {
                    try {
                        if (retval.isNull()) return;
                        var path = retval.readUtf8String();
                        if (path && isJBPath(path)) {
                            if (!fakePath) fakePath = Memory.allocUtf8String('/usr/lib/libSystem.B.dylib');
                            retval.replace(fakePath);
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    console.log(TAG + ' anti-jb OK');
})();

// ─────────────────────────────────────────────────────────────────────────
// 统计 + 状态
// ─────────────────────────────────────────────────────────────────────────

function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++)
        s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    return s;
}

var stats = { arc4: 0, header: 0, dataTask: 0 };
var state = 'idle';                       // idle → tracing → done
var tracePath = null;
var capturedKeys = [];

// ─────────────────────────────────────────────────────────────────────────
// IIFE 2：arc4random_buf hook + 深调用栈（定位算法入口）
// ─────────────────────────────────────────────────────────────────────────

(function hookArc4() {
    try {
        var addr = null;
        var mod = Process.findModuleByName('libSystem.B.dylib');
        if (mod) addr = mod.findExportByName('arc4random_buf');
        if (!addr) {
            mod = Process.findModuleByName('libsystem_c.dylib');
            if (mod) addr = mod.findExportByName('arc4random_buf');
        }
        if (!addr) { console.log(TAG + ' arc4 not found'); return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.buf = args[0];
                this.len = args[1].toInt32();
            },
            onLeave: function () {
                if (this.len !== 32) return;     // 你的目标用 16/48/64 字节就改这里
                stats.arc4++;
                var hex = bytesToHex(new Uint8Array(this.buf.readByteArray(32)));

                // 15 层调用栈；第一个在目标模块内的 frame = 算法入口候选
                var disc = Process.findModuleByName(TARGET_MODULE);
                var btFrames = [];
                var firstModRva = null;
                try {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var j = 0; j < Math.min(bt.length, 15); j++) {
                        var a = bt[j];
                        var inMod = disc && a.compare(disc.base) >= 0 &&
                                    a.compare(disc.base.add(disc.size)) < 0;
                        var off = inMod ? '+0x' + a.sub(disc.base).toString(16) : '';
                        btFrames.push({ addr: a.toString(), rva: off, inMod: inMod });
                        if (inMod && !firstModRva) firstModRva = off;
                    }
                } catch (e) {}

                capturedKeys.push({ hex: hex, t: Date.now(), bt: btFrames });

                // 前 5 次完整打调用栈（找算法入口最关键）
                if (stats.arc4 <= 5) {
                    console.log(TAG + ' arc4 #' + stats.arc4 + ': ' + hex);
                    if (firstModRva) console.log(TAG + '   算法入口候选: ' + TARGET_MODULE + firstModRva);
                    for (var k = 0; k < btFrames.length; k++) {
                        var marker = btFrames[k].inMod ? '*' : ' ';
                        console.log(TAG + '  ' + marker + '[' + k + '] ' + btFrames[k].addr +
                                    (btFrames[k].rva ? '  (' + TARGET_MODULE + btFrames[k].rva + ')' : ''));
                    }
                }
            }
        });
        console.log(TAG + ' arc4 OK');
    } catch (e) {}
})();

console.log(TAG + ' === spawn trace ready (target=' + TARGET_TRACE_GB + 'GB, module=' + TARGET_MODULE + ') ===');

// ─────────────────────────────────────────────────────────────────────────
// 延迟 500ms 装 ObjC hook（等 ObjC runtime 稳定）
// ─────────────────────────────────────────────────────────────────────────

setTimeout(function () {
    if (!ObjC.available) { setTimeout(arguments.callee, 500); return; }

    // setValue:forHTTPHeaderField: —— 捕获签名 header
    try {
        var sel = ObjC.classes.NSMutableURLRequest['- setValue:forHTTPHeaderField:'];
        if (sel) {
            Interceptor.attach(sel.implementation, {
                onEnter: function (args) {
                    try {
                        var field = ObjC.Object(args[3]).toString();
                        if (!TARGET_HEADERS_RE.test(field)) return;
                        var value = ObjC.Object(args[2]).toString();
                        stats.header++;
                        if (stats.header <= 6) {
                            console.log(TAG + ' header #' + stats.header + ' ' + field + '=' +
                                        (value.length > 96 ? value.slice(0, 96) + '...' : value));
                        }
                    } catch (e) {}
                }
            });
            console.log(TAG + ' setValue hook OK');
        }
    } catch (e) {}

    // dataTaskWithRequest: —— stalker 触发器
    try {
        var m = new ApiResolver('objc').enumerateMatches('-[NSURLSession dataTaskWithRequest:]');
        if (m.length) {
            Interceptor.attach(m[0].address, {
                onEnter: function (args) {
                    try {
                        var url = ObjC.Object(args[2]).URL().absoluteString().toString();
                        if (!TARGET_URL_RE.test(url)) return;
                        stats.dataTask++;
                        if (state === 'idle') {
                            console.log(TAG + ' http #' + stats.dataTask + ': ' + url);
                            startStalker();
                        } else if (state === 'tracing' && stats.dataTask % 10 === 0) {
                            console.log(TAG + ' progress dataTask=' + stats.dataTask + ' header=' + stats.header);
                        }
                    } catch (e) {}
                }
            });
            console.log(TAG + ' dataTask hook OK');
        }
    } catch (e) {}
}, 500);

// ─────────────────────────────────────────────────────────────────────────
// stalker 启动函数（NativeFunction + Module.load 都在函数体内 JIT 构造，
// 不在 V8 启动期 heap 里留 stalker / NativeFunction 等可疑字符串字面量）
// ─────────────────────────────────────────────────────────────────────────

function startStalker() {
    if (state !== 'idle') return;
    state = 'tracing';
    try {
        var gtMod = Process.enumerateModules().find(function (m) {
            return m.path.indexOf(GT) >= 0;
        });
        if (!gtMod) gtMod = Module.load(DYLIB_PATH);
        var initFn  = new NativeFunction(gtMod.findExportByName('init'),
                          'void', ['pointer','pointer','int','pointer']);
        var runFn   = new NativeFunction(gtMod.findExportByName('run'),   'void', []);
        var unrunFn = new NativeFunction(gtMod.findExportByName('unrun'), 'void', []);

        var home = ObjC.classes.NSString.stringWithString_('~')
                       .stringByExpandingTildeInPath().toString();
        tracePath = home + '/Documents/' + TRACE_NAME;

        var mn  = Memory.allocUtf8String(TARGET_MODULE);
        var op  = Memory.allocUtf8String(tracePath);
        var opt = Memory.alloc(8); opt.writeU64(1);   // 1 = Debug（频繁 flush）
        initFn(mn, op, 0, opt);                       // threadId=0 → follow_me 装当前线程
        runFn();
        console.log(TAG + ' STALKER ACTIVE @ tid=' + Process.getCurrentThreadId() +
                    ' path=' + tracePath);

        var MAX  = TARGET_TRACE_GB * 1024 * 1024 * 1024;
        var HARD = MAX_TRACE_GB * 1024 * 1024 * 1024;
        var NSFM = ObjC.classes.NSFileManager.defaultManager();
        var nsPath = ObjC.classes.NSString.stringWithString_(tracePath);
        var sizeKey = ObjC.classes.NSString.stringWithString_('NSFileSize');
        var lastMB = 0;
        var watcher = setInterval(function () {
            try {
                var attrs = NSFM.attributesOfItemAtPath_error_(nsPath, NULL);
                if (!attrs || attrs.isNull()) return;
                var sz = attrs.objectForKey_(sizeKey);
                if (!sz || sz.isNull()) return;
                var bytes = sz.unsignedLongLongValue();
                var mb = Math.floor(bytes / (1024 * 1024));
                if (mb >= lastMB + 100) {
                    console.log(TAG + ' size ' + (bytes / 1073741824).toFixed(2) +
                                ' GB | dataTask=' + stats.dataTask +
                                ' header=' + stats.header);
                    lastMB = mb;
                }
                if (bytes >= MAX || bytes >= HARD) {
                    clearInterval(watcher);
                    state = 'done';
                    // 双路 unrun：直接调 + mainQueue（解决跨线程 unfollow_me）
                    try { unrunFn(); } catch (e) {}
                    ObjC.schedule(ObjC.mainQueue, function () {
                        try { unrunFn(); } catch (e) {}
                        console.log('\n' + TAG + ' STOPPED');
                        console.log(TAG + ' stats: ' + JSON.stringify(stats));
                        console.log(TAG + ' trace: ' + tracePath);
                        console.log(TAG + ' 拉回（gzip 流式压缩传输）:');
                        console.log(TAG + "   scp -P 2222 -C root@localhost:'" + tracePath + "' ./");
                    });
                }
            } catch (e) {}
        }, 1000);
    } catch (e) {
        console.log(TAG + ' startStalker err: ' + e);
        state = 'idle';
    }
}

// ─────────────────────────────────────────────────────────────────────────
// RPC：在 frida REPL 里 rpc.exports.xxx() 实时查捕获数据
// ─────────────────────────────────────────────────────────────────────────

rpc.exports = {
    stats: function () { return stats; },
    keys:  function () { return capturedKeys; },        // 所有 arc4(32) + 调用栈
    state: function () { return { state: state, tracePath: tracePath }; },
};
