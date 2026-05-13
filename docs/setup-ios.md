# iOS 越狱设备 GumTrace 部署指南

从 USB 连接到 dylib 注入验证的完整流程。所有命令在 macOS 端执行（除非另外说明）。

## 0. 前置准备

- **iOS 设备**：用 **Dopamine** 越狱（rootless，`/var/jb` 前缀），或 **palera1n**
  （`/private/preboot/...`）。下面以 Dopamine 为主，palera1n 路径不同但流程一样。
- **macOS 端工具**：
  ```bash
  brew install libimobiledevice frida   # iproxy + frida-cli
  pip3 install frida-tools
  ```
- **设备端**：已装 OpenSSH，`frida-server` 已运行。
- **GumTrace** 已交叉编译出 `build_ios/libGumTrace.dylib`
  （见 [GumTrace 仓库](https://github.com/lidongyooo/GumTrace)）。

## 1. iproxy 打通 USB → SSH 通道

iOS 越狱设备 SSH 走 USB（不走 WiFi）。`iproxy` 把设备 22 端口转发到本地 2222：

```bash
iproxy 2222 22 &
```

启动一次即可，整个工作流期间别 kill。验证：

```bash
ssh -p 2222 root@localhost "uname -a"
# 首次连接要确认指纹，输 yes
# 默认密码 alpine（建议尽快改）
```

## 2. SSH known_hosts 冲突（换设备 / 重装 OpenSSH 必踩）

之前用 `localhost:2222` 连过别的设备，或者本设备重装过 OpenSSH，就会看到：

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
...
Offending ED25519 key in ~/.ssh/known_hosts:NN
Host key verification failed.
```

一行解决——只删 `[localhost]:2222` 这一条 entry，不动其他：

```bash
ssh-keygen -R "[localhost]:2222"
```

再次连接会问 `Are you sure you want to continue connecting (yes/no)?`，输 `yes`
新 key 自动入库。

**安全提醒**：换设备 / 刷机场景下这个 warning 是误报；如果你**没换过设备**
却突然冒这个错，先停下排查是不是中间人，再清 known_hosts。

## 3. 推 GumTrace 到设备

```bash
# 1) 推 dylib 到 Dopamine TweakInject 目录
scp -P 2222 build_ios/libGumTrace.dylib \
    root@localhost:/var/jb/usr/lib/TweakInject/GumTrace.dylib

# 2) ldid 签空 entitlements（dylib 不需要权限，签一下让 amfid 放行）
ssh -p 2222 root@localhost \
    "ldid -S /var/jb/usr/lib/TweakInject/GumTrace.dylib"

# 3) 让 TweakInject 重扫注入清单
ssh -p 2222 root@localhost "killall -9 SpringBoard"
```

SpringBoard 重启 = 锁屏黑 3-5 秒后回来。**禁忌**：永远不要给目标 App 主二进制
重签名或加 entitlements，会破坏 Apple Distribution 证书链，FBS 直接拒 launch。

## 4. 验证 dylib 是否注入到目标进程

冷启动一次目标 App（强杀再点开，保证 TweakInject 有干净注入窗口），用 frida
检查已加载模块：

```bash
frida -U -n <目标 App 进程名> -e \
  "console.log(JSON.stringify(Process.enumerateModules().filter(m => /GumTrace/i.test(m.path)), null, 2))"
```

进程名不知道先 `frida-ps -Uai | grep -i <关键词>` 查。

期待输出：

```json
[
  {
    "name": "GumTrace.dylib",
    "base": "0x10xxxxxxxx",
    "size": 7356416,
    "path": "/var/jb/usr/lib/TweakInject/GumTrace.dylib"
  }
]
```

**输出是 `[]` = TweakInject 没把 dylib 装进这个 App**。最常见原因：

- Choicy 把目标 App 的 tweak 注入全屏蔽了（越狱党防检测的常见配置）
- ellekit 处于 opt-in 模式，目标 App 没加白名单
- 目标 App 自带反 tweak 检测

进一步诊断——在 frida REPL 里看注入框架本身在不在：

```javascript
Process.enumerateModules()
    .filter(m => /(ellekit|substitute|substrate|TweakInject|libhooker|choicy)/i.test(m.path))
    .forEach(m => console.log(m.path))
```

- 有输出 → 框架进来了但 GumTrace 被过滤 → 改 Choicy / ellekit 白名单。
- 完全空 → 整个 tweak 链都被屏蔽 → 用第 5 节的"兜底方案"。

## 5. 兜底方案：frida 直接 `Module.load`（100% 绕过 ellekit）

把 dylib 用 `Module.load` 拉进去，不依赖 TweakInject。在 frida REPL 或 hook
脚本里执行：

```javascript
const m = Module.load('/var/jb/usr/lib/TweakInject/GumTrace.dylib')
console.log('loaded:', m.name, '@', m.base, '| size:', m.size)
```

期待输出：

```
loaded: GumTrace.dylib @ 0x13c3ac000 | size: 7356416
```

反 tweak 检测拦不到这条路径（dylib 不在进程启动时的初始模块列表里，是
**动态**加载的）。本目录三个示例脚本都自带这个兜底逻辑。

## 6. JS 侧反越狱 bypass（目标 App 主动检测 `/var/jb` 时）

一些重度加固 App 会主动扫描越狱痕迹（`/var/jb/`、`Cydia.app`、`TweakInject`、
`MobileSubstrate` 等）并在 main() 早期自杀。两种处理方式：

| 方案 | 代价 |
|---|---|
| **Dopamine 自带"隐藏越狱"开关** | 系统级隐藏 `/var/jb` 对**所有进程**。副作用：TweakInject 也看不到 jb 路径，**GumTrace 也加载不了** |
| **JS 侧 anti-jb hook**（见 [`examples/frida-gumtrace/targetapp-anti-jb-spawn.js`](../examples/frida-gumtrace/targetapp-anti-jb-spawn.js)） | 在 frida 注入的脚本里逐个 hook `stat / access / open / dlopen / getenv / ptrace / sysctl / _dyld_get_image_name`。dlopen **特殊处理**：放过 GumTrace.dylib，其他 jb 路径返回 NULL。这样 frida 还能加载 GumTrace，但目标 App 看到的是干净系统 |

**推荐**：**关掉 Dopamine 的全局隐藏越狱开关**，改用脚本级 anti-jb hook。
这样 frida 还能正常 `Module.load` GumTrace，目标 App 也看不到越狱痕迹。

## 7. 故障排查速查表

| 现象 | 原因 | 处理 |
|---|---|---|
| `iproxy: bind failed` | 2222 已被占用 | `lsof -ti:2222 \| xargs kill -9` 或换端口 |
| `Host key verification failed` | known_hosts 冲突 | `ssh-keygen -R "[localhost]:2222"` |
| `scp: Permission denied` | 目标目录权限不够 | 先 `ssh ... "mkdir -p /var/jb/usr/lib/TweakInject"` |
| `ldid: command not found` | 设备上没装 ldid | `ssh ... "apt install ldid"`（Dopamine 包管理） |
| `frida -U -n` 找不到设备 | USB 未授权 | 解锁设备、信任此电脑、`idevice_id -l` 确认设备能识别 |
| `frida-ps -Uai` 进程列表空 | frida-server 没跑 | `ssh ... "frida-server &"`（后台） |
| dylib 加载成功但 trace 0 字节 | `init()` 在错误线程调用 | hook ObjC 业务方法在 `onEnter` 里 init/run，`threadId=0` 必须 |
| `Module.load` 抛 `ENOENT` | dylib 不在设备上 | 重做第 3 步，`ls -la /var/jb/usr/lib/TweakInject/GumTrace.dylib` 确认 |
| spawn 立刻 `connection is closed` | 反越狱检测干掉进程 | 用第 6 节的 JS 侧 anti-jb hook |

## 8. 一次性命令包（环境就绪后快速复用）

```bash
# 推 + 签 + 重启 SpringBoard（dylib 重编后跑这一条）
scp -P 2222 build_ios/libGumTrace.dylib \
    root@localhost:/var/jb/usr/lib/TweakInject/GumTrace.dylib && \
ssh -p 2222 root@localhost \
    "ldid -S /var/jb/usr/lib/TweakInject/GumTrace.dylib && killall -9 SpringBoard"

# 强杀目标 App（让下次启动是真冷启动）
ssh -p 2222 root@localhost "killall -9 <进程名>"

# 验证注入（替换 <进程名>）
frida -U -n <进程名> -e \
  "console.log(Process.enumerateModules().filter(m => /GumTrace/i.test(m.path)).length)"
# 输出 1 = 已注入；0 = 用第 5 节 Module.load 兜底
```

## 9. 大 trace 文件拉回 macOS（USB SSH 单次撑不住几个 GB 时）

1.5–10 GB trace 通过 USB SSH 直传容易中途断。**三种方案从简到难**：

### 方案 A：`scp -C` 内置 gzip 压缩（最快试）

```bash
scp -P 2222 -C \
  root@localhost:'/var/mobile/Containers/Data/Application/<UUID>/Documents/<trace>.log' \
  ./
```

`-C` 让 SSH 双端自动协商 gzip 压缩。trace 是文本，重复指令多，压缩率 5-10x。

### 方案 B：`rsync --partial` 续传（如果设备有 rsync）

```bash
ssh -p 2222 root@localhost "which rsync"   # 先确认有
rsync -avP --partial -e 'ssh -p 2222' \
  root@localhost:'<远端路径>' \
  ./
```

断了直接重跑命令，从断点续传。

### 方案 C：dd 100 MB 分块（万能最稳）

```bash
mkdir -p /tmp/chunks && cd /tmp/chunks
SRC='/var/mobile/Containers/Data/Application/<UUID>/Documents/<trace>.log'
for i in $(seq 0 19); do  # 20 块 = 2 GB（按实际文件大小调整）
  CHUNK=$(printf "chunk_%03d.bin" $i)
  [ -s "$CHUNK" ] && continue   # 已拉过且非空就跳过
  echo "拉块 $i"
  ssh -p 2222 root@localhost "dd if='$SRC' bs=1M count=100 skip=$((i*100)) 2>/dev/null" > "$CHUNK"
done
cat chunk_*.bin > <本地输出.log>
rm -rf /tmp/chunks
```

每块短连接，断一块只丢一块的重传成本。

## 相关文档

- [`examples/frida-gumtrace/README.md`](../examples/frida-gumtrace/README.md)
  —— GumTrace 实战教程总览 + 三个示例脚本
- [`examples/frida-gumtrace/targetapp-correct.js`](../examples/frida-gumtrace/targetapp-correct.js)
  —— 最小验证版（单 hook 点）
- [`examples/frida-gumtrace/targetapp-startup-trace.js`](../examples/frida-gumtrace/targetapp-startup-trace.js)
  —— 启动期完整 trace 模板
- [`examples/frida-gumtrace/targetapp-anti-jb-spawn.js`](../examples/frida-gumtrace/targetapp-anti-jb-spawn.js)
  —— **反越狱 bypass + spawn 模式 trace** 模板（目标 App 检测越狱时用）
