<div align="center">

# ForgeVM

![Windows 11](https://img.shields.io/badge/Windows_11-0078D4?style=flat-square&logo=windows11&logoColor=white)
![Java 17+](https://img.shields.io/badge/Java_17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
[![JitPack](https://jitpack.io/v/CJiangqiu/ForgeVM.svg)](https://jitpack.io/#CJiangqiu/ForgeVM)

**[English](#english)** | **[中文](#中文)**

</div>

---

<a id="english"></a>

# English

ForgeVM (FVM) manipulates a running JVM through an independent, external Agent process. All operations — field writes, bytecode transforms, agent purging — are performed entirely via `ReadProcessMemory` / `WriteProcessMemory` and direct HotSpot internal structure traversal. The Java side sends only string descriptors over IPC; no `sun.misc.Unsafe`, no JVMTI, no `java.lang.instrument`.

## Getting Started

### 1. Add Dependency

```gradle
// settings.gradle
repositories {
    maven { url 'https://jitpack.io' }
}

// build.gradle
dependencies {
    implementation 'com.github.CJiangqiu:ForgeVM:v0.6.5'
}
```

For Maven / SBT / other build tools, see [JitPack page](https://jitpack.io/#CJiangqiu/ForgeVM).

### 2. Launch the Agent

```java
ForgeVM.LaunchResult result = ForgeVM.launch();

if (!result.nativeDllActive()) {
    System.err.println("ForgeVM launch failed: " + result.reason());
    return;
}
// Agent is active, all APIs are now usable
```

`launch()` is the single entry point — no overloads, no policies. Result is binary: `FULL` on success, `UNAVAILABLE` on failure (reason written to log).

### 3. Use the API

```java
// Memory — write fields by path chain, zero Unsafe
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxHealth", 200);

// Forge — runtime method interception
ForgeVM.forge().load(new MyIngot());

// JVM Control
ForgeVM.exitJvm();                                         // TerminateProcess, no Java API
ForgeVM.banJavaAgent();                                 // purge all loaded agents + block all future attaches
ForgeVM.banNativeLoad();                                // block native library loading
```

## Requirements

- **OS**: Windows x64
- **JDK**: 17+
- **Target JVM**: HotSpot (OpenJDK / Oracle JDK)
- **Privileges**: Same-user JVM access requires no elevated privileges. `SeDebugPrivilege` is attempted opportunistically at startup — if unavailable, ForgeVM continues normally.

## How It Works

```
Java Application
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java Library (in-process)
    │  Extracts & starts the native Agent executable
    │  Communicates via process stdin/stdout (initial spawn)
    │  or named pipe \\.\pipe\forgevm_cmd_<pid> (post-relaunch handoff)
    │  Sends only string descriptors — zero JVM native API
    ▼
ForgeVM Agent (forgevm_agent.exe, separate process)
    │  Receives JSON commands line-by-line, replies on stdout
    │  Loads forgevm_native.dll
    │  Opens target JVM process handle
    │  Reads HotSpot VMStructs to build internal layout map
    ▼
Native Backend (C++, Win32 API)
    ├─ ReadProcessMemory / WriteProcessMemory for field writes
    ├─ NtSuspendThread / NtResumeThread for thread control
    ├─ HotSpot ConstMethod/ConstantPool rewriting for bytecode transform
    └─ SystemDictionary traversal for class/method resolution
```

## Modules

| Package | Purpose |
|---|---|
| `forgevm.core` | Lifecycle, Agent launch, status detection |
| `forgevm.memory` | Field write API — path-based navigation, zero Unsafe |
| `forgevm.forge` | Runtime bytecode rewriting — method interception |
| `forgevm.jvm` | JVM control — exit, Agent lock, Java Agent blocking/purging, native load blocking |
| `forgevm.util` | Logging, JSON utilities |

## Agent Status

| Status | Meaning |
|---|---|
| `FULL`        | Agent running with full privileges                                    |
| `RESTRICTED`  | Agent running with limited privileges (no `SeDebugPrivilege`)         |
| `UNAVAILABLE` | Agent failed to start — all operations will throw `ForgeVMException`  |

## API Reference

### Memory Module

Write fields using a path-based API. The Agent resolves all addresses internally via RPM.

```java
// Static field
ForgeVM.memory().putIntField("com.example.Config", "maxRetries", 5);
ForgeVM.memory().putBooleanField("com.example.Config", "debugMode", true);

// Instance field via path chain from a static root
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxRetries", 10);
ForgeVM.memory().putFloatField("com.example.Server", "INSTANCE.config.timeout", 3.5f);

// Set a reference field to null
ForgeVM.memory().putNullField("com.example.Server", "INSTANCE.cache");

// Set a reference field to a new object (zero Unsafe)
MyConfig newConfig = new MyConfig();
ForgeVM.memory().putObjectField("com.example.Server", "INSTANCE.config", newConfig);
```

Supported types: `boolean`, `byte`, `char`, `short`, `int`, `float`, `long`, `double`, object reference, null reference.

### JVM Control Module

```java
// Terminate JVM (Agent calls TerminateProcess directly)
ForgeVM.exitJvm();
ForgeVM.exitJvm(1);

// Lock Agent — prevents other processes from commanding it
ForgeVM.lockAgent(60);  // TTL in seconds
ForgeVM.unlockAgent();

// Block Java Agent attachment — single API covers both already-loaded and future attaches.
// The filter is jar-path glob (case-insensitive, '\\' == '/').
ForgeVM.banJavaAgent();                                        // purge ALL loaded + block all future
ForgeVM.banJavaAgent(AgentFilter.Blacklist("*evil*.jar"));     // purge + ban only jars matching pattern
ForgeVM.banJavaAgent(AgentFilter.Whitelist("*trusted*.jar"));  // purge + ban all jars NOT in whitelist

ForgeVM.unbanJavaAgent();                                      // un-patch future-attach filter (purge is irreversible)

// Block native library loading
ForgeVM.banNativeLoad();                                       // block all
ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*"));      // block by name/path glob
ForgeVM.banNativeLoad(NativeFilter.Whitelist("lwjgl*"));       // only allow matching
ForgeVM.unbanNativeLoad();                                     // allow again

// Rebind Agent to current JVM (for Shadow JVM switching)
ForgeVM.rebindAgentToCurrentJvm();

// Relaunch — kill the JVM and restart it with a filtered command line
// Throws RelaunchException on failure. On success, never returns (JVM is killed).
// Automatically refuses to run if the current JVM was already relaunched by ForgeVM,
// preventing infinite restart loops without any extra guard from the caller.
try {
    ForgeVM.relaunch();                                      // restart, keep all args
    ForgeVM.relaunch(AgentFilter.Blacklist("evil.jar"));     // strip matching -javaagent: args
    ForgeVM.relaunch(NativeFilter.Blacklist("*cheat*"));     // strip matching -agentpath: args
    ForgeVM.relaunch(ProcessFilter.Blacklist("*.exe"));      // pre-install a process-creation filter
    ForgeVM.relaunch(agentFilter, nativeFilter);             // any pair of filters
    ForgeVM.relaunch(agentFilter, processFilter);
    ForgeVM.relaunch(nativeFilter, processFilter);
    ForgeVM.relaunch(agentFilter, nativeFilter, processFilter); // all three at once
} catch (RelaunchException e) {
    // e.getMessage(): "already_relaunched" | "agent_not_active" | "open_process_failed" | ...
}
```

**`banJavaAgent` purges already-loaded agents** that match the filter via native memory operations:
1. Enumerates `ClassLoaderDataGraph` to find every InstanceKlass holding a static `Instrumentation` / `InstrumentationImpl` reference (= agent main class)
2. Resolves each agent's source jar via `Klass._java_mirror → Class.protection_domain → CodeSource.location → URL.path` — the same jar identity the future-attach trampoline observes, so one filter covers both arms
3. For matching agents: nullifies `TransformerManager` inside `InstrumentationImpl`, nullifies the agent's static `Instrumentation` reference
3. Overwrites `agentmain`/`premain` bytecode with bare `return`
4. Forces JIT deoptimization

The purge arm is irreversible (unlike the future-attach filter, which `unbanJavaAgent()` can lift). Agents whose jar identity cannot be resolved (boot loader, dynamically-generated classes) are skipped when a filter is supplied — call `banJavaAgent()` with no filter for unconditional purge.

**`banNativeLoad`** hooks `ntdll!LdrLoadDll` — the kernel-level entry point for every DLL load in the process, including JNI loads, smuggled agent DLLs, and injected threads. All of `System.load`, `System.loadLibrary`, `Runtime.load`, `Runtime.loadLibrary`, and any other path that maps a DLL are covered. Blocked loads return `STATUS_DLL_NOT_FOUND`. ForgeVM's own DLL is not affected — it loads through the external Agent process before any hook is installed.

**`relaunch`** is the only API in ForgeVM that protects the new JVM's *entire lifecycle*, starting from its very first instruction. The flow:

1. Query the current JVM's full command line via WMI; apply filters to strip `-javaagent:` / `-agentpath:` tokens. Inject `-Dforgevm.relaunched=true` (loop-breaker) and `-Dforgevm.agent.pid=<agent_pid>` (handoff token).
2. `CreateProcessW` the new JVM with `CREATE_SUSPENDED` — the new process exists but its main thread hasn't executed a single instruction yet.
3. Open the new JVM's handle, switch the DLL's target to it (`forgevm_attach_target_minimal`), and patch `ntdll!LdrLoadDll` directly into the new JVM's memory. From this moment, every DLL load in the new JVM — including the JVM launcher's load of `jvm.dll` itself, JNI loads, and any injected DLL — is filtered against `nativeFilter`.
4. `ResumeThread` the new JVM. It now runs with the ntdll hook live from its first instruction.
5. `TerminateProcess` the old JVM. The agent does **not** exit — it persists.
6. A watcher thread in the persistent agent polls the new JVM's module list every 50 ms; the moment `jvm.dll` is mapped, it runs full `bootstrap_target` and installs the `JVM_EnqueueOperation` hook (banJavaAgent). This happens long before `main()` runs, so dynamic agent attach is blocked for the new JVM's entire lifetime.
7. When the new JVM eventually calls `ForgeVM.launch()`, it detects the handoff token and connects to the persistent agent via the named pipe `\\.\pipe\forgevm_cmd_<agent_pid>` instead of spawning a fresh agent. The same agent that pre-patched the new JVM continues to serve all subsequent commands.

Result: the supplied filters behave like real JVM startup arguments — they are in effect from instruction zero of the new JVM, with no observable window in which an attacker could attach or load. Old already-loaded agents/DLLs are gone (their JVM was terminated and the OS reclaimed the address space).

### Forge Module

Intercept methods at runtime by rewriting HotSpot `ConstMethod` bytecode from outside the process.

```java
public class ProcessLogger extends FvmIngot {
    public ProcessLogger() {
        super("com.example.app.OrderService", "processOrder");
    }

    public static void onProcess(FvmCallback callback) {
        System.out.println("processOrder called");
    }
}

// Load / unload
ForgeVM.forge().load(new ProcessLogger());
ForgeVM.forge().unload(ProcessLogger.class);
```

**Method descriptor format:**

```java
super("com.example.Foo", "bar");                    // simple
super("com.example.Foo", "bar,a_42");               // multiple candidates (obfuscation)
super("com.example.Foo", "bar", RETURN);             // inject at RETURN instead of HEAD
super("com.example.Foo", "bar(Ljava/lang/String;)"); // with parameter descriptor
```

**Injection points:**

```java
super("Foo", "bar", HEAD);                       // before first instruction (default)
super("Foo", "bar", RETURN);                     // before every return
super("Foo", "bar", INVOKE("setHealth"));        // before any call to setHealth (all overloads)
super("Foo", "bar", INVOKE("setHealth(F)"));     // before calls matching name + param descriptor
super("Foo", "bar", INVOKE("setHealth(F)V"));    // before calls matching full descriptor
super("Foo", "bar", FIELD_GET("health"));        // before any getfield/getstatic named health
super("Foo", "bar", FIELD_GET("health:F"));      // before getfield/getstatic matching name + type
super("Foo", "bar", FIELD_PUT("health"));        // before any putfield/putstatic named health
super("Foo", "bar", FIELD_PUT("health:F"));      // before putfield/putstatic matching name + type
super("Foo", "bar", NEW("java.util.ArrayList")); // before object creation
```

**Subclass propagation:**

```java
@Override
public boolean includeSubclasses() { return true; }
```

**FvmCallback:**

- `callback.setReturnValue(value)` — skip original method, return given value
- `callback.cancel()` — skip original method (void)
- `callback.getInstance()` — get `this` reference
- `callback.getArgument(index)` — get method argument by index
- `callback.argumentCount()` — get number of arguments

## Logging

Logs are written to `ForgeVM/logs/`:

- `fvm-agent.log` — Agent lifecycle
- `fvm-transform.log` — Transform & memory operation details

## Build from Source

```bash
./gradlew clean jar       # Java side → build/libs/
```

C++ side (`forgevm_agent.exe` + `forgevm_native.dll`) requires MSVC. Place binaries in `src/main/resources/native/win-x64/` to bundle into the JAR.

## License

MIT

---

<a id="中文"></a>

# 中文

ForgeVM (FVM) 通过独立的外部 Agent 进程操控运行中的 JVM。所有操作 — 字段写入、字节码变换、Agent 清除 — 均完全通过 `ReadProcessMemory` / `WriteProcessMemory` 和直接的 HotSpot 内部结构遍历执行。Java 侧仅发送字符串描述符，不使用 `sun.misc.Unsafe`、不使用 JVMTI、不使用 `java.lang.instrument`。

## 快速开始

### 1. 添加依赖

```gradle
// settings.gradle
repositories {
    maven { url 'https://jitpack.io' }
}

// build.gradle
dependencies {
    implementation 'com.github.CJiangqiu:ForgeVM:v0.6.5'
}
```

其他构建工具（Maven / SBT 等）参见 [JitPack 页面](https://jitpack.io/#CJiangqiu/ForgeVM)。

### 2. 启动 Agent

```java
ForgeVM.LaunchResult result = ForgeVM.launch();

if (!result.nativeDllActive()) {
    System.err.println("ForgeVM launch failed: " + result.reason());
    return;
}
// Agent 已就绪，所有 API 可用
```

`launch()` 是唯一入口，无重载，无策略参数。结果二值：成功为 `FULL`，失败为 `UNAVAILABLE`（原因写入日志）。

### 3. 使用 API

```java
// 内存 — 按路径链写入字段，零 Unsafe
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxHealth", 200);

// 锻造 — 运行时方法拦截
ForgeVM.forge().load(new MyIngot());

// JVM 控制
ForgeVM.exitJvm();                                         // TerminateProcess，不涉及 Java API
ForgeVM.banJavaAgent();                                 // 清除所有已加载 agent + 阻断所有未来 attach
ForgeVM.banNativeLoad();                                // 拦截原生库加载
```

## 环境要求

- **操作系统**：Windows x64
- **JDK**：17+
- **目标 JVM**：HotSpot（OpenJDK / Oracle JDK）
- **权限**：同用户 JVM 访问无需提权。`SeDebugPrivilege` 在启动时机会主义地尝试获取 — 拿不到不影响正常运行。

## 工作原理

```
Java 应用程序
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java 库（进程内）
    │  解压并启动原生 Agent 可执行文件
    │  通过进程 stdin/stdout 通信（初始启动）
    │  或命名管道 \\.\pipe\forgevm_cmd_<pid>（重启后 handoff）
    │  仅发送字符串描述符 — 零 JVM 原生 API
    ▼
ForgeVM Agent（forgevm_agent.exe，独立进程）
    │  按行接收 JSON 命令，通过 stdout 回应
    │  加载 forgevm_native.dll
    │  打开目标 JVM 进程句柄
    │  读取 HotSpot VMStructs 构建内部布局映射
    ▼
原生后端（C++，Win32 API）
    ├─ ReadProcessMemory / WriteProcessMemory 用于字段写入
    ├─ NtSuspendThread / NtResumeThread 用于线程控制
    ├─ HotSpot ConstMethod/ConstantPool 重写用于字节码变换
    └─ SystemDictionary 遍历用于类/方法定位
```

## 模块

| 包 | 用途 |
|---|---|
| `forgevm.core` | 生命周期、Agent 启动、状态检测 |
| `forgevm.memory` | 字段写入 API — 基于路径导航，零 Unsafe |
| `forgevm.forge` | 运行时字节码重写 — 方法拦截 |
| `forgevm.jvm` | JVM 控制 — 退出、Agent 锁定、Java Agent 拦截/清除、原生库加载拦截 |
| `forgevm.util` | 日志、JSON 工具 |

## Agent 状态

| 状态 | 含义 |
|---|---|
| `FULL`        | Agent 运行中，完整权限                                            |
| `RESTRICTED`  | Agent 运行中，权限受限（无 `SeDebugPrivilege`）                   |
| `UNAVAILABLE` | Agent 启动失败 — 所有操作将抛出 `ForgeVMException`                |

## API 参考

### Memory 模块

通过基于路径的 API 写入字段。Agent 内部通过 RPM 解析所有地址。

```java
// 静态字段
ForgeVM.memory().putIntField("com.example.Config", "maxRetries", 5);
ForgeVM.memory().putBooleanField("com.example.Config", "debugMode", true);

// 实例字段 — 通过路径链从静态根导航
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxRetries", 10);
ForgeVM.memory().putFloatField("com.example.Server", "INSTANCE.config.timeout", 3.5f);

// 将引用字段设为 null
ForgeVM.memory().putNullField("com.example.Server", "INSTANCE.cache");

// 将引用字段设为新对象（零 Unsafe）
MyConfig newConfig = new MyConfig();
ForgeVM.memory().putObjectField("com.example.Server", "INSTANCE.config", newConfig);
```

支持类型：`boolean`、`byte`、`char`、`short`、`int`、`float`、`long`、`double`、对象引用、null 引用。

### JVM 控制模块

```java
// 终止 JVM（Agent 直接调用 TerminateProcess）
ForgeVM.exitJvm();
ForgeVM.exitJvm(1);

// 锁定 Agent — 阻止其他进程对其发送命令
ForgeVM.lockAgent(60);  // TTL 秒数
ForgeVM.unlockAgent();

// 拦截 Java Agent —— 单一 API 同时处理"已加载"和"未来 attach"两个时态。
// filter 按 jar 路径 glob 匹配（大小写不敏感，'\\' 等价于 '/'）。
ForgeVM.banJavaAgent();                                        // 清除所有已加载 + 阻断所有未来 attach
ForgeVM.banJavaAgent(AgentFilter.Blacklist("*evil*.jar"));     // 清除并拦截匹配 pattern 的 jar
ForgeVM.banJavaAgent(AgentFilter.Whitelist("*trusted*.jar")); // 清除并拦截 不在白名单内的 jar

ForgeVM.unbanJavaAgent();                                      // 卸除未来 attach 过滤（已 purge 的不可逆）

// 拦截原生库加载
ForgeVM.banNativeLoad();                                       // 全部拦截
ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*"));      // 按名称/路径模式
ForgeVM.banNativeLoad(NativeFilter.Whitelist("lwjgl*"));       // 仅放行匹配的
ForgeVM.unbanNativeLoad();                                     // 解除拦截

// 将 Agent 重新绑定到当前 JVM（用于 Shadow JVM 切换）
ForgeVM.rebindAgentToCurrentJvm();

// 重启 — 杀死当前 JVM 并以过滤后的命令行重新启动
// 失败时抛出 RelaunchException。成功时永不返回（JVM 已被杀死）。
// 若当前 JVM 已经是 ForgeVM 重启后的进程，自动拒绝执行，无需调用方手动防死循环。
try {
    ForgeVM.relaunch();                                      // 保留所有参数重启
    ForgeVM.relaunch(AgentFilter.Blacklist("evil.jar"));     // 过滤掉匹配的 -javaagent: 参数
    ForgeVM.relaunch(NativeFilter.Blacklist("*cheat*"));     // 过滤掉匹配的 -agentpath: 参数
    ForgeVM.relaunch(ProcessFilter.Blacklist("*.exe"));      // 预装进程创建过滤器
    ForgeVM.relaunch(agentFilter, nativeFilter);             // 任意两种过滤组合
    ForgeVM.relaunch(agentFilter, processFilter);
    ForgeVM.relaunch(nativeFilter, processFilter);
    ForgeVM.relaunch(agentFilter, nativeFilter, processFilter); // 三种全应用
} catch (RelaunchException e) {
    // e.getMessage(): "already_relaunched" | "agent_not_active" | "open_process_failed" | ...
}
```

**`banJavaAgent` 自动清除匹配 filter 的已加载 Agent**，通过原生内存操作：
1. 遍历 `ClassLoaderDataGraph` 找出所有持有静态 `Instrumentation` / `InstrumentationImpl` 引用的 InstanceKlass（= agent 主类）
2. 沿 `Klass._java_mirror → Class.protection_domain → CodeSource.location → URL.path` 反查每个 agent 的来源 jar 路径——和未来 attach trampoline 看到的是同一个 jar 身份，所以同一份 filter 同时覆盖两个时态
3. 对命中 filter 的 agent：清空 `InstrumentationImpl` 内部的 `TransformerManager`、把 agent 的静态 `Instrumentation` 引用置为 null、用空 `return` 覆写 `agentmain`/`premain` 字节码、强制 JIT 反优化

purge 不可逆（不像未来 attach 过滤可以用 `unbanJavaAgent()` 撤销）。jar 身份无法识别的 agent（boot loader / 动态生成类）在 filter 模式下会被跳过——若希望连这类一起清掉，调用无参的 `banJavaAgent()`。

**`banNativeLoad`** hook `ntdll!LdrLoadDll` — 进程内所有 DLL 加载的内核级入口，覆盖 JNI 加载、注入线程、被偷渡的 Agent DLL 等全部路径。`System.load`、`System.loadLibrary`、`Runtime.load`、`Runtime.loadLibrary` 以及任何映射 DLL 的手段均受控制，被拦截的加载返回 `STATUS_DLL_NOT_FOUND`。ForgeVM 自身的 DLL 不受影响——它在 hook 安装前通过外部 Agent 进程加载。

**`relaunch`** 是 ForgeVM 中唯一能保护新 JVM **整个生命周期**（从第一条指令开始）的 API。流程：

1. 通过 WMI 查询当前 JVM 完整命令行，对 `-javaagent:` / `-agentpath:` token 应用过滤剥离。注入 `-Dforgevm.relaunched=true`（断路器）和 `-Dforgevm.agent.pid=<agent_pid>`（handoff token）。
2. `CreateProcessW` 以 `CREATE_SUSPENDED` 创建新 JVM —— 进程已存在但主线程尚未执行任何一条指令。
3. 打开新 JVM 句柄，把 DLL 的目标切换到它（`forgevm_attach_target_minimal`），把 `ntdll!LdrLoadDll` patch 直接写入新 JVM 内存。**从此刻起**，新 JVM 中所有 DLL 加载——包括 JVM 启动器加载 `jvm.dll` 本身、JNI 加载、被注入的 DLL——全部经过 `nativeFilter` 过滤。
4. `ResumeThread` 唤醒新 JVM。它从第一条指令开始就带着 ntdll hook 跑。
5. `TerminateProcess` 杀掉旧 JVM。Agent **不退出**，继续保留。
6. 持久化 agent 的 watcher 线程每 50 ms 轮询新 JVM 的模块列表；一旦看到 `jvm.dll` 被映射，立即跑完整 `bootstrap_target` 并装上 `JVM_EnqueueOperation` hook（banJavaAgent）。这早在 `main()` 运行之前完成，新 JVM 整个生命周期内动态 agent attach 都被阻断。
7. 新 JVM 后续调用 `ForgeVM.launch()` 时，检测到 handoff token，通过命名管道 `\\.\pipe\forgevm_cmd_<agent_pid>` 连接到现有 agent，而不是 spawn 新 agent。**同一个** agent 既预先 patch 了新 JVM，又继续服务所有后续命令。

结果：传入的 filter 行为等价于真正的 JVM 启动参数——从新 JVM 的第 0 条指令就生效，攻击者没有任何可乘的窗口期进行 attach 或加载。旧的已加载 agent/DLL 全部消失（旧 JVM 被终止，OS 回收了地址空间）。

### Forge 模块

通过从进程外部重写 HotSpot `ConstMethod` 字节码来拦截运行时方法。

```java
public class ProcessLogger extends FvmIngot {
    public ProcessLogger() {
        super("com.example.app.OrderService", "processOrder");
    }

    public static void onProcess(FvmCallback callback) {
        System.out.println("processOrder called");
    }
}

// 加载 / 卸载
ForgeVM.forge().load(new ProcessLogger());
ForgeVM.forge().unload(ProcessLogger.class);
```

**方法描述符格式：**

```java
super("com.example.Foo", "bar");                    // 简单形式
super("com.example.Foo", "bar,a_42");               // 多候选名（混淆场景）
super("com.example.Foo", "bar", RETURN);             // 注入点改为 RETURN
super("com.example.Foo", "bar(Ljava/lang/String;)"); // 带参数描述符
```

**注入点：**

```java
super("Foo", "bar", HEAD);                       // 方法入口（默认）
super("Foo", "bar", RETURN);                     // 每个 return 前
super("Foo", "bar", INVOKE("setHealth"));        // 所有 setHealth 调用前（全重载）
super("Foo", "bar", INVOKE("setHealth(F)"));     // 名称 + 参数描述符匹配
super("Foo", "bar", INVOKE("setHealth(F)V"));    // 完整描述符匹配
super("Foo", "bar", FIELD_GET("health"));        // 所有名为 health 的 getfield/getstatic 前
super("Foo", "bar", FIELD_GET("health:F"));      // 名称 + 类型描述符匹配
super("Foo", "bar", FIELD_PUT("health"));        // 所有名为 health 的 putfield/putstatic 前
super("Foo", "bar", FIELD_PUT("health:F"));      // 名称 + 类型描述符匹配
super("Foo", "bar", NEW("java.util.ArrayList")); // 对象创建前
```

**子类传递：**

```java
@Override
public boolean includeSubclasses() { return true; }
```

**FvmCallback：**

- `callback.setReturnValue(value)` — 跳过原始方法，返回指定值
- `callback.cancel()` — 跳过原始方法（void）
- `callback.getInstance()` — 获取 `this` 引用
- `callback.getArgument(index)` — 按索引获取方法参数
- `callback.argumentCount()` — 获取参数数量

## 日志

日志写入 `ForgeVM/logs/`：

- `fvm-agent.log` — Agent 生命周期
- `fvm-transform.log` — 变换与内存操作细节

## 从源码构建

```bash
./gradlew clean jar       # Java 侧 → build/libs/
```

C++ 侧（`forgevm_agent.exe` + `forgevm_native.dll`）需要 MSVC 编译。将产物放入 `src/main/resources/native/win-x64/` 可打包进 JAR。

## 许可证

MIT
