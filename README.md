<div align="center">

# ForgeVM

![Windows 11](https://img.shields.io/badge/Windows_11-0078D4?style=flat-square&logo=windows11&logoColor=white)
![Java 17+](https://img.shields.io/badge/Java_17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**[English](#english)** | **[中文](#中文)**

</div>

---

<a id="english"></a>

# English

Welcome to ForgeVM (FVM). FVM is a low-level tool that manipulates a running JVM through an independent, external FVM Agent process. All memory operations — field writes, bytecode transforms, agent purging — are performed entirely by the Agent via `ReadProcessMemory` / `WriteProcessMemory` and direct HotSpot internal structure traversal. The Java side sends only string descriptors over IPC; no `sun.misc.Unsafe`, no JVMTI, no `java.lang.instrument`.

## How It Works

```
Java Application
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java Library (in-process)
    │  Extracts & starts the native Agent executable
    │  Communicates via stdin/stdout JSON protocol
    │  Sends only string descriptors — zero JVM native API
    ▼
ForgeVM Agent (forgevm_agent.exe, separate process)
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
| `forgevm.core` | Lifecycle management, Agent launch, capability detection, fallback |
| `forgevm.memory` | Field write API — path-based navigation, zero Unsafe dependency |
| `forgevm.transform` | Runtime bytecode rewriting — method interception with load/unload |
| `forgevm.jvm` | JVM control — process exit, Agent lock/unlock, Java Agent blocking/purging, rebind |
| `forgevm.util` | Logging, JSON utilities |

## Requirements

- **OS**: Windows x64
- **JDK**: 17+
- **Target JVM**: HotSpot (OpenJDK / Oracle JDK)
- **Privileges**: The Agent requires `SeDebugPrivilege` or administrator rights to open the target process handle

## Usage

### 1. Bootstrap (Required First)

All ForgeVM operations depend on a successful launch. You must call `ForgeVM.launch()` at an appropriate point during your application startup before using any other API. If the launch fails, the Agent status will be `UNAVAILABLE` and all Agent-dependent operations will throw `ForgeVMException`.

```java
// Call this early in your application — everything else depends on it
ForgeVM.LaunchResult result = ForgeVM.launch();

if (!result.nativeDllActive()) {
    // Agent is not available — handle accordingly
    System.err.println("ForgeVM launch failed: " + result.reason());
    return;
}

// Agent is active, all APIs are now usable
```

`ForgeVM.launch()` handles native binary extraction, Agent process startup, HotSpot struct map initialization, and compression parameter detection. No manual path configuration is required.

Two launch policies are available:

```java
ForgeVM.launch();              // SILENT — no elevation prompt, auto-fallback
ForgeVM.launch(ForgeVM.PROMPT); // PROMPT — shows a UAC dialog to request higher privileges
```

### 2. Memory Module

Once the Agent is active, you can write to fields using a path-based API. The Java side sends only class name and field chain strings — the Agent resolves all addresses via RPM internally.

```java
// Static field
ForgeVM.memory().putIntField("com.example.app.Config", "maxRetries", 5);
ForgeVM.memory().putBooleanField("com.example.app.Config", "debugMode", true);

// Instance field via path chain — navigates from a static root
ForgeVM.memory().putIntField("com.example.app.Server", "INSTANCE.config.maxRetries", 10);
ForgeVM.memory().putFloatField("com.example.app.Server", "INSTANCE.config.timeout", 3.5f);

// Set a reference field to null
ForgeVM.memory().putNullField("com.example.app.Server", "INSTANCE.cache");
```

Supported types: `boolean`, `byte`, `char`, `short`, `int`, `float`, `long`, `double`, null reference.

Internally, the Agent resolves the class via `SystemDictionary → ClassLoaderDataGraph → InstanceKlass`, then follows the field chain: for each intermediate field, it reads the OOP value via RPM and reads the Klass from the object header, then resolves the next field. At the final field, it writes the value via WPM. If the final field is a reference type, the GC card table is automatically updated. Field offsets are cached after first resolution.

### 3. JVM Control Module

JVM-level operations through the Agent:

```java
// Terminate JVM (Agent sends TerminateProcess — no Java API involved)
ForgeVM.exit();
ForgeVM.exit(1);

// Lock Agent — prevents other processes from commanding it
ForgeVM.lockAgent(60);  // TTL in seconds
ForgeVM.unlockAgent();

// Block Java Agent attachment — prevents other agents from attaching
ForgeVM.banJavaAgent();                                        // block all
ForgeVM.banJavaAgent(AgentFilter.Blacklist("com.evil."));      // block by package prefix
ForgeVM.banJavaAgent(AgentFilter.Whitelist("com.trusted."));   // only allow matching packages
ForgeVM.banJavaAgent(AgentFilter.JarBlacklist("*evil*"));      // block by JAR path
ForgeVM.banJavaAgent(AgentFilter.JarWhitelist("*trusted*"));   // only allow matching JARs
ForgeVM.unbanJavaAgent();                                      // allow again

// Purge a loaded Java agent — disables its Instrumentation and clears entry points
ForgeVM.purgeAgent("com.example.agent.MyAgent");

// Rebind Agent to current JVM (for Shadow JVM switching)
ForgeVM.rebindAgentToCurrentJvm();
```

**`purgeAgent`** disables an already-loaded Java agent entirely via native memory operations:
1. Finds the agent class, reads its static `Instrumentation` field
2. Nullifies the `TransformerManager` inside `InstrumentationImpl` (stops future class transforms)
3. Nullifies the agent's static `Instrumentation` reference
4. Overwrites `agentmain`/`premain` method bytecode with a bare `return`
5. Forces JIT deoptimization so changes take effect immediately

All operations are performed from the external Agent process via WPM — zero Java API calls.

### 4. Transformer Module

The Transformer module intercepts methods at runtime by rewriting HotSpot `ConstMethod` bytecode from outside the process. No `java.lang.instrument`, no JVMTI — the Agent rewrites bytecode directly in the target process memory.

#### Writing a Custom Transformer

Extend `FvmTransformer` and define a `public static` hook method that takes a single `FvmCallback` parameter:

```java
import forgevm.transform.FvmTransformer;
import forgevm.transform.FvmCallback;

public class ProcessLogger extends FvmTransformer {
    public ProcessLogger() {
        // target class (fully qualified), target method name
        super("com.example.app.OrderService", "processOrder");
    }

    // Hook method — must be public static, single FvmCallback parameter
    public static void onProcess(FvmCallback callback) {
        System.out.println("processOrder called on: " + callback.getInstance());
        // Don't call cancel() or setReturnValue() → original method runs normally
    }
}
```

#### Method String Format

The second parameter is a method descriptor string. Comma-separated names are tried in order (for obfuscated methods). Append JVM parameter descriptors in parentheses to distinguish overloads.

```java
// Single method, no-arg, inject at HEAD (simplest)
super("com.example.app.OrderService", "processOrder");

// Multiple candidate names (comma-separated, tried in order)
super("com.example.app.OrderService", "processOrder,a_42");

// Specify inject point (use HEAD or RETURN directly)
super("com.example.app.OrderService", "processOrder", RETURN);

// With parameter descriptor (JVM format, to distinguish overloads)
super("com.example.app.OrderService", "attack(F)");

// Multiple candidates with parameters
super("com.example.app.OrderService", "a_71(Ljava/lang/String;I),process(Ljava/lang/String;I)");
```

#### Controlling Execution Flow via FvmCallback

Inside the hook method, `FvmCallback` controls whether the original method runs:

- **Do nothing** — original method executes normally after the hook returns.
- **`callback.setReturnValue(value)`** — skip the original method and return the given value. Use boxed types for primitives (`5` for `int`, `true` for `boolean`).
- **`callback.cancel()`** — skip the original method for `void` methods.
- **`callback.getInstance()`** — get the `this` reference of the intercepted call, for conditional logic.

```java
// Override a return value — with obfuscation candidates
public class RetryCountOverride extends FvmTransformer {
    public RetryCountOverride() {
        super("com.example.app.RetryPolicy", "getMaxRetries,a_56");
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        callback.setReturnValue(10);
    }
}

// Conditionally cancel a void method
public class ShutdownGuard extends FvmTransformer {
    public ShutdownGuard() {
        super("com.example.app.AppLifecycle", "shutdown", HEAD);
    }

    public static void onShutdown(FvmCallback callback) {
        if (shouldBlock()) {
            callback.cancel();
        }
    }
}

// Conditional logic based on instance type
public class PremiumRetryOverride extends FvmTransformer {
    public PremiumRetryOverride() {
        super("com.example.app.RetryPolicy", "getMaxRetries,a_56");
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        if (callback.getInstance() instanceof com.example.app.PremiumRetryPolicy) {
            callback.setReturnValue(100);
        }
        // Other instances → original method runs normally
    }
}
```

#### Loading and Unloading

```java
// Load — applies the bytecode transform immediately
boolean success = ForgeVM.transformer().load(new ProcessLogger());

// Check if loaded
boolean loaded = ForgeVM.transformer().isLoaded(ProcessLogger.class);

// Unload — restores original bytecode
boolean restored = ForgeVM.transformer().unload(ProcessLogger.class);
```

#### How It Works Internally

The Agent locates the target `Method*` by walking `SystemDictionary → ClassLoaderData → InstanceKlass → methods array`. It reads the original `ConstMethod` bytecode and `ConstantPool`, builds an expanded constant pool with a new `MethodRef` entry for the hook, injects `invokestatic` bytecode at the specified injection point (`HEAD` or `RETURN`), allocates new structures in the target process via `VirtualAllocEx`, and swaps the pointers. Original bytecode is backed up for restoration via `unload()`.

## Native Binary Resolution Order

ForgeVM resolves `forgevm_agent.exe` and `forgevm_native.dll` in this order:

1. **Bundled JAR resources** — extracted to `<working-dir>/ForgeVM/runtime/win-x64/`, falling back to `%LOCALAPPDATA%/ForgeVM/runtime/win-x64/` or `~/.forgevm/runtime/win-x64/`
2. **System property** — `-Dforgevm.agent.exe.path=...` / `-Dforgevm.native.dll.path=...`
3. **Environment variable** — `FORGEVM_AGENT_EXE_PATH` / `FORGEVM_NATIVE_DLL_PATH`
4. **Known local paths** — `./native/win-x64/` and working directory

For typical use, no configuration is needed. The first path that resolves to an existing file is used.

## Build

**Java side:**

```bash
./gradlew clean jar
```

Produces the JAR in `build/libs/`.

**C++ side (Agent & DLL):**

You need to compile `forgevm_agent.exe` and `forgevm_native.dll` yourself using MSVC. Place the compiled binaries into `src/main/resources/native/win-x64/` if you want them bundled into the JAR.

## Agent Status

| Status | Meaning |
|---|---|
| `FULL`        | Agent running, process handle open, struct map loaded, compression params resolved                        |
| `RESTRICTED`  | Agent running but with limited privileges (no `SeDebugPrivilege`)                                          |
| `UNAVAILABLE` | Agent failed to start or initialize — all operations that require the Agent will throw `ForgeVMException`  |

## Logging

All logs are written to `ForgeVM/logs/` (relative to the working directory):

- `fvm-agent.log` — Full Agent lifecycle (startup, bootstrap, command handling, shutdown)
- `fvm-transform.log` — Transform module details (method resolution, bytecode rewriting, memory ops)

## License

MIT

---

<a id="中文"></a>

# 中文

欢迎使用 ForgeVM (FVM)。FVM 是一个通过独立的外部 FVM Agent 进程操控运行中 JVM 的底层工具。所有内存操作 — 字段写入、字节码变换、Agent 清除 — 均完全由 Agent 通过 `ReadProcessMemory` / `WriteProcessMemory` 和直接的 HotSpot 内部结构遍历执行。Java 侧仅通过 IPC 发送字符串描述符，不使用 `sun.misc.Unsafe`、不使用 JVMTI、不使用 `java.lang.instrument`。

## 工作原理

```
Java 应用程序
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java 库（进程内）
    │  解压并启动原生 Agent 可执行文件
    │  通过 stdin/stdout JSON 协议通信
    │  仅发送字符串描述符 — 零 JVM 原生 API
    ▼
ForgeVM Agent（forgevm_agent.exe，独立进程）
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
| `forgevm.core` | 生命周期管理、Agent 启动、能力检测、回退 |
| `forgevm.memory` | 字段写入 API — 基于路径导航，零 Unsafe 依赖 |
| `forgevm.transform` | 运行时字节码重写 — 方法拦截，支持加载/卸载 |
| `forgevm.jvm` | JVM 控制 — 进程退出、Agent 锁定/解锁、Java Agent 拦截/清除、重绑定 |
| `forgevm.util` | 日志、JSON 工具 |

## 环境要求

- **操作系统**：Windows x64
- **JDK**：17+
- **目标 JVM**：HotSpot（OpenJDK / Oracle JDK）
- **权限**：Agent 需要 `SeDebugPrivilege` 或管理员权限以打开目标进程句柄

## 使用方法

### 1. 启动（必须首先执行）

所有 ForgeVM 操作都依赖于成功启动。你必须在应用启动的合适位置调用 `ForgeVM.launch()`，之后才能使用其他 API。如果启动失败，Agent 状态将为 `UNAVAILABLE`，所有依赖 Agent 的操作将抛出 `ForgeVMException`。

```java
// 在应用启动早期调用 — 后续一切操作都依赖于此
ForgeVM.LaunchResult result = ForgeVM.launch();

if (!result.nativeDllActive()) {
    // Agent 不可用
    System.err.println("ForgeVM launch failed: " + result.reason());
    return;
}

// Agent 已就绪，所有 API 可用
```

`ForgeVM.launch()` 处理原生二进制文件解压、Agent 进程启动、HotSpot 结构映射初始化和压缩参数检测。无需手动配置路径。

两种启动策略：

```java
ForgeVM.launch();              // SILENT — 不弹出提权提示，失败自动回退
ForgeVM.launch(ForgeVM.PROMPT); // PROMPT — 弹出 UAC 对话框请求更高权限
```

### 2. Memory 模块

Agent 就绪后，可通过基于路径的 API 写入字段。Java 侧仅发送类名和字段链字符串 — Agent 内部通过 RPM 解析所有地址。

```java
// 静态字段
ForgeVM.memory().putIntField("com.example.app.Config", "maxRetries", 5);
ForgeVM.memory().putBooleanField("com.example.app.Config", "debugMode", true);

// 实例字段 — 通过路径链从静态根导航
ForgeVM.memory().putIntField("com.example.app.Server", "INSTANCE.config.maxRetries", 10);
ForgeVM.memory().putFloatField("com.example.app.Server", "INSTANCE.config.timeout", 3.5f);

// 将引用字段设为 null
ForgeVM.memory().putNullField("com.example.app.Server", "INSTANCE.cache");
```

支持类型：`boolean`、`byte`、`char`、`short`、`int`、`float`、`long`、`double`、null 引用。

内部实现：Agent 通过 `SystemDictionary → ClassLoaderDataGraph → InstanceKlass` 定位类，然后沿字段链导航：对每个中间字段，通过 RPM 读取 OOP 值并从对象头读取 Klass，再解析下一个字段。在最终字段处通过 WPM 写入值。如果最终字段是引用类型，自动更新 GC 卡表。字段偏移在首次解析后缓存。

### 3. JVM 控制模块

通过 Agent 执行 JVM 级别的操作：

```java
// 终止 JVM（Agent 直接调用 TerminateProcess — 不涉及 Java API）
ForgeVM.exit();
ForgeVM.exit(1);

// 锁定 Agent — 阻止其他进程对其发送命令
ForgeVM.lockAgent(60);  // TTL 秒数
ForgeVM.unlockAgent();

// 拦截 Java Agent 附着 — 阻止其他 Agent 附着到当前 JVM
ForgeVM.banJavaAgent();                                        // 全部拦截
ForgeVM.banJavaAgent(AgentFilter.Blacklist("com.evil."));      // 按包名前缀拦截
ForgeVM.banJavaAgent(AgentFilter.Whitelist("com.trusted."));   // 仅放行匹配的包
ForgeVM.banJavaAgent(AgentFilter.JarBlacklist("*evil*"));      // 按 JAR 路径拦截
ForgeVM.banJavaAgent(AgentFilter.JarWhitelist("*trusted*"));   // 仅放行匹配的 JAR
ForgeVM.unbanJavaAgent();                                      // 解除拦截

// 清除已加载的 Java Agent — 禁用其 Instrumentation 并清空入口方法
ForgeVM.purgeAgent("com.example.agent.MyAgent");

// 将 Agent 重新绑定到当前 JVM（用于 Shadow JVM 切换）
ForgeVM.rebindAgentToCurrentJvm();
```

**`purgeAgent`** 通过原生内存操作彻底禁用已加载的 Java Agent：
1. 找到 Agent 类，读取其静态 `Instrumentation` 字段
2. 清空 `InstrumentationImpl` 内部的 `TransformerManager`（阻止后续类变换）
3. 将 Agent 的静态 `Instrumentation` 引用置为 null
4. 用空 `return` 覆写 `agentmain`/`premain` 方法字节码
5. 强制 JIT 反优化使更改立即生效

所有操作均由外部 Agent 进程通过 WPM 执行 — 零 Java API 调用。

### 4. Transformer 模块

Transformer 模块通过从进程外部重写 HotSpot `ConstMethod` 字节码来拦截运行时方法。不使用 `java.lang.instrument`，不使用 JVMTI — Agent 直接在目标进程内存中重写字节码。

#### 编写自定义 Transformer

继承 `FvmTransformer`，定义一个 `public static` hook 方法，接受单个 `FvmCallback` 参数：

```java
import forgevm.transform.FvmTransformer;
import forgevm.transform.FvmCallback;

public class ProcessLogger extends FvmTransformer {
    public ProcessLogger() {
        // 目标类（全限定名），目标方法名
        super("com.example.app.OrderService", "processOrder");
    }

    // Hook 方法 — 必须是 public static，单个 FvmCallback 参数
    public static void onProcess(FvmCallback callback) {
        System.out.println("processOrder called on: " + callback.getInstance());
        // 不调用 cancel() 或 setReturnValue() → 原始方法正常执行
    }
}
```

#### 方法字符串格式

第二个参数是方法描述字符串。逗号分隔的名称按顺序尝试（用于混淆后的方法）。在括号中追加 JVM 参数描述符以区分重载方法。

```java
// 单方法，无参，注入点 HEAD（最简形式）
super("com.example.app.OrderService", "processOrder");

// 多个候选名称（逗号分隔，按顺序尝试）
super("com.example.app.OrderService", "processOrder,a_42");

// 指定注入点（直接使用 HEAD 或 RETURN）
super("com.example.app.OrderService", "processOrder", RETURN);

// 带参数描述符（JVM 格式，区分重载方法）
super("com.example.app.OrderService", "attack(F)");

// 多候选 + 参数
super("com.example.app.OrderService", "a_71(Ljava/lang/String;I),process(Ljava/lang/String;I)");
```

#### 通过 FvmCallback 控制执行流程

在 hook 方法中，`FvmCallback` 控制原始方法是否执行：

- **不做任何操作** — hook 返回后原始方法正常执行。
- **`callback.setReturnValue(value)`** — 跳过原始方法，返回指定值。基本类型使用装箱类型（`int` 用 `5`，`boolean` 用 `true`）。
- **`callback.cancel()`** — 跳过原始方法，用于 `void` 方法。
- **`callback.getInstance()`** — 获取被拦截调用的 `this` 引用，用于条件判断。

```java
// 覆盖返回值 — 带混淆候选名
public class RetryCountOverride extends FvmTransformer {
    public RetryCountOverride() {
        super("com.example.app.RetryPolicy", "getMaxRetries,a_56");
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        callback.setReturnValue(10);
    }
}

// 有条件地取消 void 方法
public class ShutdownGuard extends FvmTransformer {
    public ShutdownGuard() {
        super("com.example.app.AppLifecycle", "shutdown", HEAD);
    }

    public static void onShutdown(FvmCallback callback) {
        if (shouldBlock()) {
            callback.cancel();
        }
    }
}

// 基于实例类型的条件判断
public class PremiumRetryOverride extends FvmTransformer {
    public PremiumRetryOverride() {
        super("com.example.app.RetryPolicy", "getMaxRetries,a_56");
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        if (callback.getInstance() instanceof com.example.app.PremiumRetryPolicy) {
            callback.setReturnValue(100);
        }
        // 其他实例 → 原始方法正常执行
    }
}
```

#### 加载与卸载

```java
// 加载 — 立即应用字节码变换
boolean success = ForgeVM.transformer().load(new ProcessLogger());

// 检查是否已加载
boolean loaded = ForgeVM.transformer().isLoaded(ProcessLogger.class);

// 卸载 — 恢复原始字节码
boolean restored = ForgeVM.transformer().unload(ProcessLogger.class);
```

#### 内部工作原理

Agent 通过遍历 `SystemDictionary → ClassLoaderData → InstanceKlass → 方法数组` 定位目标 `Method*`。读取原始 `ConstMethod` 字节码和 `ConstantPool`，构建包含 hook `MethodRef` 条目的扩展常量池，在指定注入点（`HEAD` 或 `RETURN`）注入 `invokestatic` 字节码，通过 `VirtualAllocEx` 在目标进程中分配新结构并交换指针。原始字节码会备份，可通过 `unload()` 恢复。

## 原生二进制文件解析顺序

ForgeVM 按以下顺序解析 `forgevm_agent.exe` 和 `forgevm_native.dll`：

1. **JAR 内置资源** — 解压到 `<工作目录>/ForgeVM/runtime/win-x64/`，回退到 `%LOCALAPPDATA%/ForgeVM/runtime/win-x64/` 或 `~/.forgevm/runtime/win-x64/`
2. **系统属性** — `-Dforgevm.agent.exe.path=...` / `-Dforgevm.native.dll.path=...`
3. **环境变量** — `FORGEVM_AGENT_EXE_PATH` / `FORGEVM_NATIVE_DLL_PATH`
4. **已知本地路径** — `./native/win-x64/` 和工作目录

通常无需配置。第一个存在的文件路径即被使用。

## 构建

**Java 侧：**

```bash
./gradlew clean jar
```

生成的 JAR 位于 `build/libs/`。

**C++ 侧（Agent 和 DLL）：**

需要自行使用 MSVC 编译 `forgevm_agent.exe` 和 `forgevm_native.dll`。如需打包到 JAR 中，将编译产物放入 `src/main/resources/native/win-x64/`。

## Agent 状态

| 状态 | 含义 |
|---|---|
| `FULL`        | Agent 运行中，进程句柄已打开，结构映射已加载，压缩参数已解析                |
| `RESTRICTED`  | Agent 运行中但权限受限（无 `SeDebugPrivilege`）                              |
| `UNAVAILABLE` | Agent 启动或初始化失败 — 所有需要 Agent 的操作将抛出 `ForgeVMException`      |

## 日志

所有日志统一写入 `ForgeVM/logs/`（相对于工作目录）：

- `fvm-agent.log` — Agent 完整生命周期（启动、bootstrap、命令处理、关闭）
- `fvm-transform.log` — Transform 模块细节（方法定位、字节码重写、内存操作）

## 许可证

MIT
