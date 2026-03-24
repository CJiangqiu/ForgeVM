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

Welcome to ForgeVM (FVM). FVM is a low-level tool that manipulates a running JVM through an independent, external FVM Agent process. It uses `sun.misc.Unsafe` for in-process OOP address extraction, then delegates actual memory operations to the Agent via `ReadProcessMemory` / `WriteProcessMemory` and direct HotSpot internal structure traversal. The bytecode transform and memory write paths do not depend on JVMTI or `java.lang.instrument`.

## How It Works

```
Java Application
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java Library (in-process)
    │  Extracts & starts the native Agent executable
    │  Communicates via stdin/stdout JSON protocol
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
| `forgevm.memory` | Field write API — primitive types and object references |
| `forgevm.transform` | Runtime bytecode rewriting — method interception with load/unload |
| `forgevm.jvm` | JVM control — process exit, Agent lock/unlock, rebind |
| `forgevm.util` | Logging, JSON utilities |

## Requirements

- **OS**: Windows x64
- **JDK**: 17+
- **Target JVM**: HotSpot (OpenJDK / Oracle JDK)
- **Privileges**: The Agent requires `SeDebugPrivilege` or administrator rights to open the target process handle

## Usage

### 1. Bootstrap (Required First)

All ForgeVM operations depend on a successful launch. You must call `ForgeVM.launch()` at an appropriate point during your application startup before using any other API. If the launch fails, the system falls back to `JVM_FALLBACK` mode and all Agent-dependent operations will throw `ForgeVMException`.

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

Once the Agent is active, you can write to object fields by descriptor (`ClassName.fieldName`), bypassing access modifiers and reflection:

```java
// Single instance
ForgeVM.memory().putIntField(obj, "com.example.app.UserService.maxRetries", 5);
ForgeVM.memory().putBooleanField(obj, "com.example.app.UserService.active", false);
ForgeVM.memory().putFloatField(obj, "com.example.app.UserService.timeout", 3.5f);

// Batch — one suspend/resume cycle covers all writes
List<UserService> instances = getInstances();
ForgeVM.memory().putBooleanField(instances, "com.example.app.UserService.active", true);

// Object reference (updates GC card table)
ForgeVM.memory().putObjectField(obj, "com.example.app.UserService.delegate", newDelegate);
```

Supported types: `boolean`, `byte`, `char`, `short`, `int`, `float`, `long`, `double`, `Object`.

Internally, the Java side uses `Unsafe` to extract raw OOP addresses from live objects, encodes field values in little-endian hex, and sends them to the Agent. The Agent resolves the field offset by walking the HotSpot Klass hierarchy (`klass pointer → InstanceKlass → field array → offset`), then writes via `WriteProcessMemory`. Field offsets are cached after first resolution.

For batch writes, the Agent suspends all target threads (`NtSuspendThread`) before writing and resumes them after, ensuring consistency across multiple objects.

### 3. JVM Control Module

Basic JVM-level operations through the Agent:

```java
// Terminate JVM (sends exit command to Agent, then Runtime.halt)
ForgeVM.exit();
ForgeVM.exit(1);

// Lock Agent — prevents other processes from commanding it
ForgeVM.lockAgent(60);  // TTL in seconds
ForgeVM.unlockAgent();

// Rebind Agent to current JVM (for Shadow JVM switching)
ForgeVM.rebindAgentToCurrentJvm();
```

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

#### Constructor Variants

```java
// Single method, no-arg, inject at HEAD (simplest)
super("com.example.app.OrderService", "processOrder");

// Multiple candidate names (for obfuscated methods — tried in order)
super("com.example.app.OrderService", new String[]{"processOrder", "a_42"});

// Specify inject point
super("com.example.app.OrderService", "processOrder", InjectPoint.RETURN);

// With parameter types (to distinguish overloads)
super("com.example.app.OrderService", "processOrder", new Class<?>[]{String.class}, InjectPoint.HEAD);
```

#### Controlling Execution Flow via FvmCallback

Inside the hook method, `FvmCallback` controls whether the original method runs:

- **Do nothing** — original method executes normally after the hook returns.
- **`callback.setReturnValue(value)`** — skip the original method and return the given value. Use boxed types for primitives (`5` for `int`, `true` for `boolean`).
- **`callback.cancel()`** — skip the original method for `void` methods.
- **`callback.getInstance()`** — get the `this` reference of the intercepted call, for conditional logic.

```java
// Override a return value
public class RetryCountOverride extends FvmTransformer {
    public RetryCountOverride() {
        super("com.example.app.RetryPolicy",
              new String[]{"getMaxRetries", "a_56"});
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        callback.setReturnValue(10);
    }
}

// Conditionally cancel a void method
public class ShutdownGuard extends FvmTransformer {
    public ShutdownGuard() {
        super("com.example.app.AppLifecycle", "shutdown", InjectPoint.HEAD);
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
        super("com.example.app.RetryPolicy",
              new String[]{"getMaxRetries", "a_56"});
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

## Capability Levels

| Level | Meaning |
|---|---|
| `NATIVE_FULL` | Agent running, process handle open, struct map loaded, compression params resolved |
| `NATIVE_RESTRICTED` | Agent running but with limited privileges (no `SeDebugPrivilege`) |
| `JVM_FALLBACK` | Agent failed to start or initialize — all operations that require the Agent will throw `ForgeVMException` |

## Logging

All logs are written to `ForgeVM/logs/` (relative to the working directory):

- `fvm-agent.log` — Full Agent lifecycle (startup, bootstrap, command handling, shutdown)
- `fvm-transform.log` — Transform module details (method resolution, bytecode rewriting, memory ops)

## License

MIT

---

<a id="中文"></a>

# 中文

欢迎使用 ForgeVM (FVM)。FVM 是一个通过独立的外部 FVM Agent 进程操控运行中的 JVM 的底层工具。进程内通过 `sun.misc.Unsafe` 提取 OOP 地址，再由 Agent 通过 `ReadProcessMemory` / `WriteProcessMemory` 和直接的 HotSpot 内部结构遍历执行实际内存操作。字节码变换和内存写入路径不依赖 JVMTI 或 `java.lang.instrument`。

## 工作原理

```
Java 应用程序
    │
    │  ForgeVM.launch()
    ▼
ForgeVM Java 库（进程内）
    │  解压并启动原生 Agent 可执行文件
    │  通过 stdin/stdout JSON 协议通信
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
| `forgevm.memory` | 字段写入 API — 基本类型和对象引用 |
| `forgevm.transform` | 运行时字节码重写 — 方法拦截，支持加载/卸载 |
| `forgevm.jvm` | JVM 控制 — 进程退出、Agent 锁定/解锁、重绑定 |
| `forgevm.util` | 日志、JSON 工具 |

## 环境要求

- **操作系统**：Windows x64
- **JDK**：17+
- **目标 JVM**：HotSpot（OpenJDK / Oracle JDK）
- **权限**：Agent 需要 `SeDebugPrivilege` 或管理员权限以打开目标进程句柄

## 使用方法

### 1. 启动（必须首先执行）

所有 ForgeVM 操作都依赖于成功启动。你必须在应用启动的合适位置调用 `ForgeVM.launch()`，之后才能使用其他 API。如果启动失败，系统回退到 `JVM_FALLBACK` 模式，所有依赖 Agent 的操作将抛出 `ForgeVMException`。

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

Agent 就绪后，可通过描述符（`类名.字段名`）写入对象字段，绕过访问修饰符和反射限制：

```java
// 单实例
ForgeVM.memory().putIntField(obj, "com.example.app.UserService.maxRetries", 5);
ForgeVM.memory().putBooleanField(obj, "com.example.app.UserService.active", false);
ForgeVM.memory().putFloatField(obj, "com.example.app.UserService.timeout", 3.5f);

// 批量 — 一次挂起/恢复周期覆盖所有写入
List<UserService> instances = getInstances();
ForgeVM.memory().putBooleanField(instances, "com.example.app.UserService.active", true);

// 对象引用（自动更新 GC 卡表）
ForgeVM.memory().putObjectField(obj, "com.example.app.UserService.delegate", newDelegate);
```

支持类型：`boolean`、`byte`、`char`、`short`、`int`、`float`、`long`、`double`、`Object`。

内部实现：Java 侧使用 `Unsafe` 从活跃对象提取原始 OOP 地址，将字段值编码为小端序十六进制，发送给 Agent。Agent 通过遍历 HotSpot Klass 层级（`klass 指针 → InstanceKlass → 字段数组 → 偏移量`）解析字段偏移，然后通过 `WriteProcessMemory` 写入。字段偏移在首次解析后缓存。

批量写入时，Agent 在写入前挂起所有目标线程（`NtSuspendThread`），写入完成后恢复，确保跨多个对象的一致性。

### 3. JVM 控制模块

通过 Agent 执行 JVM 级别的基础操作：

```java
// 终止 JVM（向 Agent 发送退出命令，然后 Runtime.halt）
ForgeVM.exit();
ForgeVM.exit(1);

// 锁定 Agent — 阻止其他进程对其发送命令
ForgeVM.lockAgent(60);  // TTL 秒数
ForgeVM.unlockAgent();

// 将 Agent 重新绑定到当前 JVM（用于 Shadow JVM 切换）
ForgeVM.rebindAgentToCurrentJvm();
```

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

#### 构造函数变体

```java
// 单方法，无参，注入点 HEAD（最简形式）
super("com.example.app.OrderService", "processOrder");

// 多个候选名称（用于混淆后的方法 — 按顺序尝试）
super("com.example.app.OrderService", new String[]{"processOrder", "a_42"});

// 指定注入点
super("com.example.app.OrderService", "processOrder", InjectPoint.RETURN);

// 带参数类型（区分重载方法）
super("com.example.app.OrderService", "processOrder", new Class<?>[]{String.class}, InjectPoint.HEAD);
```

#### 通过 FvmCallback 控制执行流程

在 hook 方法中，`FvmCallback` 控制原始方法是否执行：

- **不做任何操作** — hook 返回后原始方法正常执行。
- **`callback.setReturnValue(value)`** — 跳过原始方法，返回指定值。基本类型使用装箱类型（`int` 用 `5`，`boolean` 用 `true`）。
- **`callback.cancel()`** — 跳过原始方法，用于 `void` 方法。
- **`callback.getInstance()`** — 获取被拦截调用的 `this` 引用，用于条件判断。

```java
// 覆盖返回值
public class RetryCountOverride extends FvmTransformer {
    public RetryCountOverride() {
        super("com.example.app.RetryPolicy",
              new String[]{"getMaxRetries", "a_56"});
    }

    public static void onGetMaxRetries(FvmCallback callback) {
        callback.setReturnValue(10);
    }
}

// 有条件地取消 void 方法
public class ShutdownGuard extends FvmTransformer {
    public ShutdownGuard() {
        super("com.example.app.AppLifecycle", "shutdown", InjectPoint.HEAD);
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
        super("com.example.app.RetryPolicy",
              new String[]{"getMaxRetries", "a_56"});
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

## 能力等级

| 等级 | 含义 |
|---|---|
| `NATIVE_FULL` | Agent 运行中，进程句柄已打开，结构映射已加载，压缩参数已解析 |
| `NATIVE_RESTRICTED` | Agent 运行中但权限受限（无 `SeDebugPrivilege`） |
| `JVM_FALLBACK` | Agent 启动或初始化失败 — 所有需要 Agent 的操作将抛出 `ForgeVMException` |

## 日志

所有日志统一写入 `ForgeVM/logs/`（相对于工作目录）：

- `fvm-agent.log` — Agent 完整生命周期（启动、bootstrap、命令处理、关闭）
- `fvm-transform.log` — Transform 模块细节（方法定位、字节码重写、内存操作）

## 许可证

MIT
