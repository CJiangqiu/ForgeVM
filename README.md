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
    implementation 'com.github.CJiangqiu:ForgeVM:v0.5.0'
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

Two launch policies:

```java
ForgeVM.launch();              // SILENT — no elevation prompt
ForgeVM.launch(ForgeVM.PROMPT); // PROMPT — shows a UAC dialog to request higher privileges
```

### 3. Use the API

```java
// Memory — write fields by path chain, zero Unsafe
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxHealth", 200);

// Forge — runtime method interception
ForgeVM.forge().load(new MyIngot());

// JVM Control
ForgeVM.exit();                                         // TerminateProcess, no Java API
ForgeVM.banJavaAgent();                                 // block agent attachment
ForgeVM.purgeAgent("com.example.agent.EvilAgent");      // disable a loaded agent
```

## Requirements

- **OS**: Windows x64
- **JDK**: 17+
- **Target JVM**: HotSpot (OpenJDK / Oracle JDK)
- **Privileges**: `SeDebugPrivilege` or administrator rights

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
| `forgevm.core` | Lifecycle, Agent launch, status detection |
| `forgevm.memory` | Field write API — path-based navigation, zero Unsafe |
| `forgevm.forge` | Runtime bytecode rewriting — method interception |
| `forgevm.jvm` | JVM control — exit, Agent lock, Java Agent blocking/purging |
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
```

Supported types: `boolean`, `byte`, `char`, `short`, `int`, `float`, `long`, `double`, null reference.

### JVM Control Module

```java
// Terminate JVM (Agent calls TerminateProcess directly)
ForgeVM.exit();
ForgeVM.exit(1);

// Lock Agent — prevents other processes from commanding it
ForgeVM.lockAgent(60);  // TTL in seconds
ForgeVM.unlockAgent();

// Block Java Agent attachment
ForgeVM.banJavaAgent();                                        // block all
ForgeVM.banJavaAgent(AgentFilter.Blacklist("com.evil."));      // block by package prefix
ForgeVM.banJavaAgent(AgentFilter.Whitelist("com.trusted."));   // only allow matching packages
ForgeVM.banJavaAgent(AgentFilter.JarBlacklist("*evil*"));      // block by JAR path
ForgeVM.banJavaAgent(AgentFilter.JarWhitelist("*trusted*"));   // only allow matching JARs
ForgeVM.unbanJavaAgent();                                      // allow again

// Purge a loaded Java agent entirely
ForgeVM.purgeAgent("com.example.agent.MyAgent");

// Rebind Agent to current JVM (for Shadow JVM switching)
ForgeVM.rebindAgentToCurrentJvm();
```

**`purgeAgent`** disables an already-loaded agent via native memory operations:
1. Nullifies `TransformerManager` inside `InstrumentationImpl`
2. Nullifies the agent's static `Instrumentation` reference
3. Overwrites `agentmain`/`premain` bytecode with bare `return`
4. Forces JIT deoptimization

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
super("Foo", "bar", HEAD);                      // before first instruction (default)
super("Foo", "bar", RETURN);                     // before every return
super("Foo", "bar", INVOKE("targetMethod"));     // before a method call
super("Foo", "bar", FIELD_GET("fieldName"));     // before a field read
super("Foo", "bar", FIELD_PUT("fieldName"));     // before a field write
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
    implementation 'com.github.CJiangqiu:ForgeVM:v0.5.0'
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

两种启动策略：

```java
ForgeVM.launch();              // SILENT — 不弹出提权提示
ForgeVM.launch(ForgeVM.PROMPT); // PROMPT — 弹出 UAC 对话框请求更高权限
```

### 3. 使用 API

```java
// 内存 — 按路径链写入字段，零 Unsafe
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);
ForgeVM.memory().putIntField("com.example.Server", "INSTANCE.config.maxHealth", 200);

// 锻造 — 运行时方法拦截
ForgeVM.forge().load(new MyIngot());

// JVM 控制
ForgeVM.exit();                                         // TerminateProcess，不涉及 Java API
ForgeVM.banJavaAgent();                                 // 拦截 Agent 附着
ForgeVM.purgeAgent("com.example.agent.EvilAgent");      // 禁用已加载的 Agent
```

## 环境要求

- **操作系统**：Windows x64
- **JDK**：17+
- **目标 JVM**：HotSpot（OpenJDK / Oracle JDK）
- **权限**：`SeDebugPrivilege` 或管理员权限

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
| `forgevm.core` | 生命周期、Agent 启动、状态检测 |
| `forgevm.memory` | 字段写入 API — 基于路径导航，零 Unsafe |
| `forgevm.forge` | 运行时字节码重写 — 方法拦截 |
| `forgevm.jvm` | JVM 控制 — 退出、Agent 锁定、Java Agent 拦截/清除 |
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
```

支持类型：`boolean`、`byte`、`char`、`short`、`int`、`float`、`long`、`double`、null 引用。

### JVM 控制模块

```java
// 终止 JVM（Agent 直接调用 TerminateProcess）
ForgeVM.exit();
ForgeVM.exit(1);

// 锁定 Agent — 阻止其他进程对其发送命令
ForgeVM.lockAgent(60);  // TTL 秒数
ForgeVM.unlockAgent();

// 拦截 Java Agent 附着
ForgeVM.banJavaAgent();                                        // 全部拦截
ForgeVM.banJavaAgent(AgentFilter.Blacklist("com.evil."));      // 按包名前缀拦截
ForgeVM.banJavaAgent(AgentFilter.Whitelist("com.trusted."));   // 仅放行匹配的包
ForgeVM.banJavaAgent(AgentFilter.JarBlacklist("*evil*"));      // 按 JAR 路径拦截
ForgeVM.banJavaAgent(AgentFilter.JarWhitelist("*trusted*"));   // 仅放行匹配的 JAR
ForgeVM.unbanJavaAgent();                                      // 解除拦截

// 清除已加载的 Java Agent
ForgeVM.purgeAgent("com.example.agent.MyAgent");

// 将 Agent 重新绑定到当前 JVM（用于 Shadow JVM 切换）
ForgeVM.rebindAgentToCurrentJvm();
```

**`purgeAgent`** 通过原生内存操作彻底禁用已加载的 Agent：
1. 清空 `InstrumentationImpl` 内部的 `TransformerManager`
2. 将 Agent 的静态 `Instrumentation` 引用置为 null
3. 用空 `return` 覆写 `agentmain`/`premain` 方法字节码
4. 强制 JIT 反优化

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
super("Foo", "bar", HEAD);                      // 方法入口（默认）
super("Foo", "bar", RETURN);                     // 每个 return 前
super("Foo", "bar", INVOKE("targetMethod"));     // 方法调用前
super("Foo", "bar", FIELD_GET("fieldName"));     // 字段读取前
super("Foo", "bar", FIELD_PUT("fieldName"));     // 字段写入前
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
