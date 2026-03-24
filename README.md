# ForgeVM

[English](#english) | [中文](#中文)

---

## English

ForgeVM is a Java library for low-level JVM manipulation through an out-of-process native agent. Instead of relying on standard JVM APIs (JVMTI, `java.lang.instrument`, Reflection), ForgeVM spawns a separate native process that directly reads and writes target JVM memory via OS-level primitives (e.g. `WriteProcessMemory` on Windows).

### Architecture

```
┌─────────────────────────────────┐
│         Your Application        │
│    ForgeVM.launch() / memory()  │
│         / transformer()         │
└────────────┬────────────────────┘
             │ stdin/stdout JSON IPC
             ▼
┌─────────────────────────────────┐
│      forgevm_agent.exe          │
│   (separate native process)     │
│                                 │
│  ┌───────────────────────────┐  │
│  │   forgevm_native.dll      │  │
│  │  - memory read/write      │  │
│  │  - thread suspend/resume  │  │
│  │  - bytecode rewriting     │  │
│  └───────────────────────────┘  │
└────────────┬────────────────────┘
             │ Win32 API
             │ (ReadProcessMemory,
             │  WriteProcessMemory,
             │  NtSuspendThread ...)
             ▼
┌─────────────────────────────────┐
│        Target JVM Process       │
└─────────────────────────────────┘
```

The Java library communicates with the agent over stdin/stdout using a line-delimited JSON protocol. The agent performs all privileged operations externally, which avoids the constraints and interception risks of in-process JVM tooling.

### Capability Levels

On launch, ForgeVM probes the environment and reports one of three capability levels:

| Level | Meaning |
|---|---|
| `NATIVE_FULL` | Agent process started, native DLL loaded, struct map ready. All APIs operational. |
| `NATIVE_RESTRICTED` | Agent started but with limited capability (e.g. partial permission). |
| `JVM_FALLBACK` | Agent unavailable. Automatic fallback — the application continues running. |

### Modules

```
forgevm.core       — Lifecycle, launch orchestration, agent session management
forgevm.memory     — Field-level memory write API (MemoryUtil)
forgevm.transform  — Runtime bytecode transformation (FvmTransformer, TransformManager)
forgevm.jvm        — JVM control: process exit, agent lock/unlock, rebind
forgevm.util       — Logging (FvmLog), JSON parsing (JsonUtils)
```

### API

#### Launch

```java
// Default: silent permission policy
ForgeVM.LaunchResult result = ForgeVM.launch();

// Or with UAC-style elevation prompt
ForgeVM.LaunchResult result = ForgeVM.launch(ForgeVM.PROMPT);

// Check result
result.capabilityLevel();  // NATIVE_FULL, NATIVE_RESTRICTED, or JVM_FALLBACK
result.nativeDllActive();  // true if native backend is active
```

No JVM flags, no `-D` parameters, no manual path configuration required. The native binaries are extracted from the JAR at runtime and placed in a local runtime directory.

#### Field Memory Write

Write to object fields by descriptor, bypassing access modifiers and JVM restrictions. The agent resolves field offsets from object headers and writes directly into heap memory.

```java
MemoryUtil mem = ForgeVM.memory();

// Single instance — all primitive types supported
mem.putBooleanField(entity, "com.example.entity.LivingEntity.dead", true);
mem.putIntField(entity, "com.example.entity.LivingEntity.health", 20);
mem.putFloatField(entity, "com.example.entity.LivingEntity.speed", 0.3f);

// Object reference (updates GC card table)
mem.putObjectField(entity, "com.example.entity.Entity.level", newLevel);

// Batch — operates on any Iterable, single suspend/resume cycle
List<LivingEntity> entities = getAllEntities();
mem.putBooleanField(entities, "com.example.entity.LivingEntity.dead", false);
```

Batch operations suspend all target JVM threads once, perform all writes, then resume — the caller does not manage synchronization.

#### Bytecode Transformation

Rewrite method bytecode at runtime without `java.lang.instrument` or JVMTI. The agent patches compiled method code directly in memory.

```java
// 1. Define a transformer
public class TickLogger extends FvmTransformer {
    public TickLogger() {
        super("com.example.engine.GameLoop", "tick");
    }

    public static void onTick(FvmCallback callback) {
        System.out.println("tick called on: " + callback.getInstance());
        // Not calling cancel() or setReturnValue() → original method runs normally
    }
}

// 2. Load it
ForgeVM.transformer().load(new TickLogger());

// 3. Unload to restore original bytecode
ForgeVM.transformer().unload(TickLogger.class);
```

Transformers support:
- Multiple method name candidates (for obfuscated targets): `new String[]{"tick", "m_1234"}`
- Parameter type matching to distinguish overloads: `new Class<?>[]{float.class}`
- Injection at `HEAD` (before method body) or `RETURN` (before return instructions)
- Return value override via `callback.setReturnValue(value)`
- Method cancellation via `callback.cancel()` (void methods)

#### JVM Control

```java
// Terminate the JVM via the agent (sends exit command, then halts)
ForgeVM.exit();
ForgeVM.exit(1);

// Lock the agent for exclusive access (TTL in seconds)
ForgeVM.lockAgent(30);
ForgeVM.unlockAgent();

// Rebind agent to current JVM (for Shadow JVM switch scenarios)
ForgeVM.rebindAgentToCurrentJvm();
```

### Thread Safety During Memory Operations

- **Single-instance writes** may skip thread suspension for minimal latency (~3ms saved), accepting a small GC window risk.
- **Batch writes** (Iterable parameter) always suspend target threads for the duration of the write sequence using `NtSuspendThread` / `NtResumeThread` — kernel-level, not interceptable by in-process hooks.

### Native Binary Resolution Order

1. Bundled resource inside the JAR (`/native/win-x64/`)
2. System property (`-Dforgevm.native.dll.path=...`)
3. Environment variable (`FORGEVM_NATIVE_DLL_PATH`)
4. Known local paths (`./native/win-x64/`, `./`)

The same order applies to the agent executable.

### Requirements

- Java 17+
- Windows x64 (current native backend)
- The agent process requires sufficient OS-level permission to read/write the target JVM's memory

### Build

```bash
./gradlew build
```

### License

[MIT](LICENSE.txt) — Copyright © 2026 CJiangqiu

---

## 中文

ForgeVM 是一个通过外部进程原生代理实现 JVM 底层操作的 Java 库。它不依赖标准 JVM API（JVMTI、`java.lang.instrument`、反射），而是启动一个独立的原生进程，通过操作系统级原语（如 Windows 上的 `WriteProcessMemory`）直接读写目标 JVM 内存。

### 架构

```
┌─────────────────────────────────┐
│          你的应用程序             │
│    ForgeVM.launch() / memory()  │
│         / transformer()         │
└────────────┬────────────────────┘
             │ stdin/stdout JSON IPC
             ▼
┌─────────────────────────────────┐
│      forgevm_agent.exe          │
│      （独立原生进程）              │
│                                 │
│  ┌───────────────────────────┐  │
│  │   forgevm_native.dll      │  │
│  │  - 内存读写                │  │
│  │  - 线程挂起/恢复           │  │
│  │  - 字节码改写              │  │
│  └───────────────────────────┘  │
└────────────┬────────────────────┘
             │ Win32 API
             │ (ReadProcessMemory,
             │  WriteProcessMemory,
             │  NtSuspendThread ...)
             ▼
┌─────────────────────────────────┐
│         目标 JVM 进程            │
└─────────────────────────────────┘
```

Java 库通过 stdin/stdout 使用行分隔 JSON 协议与 Agent 通信。Agent 在进程外执行所有特权操作，避开了进程内 JVM 工具的限制和被拦截风险。

### 能力等级

启动时，ForgeVM 探测运行环境并报告以下三种能力等级之一：

| 等级 | 含义 |
|---|---|
| `NATIVE_FULL` | Agent 进程已启动，原生 DLL 已加载，结构映射就绪。所有 API 可用。 |
| `NATIVE_RESTRICTED` | Agent 已启动但能力受限（如部分权限不足）。 |
| `JVM_FALLBACK` | Agent 不可用。自动回退——应用继续正常运行。 |

### 模块

```
forgevm.core       — 生命周期、启动编排、Agent 会话管理
forgevm.memory     — 字段级内存写入 API（MemoryUtil）
forgevm.transform  — 运行时字节码改写（FvmTransformer、TransformManager）
forgevm.jvm        — JVM 控制：进程退出、Agent 锁定/解锁、重绑定
forgevm.util       — 日志（FvmLog）、JSON 解析（JsonUtils）
```

### API

#### 启动

```java
// 默认静默权限策略
ForgeVM.LaunchResult result = ForgeVM.launch();

// 带 UAC 式提权提示
ForgeVM.LaunchResult result = ForgeVM.launch(ForgeVM.PROMPT);

// 检查结果
result.capabilityLevel();  // NATIVE_FULL、NATIVE_RESTRICTED 或 JVM_FALLBACK
result.nativeDllActive();  // 原生后端是否激活
```

无需 JVM 启动参数，无需 `-D` 配置，无需手动指定路径。原生二进制文件在运行时从 JAR 中提取并放置到本地运行目录。

#### 字段内存写入

通过字段描述符写入对象字段，绕过访问修饰符和 JVM 限制。Agent 从对象头解析字段偏移量，直接写入堆内存。

```java
MemoryUtil mem = ForgeVM.memory();

// 单实例——支持所有基本类型
mem.putBooleanField(entity, "com.example.entity.LivingEntity.dead", true);
mem.putIntField(entity, "com.example.entity.LivingEntity.health", 20);
mem.putFloatField(entity, "com.example.entity.LivingEntity.speed", 0.3f);

// 对象引用（自动更新 GC 卡表）
mem.putObjectField(entity, "com.example.entity.Entity.level", newLevel);

// 批量——接受任意 Iterable，单次挂起/恢复周期
List<LivingEntity> entities = getAllEntities();
mem.putBooleanField(entities, "com.example.entity.LivingEntity.dead", false);
```

批量操作将目标 JVM 所有线程挂起一次，执行全部写入后恢复——调用方无需管理同步。

#### 字节码改写

在运行时改写方法字节码，无需 `java.lang.instrument` 或 JVMTI。Agent 直接在内存中修改已编译的方法代码。

```java
// 1. 定义 Transformer
public class TickLogger extends FvmTransformer {
    public TickLogger() {
        super("com.example.engine.GameLoop", "tick");
    }

    public static void onTick(FvmCallback callback) {
        System.out.println("tick called on: " + callback.getInstance());
        // 不调用 cancel() 或 setReturnValue() → 原方法正常执行
    }
}

// 2. 加载
ForgeVM.transformer().load(new TickLogger());

// 3. 卸载以恢复原始字节码
ForgeVM.transformer().unload(TickLogger.class);
```

Transformer 支持：
- 多方法名候选（用于混淆目标）：`new String[]{"tick", "m_1234"}`
- 参数类型匹配以区分重载：`new Class<?>[]{float.class}`
- 在 `HEAD`（方法体前）或 `RETURN`（return 指令前）注入
- 通过 `callback.setReturnValue(value)` 覆盖返回值
- 通过 `callback.cancel()` 取消方法执行（void 方法）

#### JVM 控制

```java
// 通过 Agent 终止 JVM（发送退出命令后 halt）
ForgeVM.exit();
ForgeVM.exit(1);

// 锁定 Agent 独占访问（TTL 秒）
ForgeVM.lockAgent(30);
ForgeVM.unlockAgent();

// 将 Agent 重绑定到当前 JVM（用于 Shadow JVM 切换场景）
ForgeVM.rebindAgentToCurrentJvm();
```

### 内存操作的线程安全

- **单实例写入**可跳过线程挂起以降低延迟（节省约 3ms），代价是极小的 GC 窗口风险。
- **批量写入**（Iterable 参数）始终在整个写入序列期间挂起目标线程，使用 `NtSuspendThread` / `NtResumeThread`——内核级调用，不会被进程内 hook 拦截。

### 原生二进制查找顺序

1. JAR 内置资源（`/native/win-x64/`）
2. 系统属性（`-Dforgevm.native.dll.path=...`）
3. 环境变量（`FORGEVM_NATIVE_DLL_PATH`）
4. 已知本地路径（`./native/win-x64/`、`./`）

Agent 可执行文件的查找顺序相同。

### 环境要求

- Java 17+
- Windows x64（当前原生后端）
- Agent 进程需要足够的操作系统级权限来读写目标 JVM 内存

### 构建

```bash
./gradlew build
```

### 许可证

[MIT](LICENSE.txt) — Copyright © 2026 CJiangqiu
