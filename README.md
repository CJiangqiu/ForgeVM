<a id="中文"></a>

<div align="center">

# ForgeVM

[![Windows x64](https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square&logo=windows11&logoColor=white)](#运行条件)
[![Java 17](https://img.shields.io/badge/build-Java%2017-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](#运行条件)
[![MIT License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE.txt)
[![JitPack](https://jitpack.io/v/CJiangqiu/ForgeVM.svg?style=flat-square)](https://jitpack.io/#CJiangqiu/ForgeVM)

[中文](#中文) | [English](#english)

</div>

ForgeVM 是一个面向 Windows x64 JVM 的进程外运行时控制库。它由 Java API、独立 agent 和 native DLL 组成：Java 侧描述操作，agent 在 JVM 外执行进程控制与内存访问，native DLL 负责识别 HotSpot 结构、安装 hook 和执行字节码计划。

它适合需要在不使用 `Unsafe`、`Instrumentation` 或普通 JVMTI 工作流的前提下，对运行中的 JVM 做受控修改、拦截和生命周期保护的场景。它不是通用 Java 框架；使用前请确保运行环境适合 ForgeVM。

## 目录

- [运行条件](#运行条件)
- [安装](#安装)
- [快速开始](#快速开始)
- [启动策略与 JVM 守护](#启动策略与-jvm-守护)
- [窗口与命令](#窗口与命令)
- [安全拦截](#安全拦截)
- [JVM 重启](#jvm-重启)
- [内存字段操作](#内存字段操作)
- [Forge 方法注入](#forge-方法注入)
- [日志、构建与排错](#日志构建与排错)

## 运行条件

- Windows x64；agent 使用 Windows 进程、命名管道和 HotSpot 相关实现。
- 使用与目标 JVM 匹配的 ForgeVM native 资源；目前发布资源面向 x64。
- 构建项目使用 JDK 17。目标 JVM 的兼容性取决于 native 结构识别结果，而不是仅由 Java 编译版本决定。
- agent 必须能够打开并操作目标 JVM。权限、完整性级别、杀毒软件或受保护进程策略都可能阻止启动。

ForgeVM 会将运行时文件和日志写入当前工作目录下的 `ForgeVM/`。开发时可通过 `forgevm.agent.exe.path`、`forgevm.native.dll.path` 系统属性，或相应环境变量指定本地 agent/DLL 路径。

## 安装

通过 JitPack 使用发行版本时，先添加仓库，再替换 `VERSION` 为所需的 tag 或版本号：

```gradle
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.CJiangqiu:ForgeVM:VERSION")
}
```

可用版本和 Maven 坐标以 [JitPack 页面](https://jitpack.io/#CJiangqiu/ForgeVM) 为准。开发本仓库时直接使用 Gradle：

```powershell
.\gradlew.bat test
```

## 快速开始

将 ForgeVM 加入项目后，在尽可能早的初始化阶段启动：

```java
import forgevm.core.ForgeVM;
import forgevm.core.ForgeVMOptions;

ForgeVM.LaunchResult result = ForgeVM.launch(ForgeVMOptions.builder()
    .window(true)
    .build());

if (!result.nativeDllActive()) {
    throw new IllegalStateException("ForgeVM unavailable: " + result.reason());
}
```

`LaunchResult` 是启动结果的唯一依据。启动失败时不要继续调用内存、Forge 或安全拦截 API。

旧入口 `ForgeVM.launch()` 和 `ForgeVM.launch(boolean)` 仍可运行，但已经标记为弃用；新代码应始终显式声明启动策略。

## 启动策略与 JVM 守护

`ForgeVMOptions` 在首次创建 agent 时生效，后续 `launch(...)` 会复用已有 agent，不会更改其策略。

```java
ForgeVM.launch(ForgeVMOptions.builder()
    .window(true)   // 显示 FVM 实时状态和命令窗口
    .lockJvm(true)  // 保护 JVM：DACL 终止锁 + halt 拦截 + 崩溃复活
    .build());
```

两个选项的含义如下：

| 选项 | 默认值 | 作用 |
| --- | --- | --- |
| `window` | `false` | 打开 agent 的状态与命令窗口。非 FVM relaunch 导致 JVM 消失时，agent 记录日志后干净退出。 |
| `lockJvm` | `false` | 开启 JVM 生命周期守护，强制打开窗口。包含 DACL 终止权限锁、`Shutdown.halt()` 内进程拦截、以及崩溃后最多 4 次连续复活。 |

开启 `lockJvm` 后，agent 会先保留一个仅供 FVM 使用的终止句柄，再拒绝后续句柄请求 `PROCESS_TERMINATE` 权限；同时 hook `jvm.dll!JVM_Halt` 阻断 Java 层 `Shutdown.halt()` 自尽路径。FVM 授权退出通过保留句柄的 `TerminateProcess`，不经过 `JVM_Halt`，不受影响。

若 JVM 仍因崩溃、已有终止句柄、管理员权限或内核级手段而结束，watchdog 会重新创建 JVM，重新绑定 agent，并在 `jvm.dll` 可用后恢复已启用的 hook。每次成功 bootstrap 后重置连续死亡计数器；连续 4 次复活失败则 agent 放行 halt hook、记录日志后退出。

`window` 模式（不开启 `lockJvm`）：FVM relaunch 正常维持 agent 跨 JVM 存活。若 JVM 非 relaunch 场景下消失，agent 记录日志后干净退出，不残留僵尸进程。

## 窗口与命令

状态窗口分为三部分：

- 左侧：agent、JVM 和 guard 的持续事件流；
- 右侧：最近一次命令的完整结果；
- 底部：命令输入。输入 `/` 会列出可点击补全项，Tab 也可补全。

命令不会混入右侧以外的结果区；左侧只留下简短审计记录。

| 命令 | 行为 |
| --- | --- |
| `/help` | 在右侧显示每条命令的说明。 |
| `/status` | 显示 JVM PID、生命周期模式、窗口状态和 JVM 锁定状态。 |
| `/clear` | 清空左侧状态流。 |
| `/stop jvm` | 授权停止 JVM 并解除 guard。lockJvm 模式下 agent 保留窗口；仅 window 模式下 agent 一并退出。 |
| `/stop fvm` | 只停止 agent，JVM 保持运行但不再受 FVM 保护。 |
| `/stop` | 停止 JVM 与 agent。 |

停止命令不要求二次确认。`/stop jvm` 是 guard 模式下的正常 JVM 退出通道；它会先写入授权退出状态并放行 halt hook，防止 watchdog 立即拉起一个新的 JVM。

## 安全拦截

安全 API 会在目标 JVM 内安装 native hook，应在待控制操作发生前调用。它们控制后续请求，不提供对已执行代码、已创建进程或已取得 `jvmtiEnv*` 的通用回滚。

路径规则不区分 ASCII 大小写。前导 `*` 表示允许任意前缀，尾随 `*` 表示允许任意后缀；未使用相应通配符时，路径起始或结尾会被锚定。例如 `*\\java.exe` 只匹配以 `\\java.exe` 结尾的路径，不匹配 `java.exe.payload`。内部 `*` 和 `?` 不能由驻留 native 匹配器表达；遇到此类规则时，`ban...` 调用失败，不会静默改写策略。

### Java agent

```java
import forgevm.jvm.AgentFilter;

ForgeVM.banJavaAgent(AgentFilter.Blacklist("*tool_musics_egg*"));
```

无参 `banJavaAgent()` 会先请求处理已加载 agent，再阻止后续 attach；带过滤器的版本只处理匹配项。已有处理依赖 HotSpot 元数据和已知 `Instrumentation` 字段，清理部分引用与方法体。这是实现相关的隔离尝试，不能保证停止 agent 创建的线程、native 代码、保留引用或已经完成的类修改。`unbanJavaAgent()` 仅移除未来 attach 的拦截。

### native DLL、JVMTI 与子进程

```java
import forgevm.jvm.JvmtiFilter;
import forgevm.jvm.NativeFilter;
import forgevm.jvm.ProcessFilter;

ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*", "*inject*"));
ForgeVM.banJvmti(JvmtiFilter.Whitelist("*trusted-profiler*"));
ForgeVM.banProcessCreate(ProcessFilter.Blacklist("*java.exe", "*javaw.exe"));
```

对应的解除 API 为 `unbanNativeLoad()`、`unbanJvmti()` 和 `unbanProcessCreate()`。

| API | native 拦截点 | 对后续请求的作用 |
| --- | --- | --- |
| `banNativeLoad` | `ntdll!LdrLoadDll`，以及 `NtCreateSection` 映像节 guard | 拒绝匹配的加载器 DLL 加载与映像节创建请求。 |
| `banJvmti` | `JavaVM::GetEnv` | 拒绝请求接口为 JVMTI 的调用；调用方按返回地址所在 native 模块判定。 |
| `banProcessCreate` | `ntdll!NtCreateUserProcess`，以及 `NtCreateProcessEx` guard | 拒绝匹配的子进程创建请求。 |
| `banJavaAgent` | HotSpot `JVM_EnqueueOperation` | 拒绝符合当前策略的后续 Java agent 入队操作。 |

JNA 发起的 JVMTI 获取仍会经过 `JavaVM::GetEnv`。规则应匹配实际发起 native 调用的模块（通常为 JNA 的 native dispatch 库），而不是 Java 调用者所在的 jar。

### 范围与边界

ForgeVM 是同权限 Windows 用户态机制，不声称隔离已经在目标进程执行的 native 代码、直接系统调用、手动映射、既有进程句柄、管理员级控制或内核代码。若已确认进程受污染，可靠的重置方式是在不信任应用代码执行前安装策略并受控重启 JVM。

## JVM 重启

受控重启的主 API 是 `ForgeVM.relaunch(RelaunchSpec)`。它由 supervisor 使用首次启动时保存的启动基线构造替代 JVM，并将替代 JVM 交接给同一 ForgeVM agent。成功时当前 JVM 被终止，因此方法不会返回；创建、校验或交接失败时抛出 `RelaunchException`，当前 JVM 保持运行。

```java
import forgevm.jvm.JvmtiFilter;
import forgevm.jvm.ProcessFilter;
import forgevm.jvm.RelaunchSpec;

import java.time.Duration;

try {
    RelaunchSpec spec = RelaunchSpec.builder()
        .existingAgents(RelaunchSpec.ExistingAgentPolicy.DROP_ALL)
        .jvmtiFilter(JvmtiFilter.Blacklist("*jnidispatch*"))
        .processFilter(ProcessFilter.Blacklist("*javaw.exe"))
        .handoff(RelaunchSpec.HandoffPoint.PROCESS_STARTED, Duration.ofSeconds(30))
        .build();
    ForgeVM.relaunch(spec); // 成功时不返回
} catch (forgevm.jvm.RelaunchException e) {
    throw new IllegalStateException("relaunch failed: " + e.getMessage(), e);
}
```

| 字段 | 语义 |
| --- | --- |
| `existingAgents(...)` | `DROP_ALL` 移除继承的 `-javaagent`、`-agentpath` 与 `-agentlib`；`FILTER` 使用提供的 `AgentFilter` / `NativeFilter` 筛选；`PRESERVE` 保留继承选项。 |
| `trustedNativeAgent(...)` / `trustedJavaAgent(...)` | 在创建替代 JVM 前校验指定文件的 SHA-256，并在继承 agent 选项处理后插入该 agent。 |
| 四种 `...Filter(...)` | 为替代 JVM 提供 Java agent、native load、JVMTI 获取和子进程创建策略；它们不撤销当前 JVM 中已经发生的对应操作。 |
| `sanitizeEnvironment(...)` | 控制是否使用净化后的继承环境；默认开启。 |
| `rejectArgumentFiles(...)` | 控制是否拒绝命令行中的 `@argument-file`；默认开启。 |
| `handoff(...)` | `PROCESS_STARTED` 在替代进程启动后提交；`POLICY_APPLIED` 仅在受信任 Java agent 报告策略已应用后提交，且要求配置 `trustedJavaAgent`。 |

`ForgeVM.relaunch()` 及其接收过滤器的重载保留为简化 API。它们适用于只需传递过滤规则的场景；需要声明继承 agent、受信任 agent、环境或交接策略时，应使用 `RelaunchSpec`。`ForgeVM.relaunchGeneration()` 返回当前重启链代数。业务内存状态不会因重启自动保留，应由应用自身恢复。

## 内存字段操作

`ForgeVM.memory()` 提供基于“类名 + 字段链”的字段写入。解析和写入都由 agent 在进程外完成。

```java
// 静态字段
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);

// 从静态根字段开始的对象链
ForgeVM.memory().putBooleanField(
    "com.example.Server",
    "INSTANCE.config.maintenance",
    true
);

// 写入对象引用或 null
ForgeVM.memory().putObjectField("com.example.Server", "INSTANCE.config", newConfig);
ForgeVM.memory().putNullField("com.example.Server", "INSTANCE.pendingJob");
```

支持 `boolean`、整数、浮点数、`char`、对象引用和 `null`。字段链以静态字段为根并用 `.` 分隔。写入错误的类、字段、对象布局或生命周期不受 Java 类型系统保护，可能造成 JVM 崩溃或静默数据损坏；应只对已验证的 HotSpot 目标和稳定字段使用。

## Forge 方法注入

Forge 是运行时方法注入层。创建一个 `FvmIngot` 子类，声明目标类、方法候选和注入位置，再提供一个 `public static` 的 `FvmCallback` 方法。

```java
import forgevm.forge.FvmCallback;
import forgevm.forge.FvmIngot;

public final class LoginAudit extends FvmIngot {
    public LoginAudit() {
        // 逗号分隔的候选名可同时兼容映射名与混淆名。
        super("com.example.LoginService", "login,m_12345_");
    }

    public static void onLogin(FvmCallback callback) {
        System.out.println("login: " + callback.getInstance());
    }
}

boolean installed = ForgeVM.forge().load(new LoginAudit());
boolean removed = ForgeVM.forge().unload(LoginAudit.class);
```

常用注入点：

| 写法 | 含义 |
| --- | --- |
| `HEAD` | 方法第一条指令前。 |
| `RETURN` | 每个 `return` 指令前。 |
| `INVOKE("method(F)")` | 指定方法调用前。 |
| `FIELD_GET("health:F")` | 指定字段读取前。 |
| `FIELD_PUT("health:F")` | 指定字段写入前。 |
| `NEW("java.util.ArrayList")` | 指定对象创建前。 |

回调不设置返回值时，原方法继续执行；`callback.cancel()` 用于取消 void 方法；`callback.setReturnValue(value)` 用于跳过原方法并返回值。注入方法必须是 `public static void method(FvmCallback)`。

同一目标类的卸载以类级别回滚进行。若多个 ingot 作用于该类，ForgeVM 会先回滚类计划，再重新应用仍应保留的 ingot。批量 `load(...)` 优先以一个计划提交，减少重复挂起与去优化。

## 日志、构建与排错

日志位于：

```text
ForgeVM/logs/fvm-agent.log
ForgeVM/logs/fvm-transform.log
```

排查顺序：

1. 检查 `LaunchResult.reason()`；
2. 查看 `fvm-agent.log` 中的 `bootstrap`、`guard`、`relaunch`、`CMD` 记录；
3. 查看 `fvm-transform.log` 中 native 结构识别和 hook 安装记录；
4. 在窗口执行 `/status`，确认 PID、生命周期与锁定状态；
5. 检查部署的 `forgevm_agent.exe` 与 `forgevm_native.dll` 是否来自同一构建。

Java 部分可通过 Gradle 验证：

```powershell
.\gradlew.bat test
```

native agent 需要 MSVC 的 x64 工具链。示例命令如下，产物会写入 `build/native`：

```powershell
cl.exe /std:c++17 /EHsc /utf-8 /O2 `
  /Fe:build\native\forgevm_agent.exe `
  src\main\c++\cpp\forgevm_agent.cpp `
  /link ole32.lib oleaut32.lib wbemuuid.lib psapi.lib advapi32.lib shell32.lib gdi32.lib
```

发布前必须将重新编译的 agent 与匹配的 native DLL 一起更新到资源目录；只替换其中一个会造成协议或导出符号不匹配。

## 许可

本项目采用 [MIT License](LICENSE.txt)。

---

<a id="english"></a>

<div align="center">

# ForgeVM · English

[![Windows x64](https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square&logo=windows11&logoColor=white)](#requirements)
[![Java 17](https://img.shields.io/badge/build-Java%2017-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](#requirements)
[![MIT License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE.txt)
[![JitPack](https://jitpack.io/v/CJiangqiu/ForgeVM.svg?style=flat-square)](https://jitpack.io/#CJiangqiu/ForgeVM)

[中文](#中文) | [English](#english)

</div>

ForgeVM is an out-of-process runtime-control library for Windows x64 JVMs. A Java API describes an operation; a standalone agent performs process control and memory work outside the JVM; the native DLL recognizes HotSpot structures, installs hooks, and applies bytecode plans.

It is intended for controlled runtime modification, interception, and JVM-lifecycle protection where ordinary `Unsafe`, `Instrumentation`, or a conventional JVMTI workflow is not the chosen integration point. It is not a general-purpose Java framework; ensure the runtime environment is appropriate for ForgeVM before use.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Startup policy and JVM guard](#startup-policy-and-jvm-guard)
- [Window and commands](#window-and-commands)
- [Security interception](#security-interception)
- [JVM relaunch](#jvm-relaunch)
- [Field memory operations](#field-memory-operations)
- [Forge method injection](#forge-method-injection)
- [Logs, build, and troubleshooting](#logs-build-and-troubleshooting)

## Requirements

- Windows x64. The agent uses Windows processes, named pipes, and HotSpot-specific implementation details.
- A ForgeVM native resource compatible with the target JVM and x64 process.
- JDK 17 to build this repository. Target-JVM compatibility is determined by native structure discovery, not only by the Java compiler level.
- Permission for the agent to open and operate on the target JVM. Process integrity, endpoint protection, or protected-process policy may prevent startup.

Runtime files and logs are written under `ForgeVM/` in the current working directory. For development, `forgevm.agent.exe.path` and `forgevm.native.dll.path` system properties, or their matching environment variables, can point to local binaries.

## Installation

Use JitPack by adding the repository and replacing `VERSION` with the desired release tag or version:

```gradle
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.CJiangqiu:ForgeVM:VERSION")
}
```

See the [JitPack page](https://jitpack.io/#CJiangqiu/ForgeVM) for available coordinates. To work on this repository directly:

```powershell
.\gradlew.bat test
```

## Quick start

Start ForgeVM as early as practical in application initialization:

```java
import forgevm.core.ForgeVM;
import forgevm.core.ForgeVMOptions;

ForgeVM.LaunchResult result = ForgeVM.launch(ForgeVMOptions.builder()
    .window(true)
    .build());

if (!result.nativeDllActive()) {
    throw new IllegalStateException("ForgeVM unavailable: " + result.reason());
}
```

`LaunchResult` is the authoritative startup result. Do not call memory, Forge, or interception APIs after a failed launch. The legacy `ForgeVM.launch()` and `ForgeVM.launch(boolean)` methods are retained for compatibility but deprecated; new code should declare an explicit policy.

## Startup policy and JVM guard

`ForgeVMOptions` is consumed when the first agent is created. Later `launch(...)` calls reuse that agent and do not change its policy.

```java
ForgeVM.launch(ForgeVMOptions.builder()
    .window(true)
    .lockJvm(true)
    .build());
```

| Option | Default | Meaning |
| --- | --- | --- |
| `window` | `false` | Opens the agent status and command window. Agent exits cleanly (with a log entry) when the JVM disappears without a relaunch handoff. |
| `lockJvm` | `false` | Protects the JVM lifecycle, forces the window on. Includes DACL termination lock, `Shutdown.halt()` interception, and up to 4 consecutive crash-recovery attempts. |

With `lockJvm`, the agent retains an FVM-only termination handle, then denies `PROCESS_TERMINATE` to subsequently opened handles; it also hooks `jvm.dll!JVM_Halt` to block in-process `Shutdown.halt()`. FVM-authorized exits go through `TerminateProcess` on the retained handle, never touching `JVM_Halt`.

If the JVM still exits through a crash, an existing handle, administrator privileges, or kernel-level code, the watchdog recreates it, rebinds the agent, and restores hooks once `jvm.dll` is available. Each successful bootstrap resets the consecutive-death counter. After 4 consecutive failed recoveries the agent releases the halt hook, logs the event, and exits.

Window-only mode (without `lockJvm`): relaunch keeps the agent alive across JVM generations as normal. If the JVM disappears without a relaunch, the agent logs the event and exits — no zombie processes.

## Window and commands

The window has a continuous status stream on the left, full output for the latest command on the right, and a command input at the bottom. Typing `/` shows clickable completions; Tab also completes.

| Command | Action |
| --- | --- |
| `/help` | Shows a description for every command in the right pane. |
| `/status` | Shows JVM PID, lifecycle mode, window, and guard state. |
| `/clear` | Clears the left status stream. |
| `/stop jvm` | Authorizes and stops the JVM, disables guard. In lockJvm mode the agent keeps its window; in window-only mode the agent exits too. |
| `/stop fvm` | Stops only the agent; the JVM continues without FVM protection. |
| `/stop` | Stops both JVM and agent. |

`/stop jvm` is the normal JVM-exit path while guard is enabled. It sets the authorized-exit state and releases the halt hook before the process stops, so watchdog does not immediately recreate it.

## Security interception

The interception APIs install in-process native hooks in the target JVM. Install
them before the operation to be controlled. They govern subsequent requests;
they do not provide a general rollback mechanism for code, processes, or JVMTI
environments that already exist.

All path filters are case-insensitive. A leading `*` permits an arbitrary path
prefix and a trailing `*` permits an arbitrary suffix. Without the respective
wildcard, the beginning or end is anchored. For example, `*\\java.exe` matches
paths ending in `\\java.exe`; it does not match `java.exe.payload`. Internal
`*` and `?` wildcards are not represented by the resident native matcher. A
rule that cannot be represented causes the `ban...` call to fail rather than
silently applying a different rule.

```java
import forgevm.jvm.AgentFilter;
import forgevm.jvm.JvmtiFilter;
import forgevm.jvm.NativeFilter;
import forgevm.jvm.ProcessFilter;

ForgeVM.banJavaAgent(AgentFilter.Blacklist("*tool_musics_egg*"));
ForgeVM.banNativeLoad(NativeFilter.Blacklist("*cheat*", "*inject*"));
ForgeVM.banJvmti(JvmtiFilter.Whitelist("*trusted-profiler*"));
ForgeVM.banProcessCreate(ProcessFilter.Blacklist("*java.exe", "*javaw.exe"));
```

| API | Native interception point | Effect on later requests |
| --- | --- | --- |
| `banJavaAgent` | HotSpot `JVM_EnqueueOperation` | Rejects subsequent Java-agent enqueue operations matching the active policy. |
| `banNativeLoad` | `ntdll!LdrLoadDll`, with an `NtCreateSection` image-section guard | Rejects matching later loader-based native-library loads and image-section creation requests. |
| `banJvmti` | `JavaVM::GetEnv` | Rejects later requests whose requested interface is JVMTI. The decision is made from the native module containing the call return address. |
| `banProcessCreate` | `ntdll!NtCreateUserProcess`, with an `NtCreateProcessEx` guard | Rejects matching later child-process creation requests. |

`unbanJavaAgent()`, `unbanNativeLoad()`, `unbanJvmti()`, and
`unbanProcessCreate()` remove the corresponding future-request hooks when the
native operation succeeds. They do not undo a previous Java-agent attach,
loaded module, acquired `jvmtiEnv*`, or created child process.

`banJavaAgent()` also invokes the existing-agent purge routine before installing
the future-attach hook. That routine identifies a limited set of loaded agents
by HotSpot metadata and known `Instrumentation` fields, then clears selected
references and method bodies. It is an implementation-specific containment
attempt, not a general Java-agent unload facility: it cannot guarantee removal
of agent-created threads, native code, retained references, or class changes
already applied by an agent.

For JNA-based JVMTI acquisition, the `JavaVM::GetEnv` call is still intercepted.
The policy must match the native module that performs the call (normally JNA's
native dispatch library), rather than the Java archive containing the caller.

### Scope and limitations

ForgeVM is a Windows user-mode mechanism operating against a process of the
same privilege level. It does not claim to provide containment against native
code already executing in the target process, direct system calls, manual
mapping, pre-existing process handles, administrator-level control, or kernel
code. A known compromised process should be treated as contaminated. The
reliable reset operation is a controlled relaunch with policies installed before
untrusted application code is allowed to run.

## JVM relaunch

`ForgeVM.relaunch(RelaunchSpec)` is the primary controlled-relaunch API. The
supervisor constructs the replacement JVM from the launch baseline captured at
first startup and hands it to the same ForgeVM agent. On success the current JVM
is terminated and the method does not return. Creation, verification, or
handoff failure throws `RelaunchException` while the current JVM remains alive.

```java
import forgevm.jvm.JvmtiFilter;
import forgevm.jvm.ProcessFilter;
import forgevm.jvm.RelaunchSpec;

import java.time.Duration;

try {
    RelaunchSpec spec = RelaunchSpec.builder()
        .existingAgents(RelaunchSpec.ExistingAgentPolicy.DROP_ALL)
        .jvmtiFilter(JvmtiFilter.Blacklist("*jnidispatch*"))
        .processFilter(ProcessFilter.Blacklist("*javaw.exe"))
        .handoff(RelaunchSpec.HandoffPoint.PROCESS_STARTED, Duration.ofSeconds(30))
        .build();
    ForgeVM.relaunch(spec); // does not return on success
} catch (forgevm.jvm.RelaunchException e) {
    throw new IllegalStateException("relaunch failed: " + e.getMessage(), e);
}
```

| Field | Meaning |
| --- | --- |
| `existingAgents(...)` | `DROP_ALL` removes inherited `-javaagent`, `-agentpath`, and `-agentlib` options; `FILTER` evaluates inherited options using the supplied `AgentFilter` / `NativeFilter`; `PRESERVE` retains them. |
| `trustedNativeAgent(...)` / `trustedJavaAgent(...)` | Verifies the specified file's SHA-256 before creating the replacement JVM, then inserts that agent after inherited agent-option processing. |
| The four `...Filter(...)` methods | Supply Java-agent, native-load, JVMTI-acquisition, and child-process policies for the replacement JVM. They do not undo corresponding operations already completed in the current JVM. |
| `sanitizeEnvironment(...)` | Selects a sanitized inherited environment; enabled by default. |
| `rejectArgumentFiles(...)` | Rejects `@argument-file` command-line entries when enabled; enabled by default. |
| `handoff(...)` | `PROCESS_STARTED` commits after replacement-process start. `POLICY_APPLIED` commits only after a trusted Java agent reports policy application and requires `trustedJavaAgent`. |

`ForgeVM.relaunch()` and its filter-accepting overloads remain simplified APIs
for cases that only need filter arguments. Use `RelaunchSpec` when inherited
agents, trusted agents, environment handling, or handoff policy must be stated
explicitly. `ForgeVM.relaunchGeneration()` returns the current relaunch-chain
generation. Application memory state is not preserved automatically across a
relaunch and must be restored by the application.

## Field memory operations

`ForgeVM.memory()` writes fields by class name and field chain. Resolution and writes are performed outside the JVM by the agent.

```java
ForgeVM.memory().putIntField("com.example.Config", "maxHealth", 200);

ForgeVM.memory().putBooleanField(
    "com.example.Server",
    "INSTANCE.config.maintenance",
    true
);

ForgeVM.memory().putObjectField("com.example.Server", "INSTANCE.config", newConfig);
ForgeVM.memory().putNullField("com.example.Server", "INSTANCE.pendingJob");
```

Supported writes include primitive values, object references, and `null`. A field chain starts at a static field and uses `.` separators. Validate target classes, field names, and lifecycle before writing.

## Forge method injection

Forge is the runtime method-injection layer. Implement an `FvmIngot`, declare the target class, candidate methods, and injection point, then expose a `public static` callback with one `FvmCallback` parameter.

```java
import forgevm.forge.FvmCallback;
import forgevm.forge.FvmIngot;

public final class LoginAudit extends FvmIngot {
    public LoginAudit() {
        super("com.example.LoginService", "login,m_12345_");
    }

    public static void onLogin(FvmCallback callback) {
        System.out.println("login: " + callback.getInstance());
    }
}

boolean installed = ForgeVM.forge().load(new LoginAudit());
boolean removed = ForgeVM.forge().unload(LoginAudit.class);
```

| Form | Injection point |
| --- | --- |
| `HEAD` | Before the first instruction. |
| `RETURN` | Before every `return`. |
| `INVOKE("method(F)")` | Before a matching method call. |
| `FIELD_GET("health:F")` | Before a matching field read. |
| `FIELD_PUT("health:F")` | Before a matching field write. |
| `NEW("java.util.ArrayList")` | Before a matching object allocation. |

If a callback leaves its return value untouched, the original method continues. `callback.cancel()` skips a void method; `callback.setReturnValue(value)` skips the original method and supplies its return value. An ingot must expose `public static void method(FvmCallback)`.

Unloading is class-plan based. If multiple ingots target a class, ForgeVM restores that class plan and reapplies the surviving ingots. Batch `load(...)` uses a shared plan where possible to avoid repeated suspension and deoptimization.

## Logs, build, and troubleshooting

Runtime logs are written to:

```text
ForgeVM/logs/fvm-agent.log
ForgeVM/logs/fvm-transform.log
```

For diagnosis, first inspect `LaunchResult.reason()`, then look for `bootstrap`, `guard`, `relaunch`, and `CMD` records in `fvm-agent.log`; use `/status` to confirm the active PID and policy. Ensure deployed `forgevm_agent.exe` and `forgevm_native.dll` came from the same build.

Verify Java code with:

```powershell
.\gradlew.bat test
```

The native agent requires the MSVC x64 toolchain. This command writes the agent to `build/native`:

```powershell
cl.exe /std:c++17 /EHsc /utf-8 /O2 `
  /Fe:build\native\forgevm_agent.exe `
  src\main\c++\cpp\forgevm_agent.cpp `
  /link ole32.lib oleaut32.lib wbemuuid.lib psapi.lib advapi32.lib shell32.lib gdi32.lib
```

Before release, update the agent and its matching native DLL together in the resource directory.

## License

[MIT License](LICENSE.txt)
