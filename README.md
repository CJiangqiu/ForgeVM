# ForgeVM

ForgeVM is a JVM runtime manipulation library that operates **entirely out-of-process**. Instead of relying on JVMTI, JNI, or other official JVM APIs, ForgeVM uses an external native Agent to read and write JVM memory directly through OS-level `ReadProcessMemory` / `WriteProcessMemory`. This makes it resistant to in-process hook interception and JDK version changes.

## Architecture

```
Your Java Code
     │
     ▼
ForgeVM.launch()  ──  Java orchestrator
     │
     ▼
forgevm_agent.exe  ──  independent process, stdin/stdout JSON IPC
     │
     ▼
forgevm_native.dll  ──  C++, Win32 ReadProcessMemory / WriteProcessMemory
     │
     ▼
Target JVM Heap  ──  HotSpot object memory
```

If the Agent or DLL is unavailable, ForgeVM reports `JVM_FALLBACK` — no crash, no exception from launch. The Agent includes a **parent-process watchdog** that automatically exits when the JVM process dies, preventing orphaned processes.

## Requirements

- Java 17+
- Windows x64
- HotSpot JVM (OpenJDK / Oracle JDK)
- `forgevm_agent.exe` + `forgevm_native.dll` (auto-extracted from bundled resources, or placed in `native/win-x64/`)
- Administrator or SeDebugPrivilege for `NATIVE_FULL`; debug privilege only for `NATIVE_RESTRICTED`

## Quick Start

```java
import forgevm.core.ForgeVM;

// One call to start everything. No -D flags, no env vars, no manual config.
ForgeVM.launch();
```

## Features

### 1. JVM Control

Control the target JVM process through the Agent.

```java
// Exit target JVM
ForgeVM.exit(0);

// Lock Agent to prevent rebind races (e.g., during Shadow JVM switch)
ForgeVM.lockAgent(30);
ForgeVM.unlockAgent();

// Rebind Agent to current JVM process
ForgeVM.lockAgent(10);
ForgeVM.rebindAgentToCurrentJvm();
```

### 2. Field Memory

Write field values directly to JVM heap memory, bypassing all access restrictions. ForgeVM resolves field offsets at runtime from the object's klass pointer — no hardcoded offsets, works across JDK versions.

**Single instance:**

```java
Object target = getTargetObject();

ForgeVM.memory().putBooleanField(target, "com.example.Entity.active", true);
ForgeVM.memory().putFloatField(target, "com.example.Entity.health", 20.0f);
ForgeVM.memory().putIntField(target, "com.example.Entity.score", 9999);

// Object reference write (automatically updates GC card table)
ForgeVM.memory().putObjectField(target, "com.example.Entity.owner", newOwner);
```

**Batch (Iterable) — all writes under a single thread-suspend window:**

```java
List<Object> targets = getAllEntities();

// One suspend → write all → resume. Zero GC interference.
ForgeVM.memory().putBooleanField(targets, "com.example.Entity.active", false);
```

**Supported types:**

| Type | Bytes | Type | Bytes |
|------|-------|------|-------|
| `boolean` | 1 | `int` | 4 |
| `byte` | 1 | `float` | 4 |
| `short` | 2 | `long` | 8 |
| `char` | 2 | `double` | 8 |
| `Object` | 4 or 8 (CompressedOops) | | |

Field descriptor format: `"fully.qualified.ClassName.fieldName"`. Resolved offsets are **cached** — subsequent writes skip resolution entirely.

### 3. Transformer

Inject custom logic into any loaded class's methods at runtime. ForgeVM rewrites bytecode in-memory through the Agent — no `java.lang.instrument`, no Instrumentation API.

**Define a transformer:**

```java
import forgevm.transform.FvmTransformer;
import forgevm.transform.FvmCallback;

// Simplest form — target class + method name
public class TickLogger extends FvmTransformer {
    public TickLogger() {
        super("com.example.Entity", "tick");
    }

    public void onTick(FvmCallback callback) {
        System.out.println("tick was called!");
        // not calling callback methods → original method runs normally
    }
}
```

**Override a return value:**

```java
public class HealthOverride extends FvmTransformer {
    public HealthOverride() {
        super("com.example.Entity", new String[]{"getHealth", "m1234"});
    }

    public void onGetHealth(FvmCallback callback) {
        callback.setReturnValue(20.0f);  // original method is skipped
    }
}
```

**Conditional logic based on target instance:**

```java
public class PlayerHealthOnly extends FvmTransformer {
    public PlayerHealthOnly() {
        super("com.example.Entity", new String[]{"getHealth", "m1234"});
    }

    public void onGetHealth(FvmCallback callback) {
        Object target = callback.getInstance();
        if (target instanceof Player) {
            callback.setReturnValue(20.0f);  // only Players get 20 HP
        }
        // non-Player entities → original method runs normally
    }
}
```

**Conditionally cancel a method:**

```java
public class TickGuard extends FvmTransformer {
    public TickGuard() {
        super("com.example.Entity", "tick", InjectPoint.HEAD);
    }

    public void onTick(FvmCallback callback) {
        if (shouldBlock()) {
            callback.cancel();  // original method is skipped (void)
        }
        // not cancelled → original method runs normally
    }
}
```

**Load and unload at runtime:**

```java
// Apply
ForgeVM.transformer().load(new HealthOverride());

// Remove (restores original bytecode)
ForgeVM.transformer().unload(HealthOverride.class);
```

**Constructor variants — use only what you need:**

```java
// Single method, no-arg, HEAD (simplest)
super("com.example.Entity", "tick");

// Multiple candidate names (obfuscation support)
super("com.example.Entity", new String[]{"getHealth", "m1234"});

// Specify inject point
super("com.example.Entity", "tick", InjectPoint.RETURN);

// With parameter types (to distinguish overloads)
super("com.example.Entity", "damage", new Class<?>[]{float.class}, InjectPoint.HEAD);
```

**FvmCallback methods:**

| Method | Effect |
|--------|--------|
| `callback.getInstance()` | Get the target object (`this` of the hooked method) |
| `callback.setReturnValue(value)` | Skip original method, return the given value |
| `callback.cancel()` | Skip original method (for void methods) |
| *(neither called)* | Original method executes normally |

## Capability Levels

| Level | Meaning |
|-------|---------|
| `NATIVE_FULL` | Agent + DLL active, admin + SeDebugPrivilege |
| `NATIVE_RESTRICTED` | Agent + DLL active, debug privilege only |
| `JVM_FALLBACK` | Agent/DLL unavailable — memory and transform operations will fail |

## How It Works

### Bootstrap

`ForgeVM.launch()` starts `forgevm_agent.exe` as a child process, which loads `forgevm_native.dll`. The DLL opens a handle to the calling JVM process and reads HotSpot's exported self-describing tables:

- `gHotSpotVMStructs` — C++ struct field offsets
- `gHotSpotVMTypes` — type sizes
- `gHotSpotVMIntConstants` / `gHotSpotVMLongConstants` — runtime flags

These tables make ForgeVM work across JDK versions without hardcoded offsets.

### putField Execution Chain

```
Java:  ForgeVM.memory().putXxxField(target, "ClassName.field", value)
  │
  ├── Unsafe extracts raw OOP address
  ├── Value encoded to little-endian bytes
  ├── JSON IPC → Agent
  │
  ▼
Native DLL:
  ├── decodeRawOop → object address
  ├── readKlass → klass pointer from object header
  ├── Walk Klass._super chain → resolve field offset (cached)
  └── WriteProcessMemory(objAddr + offset, valueBytes)
```

### Transformer Execution Chain

```
Java:  ForgeVM.transformer().load(new MyPatch())
  │
  ├── Reflect to find hook method name and FvmCallback parameter
  ├── JSON IPC → Agent
  │
  ▼
Native DLL:
  ├── ClassLoaderDataGraph → find target InstanceKlass
  ├── InstanceKlass._methods → find target Method*
  ├── Read ConstMethod bytecode + ConstantPool
  ├── VirtualAllocEx → allocate new ConstMethod + expanded ConstantPool
  ├── Build new bytecode:
  │     new FvmCallback → invokestatic hook(FvmCallback)
  │     → isCancelled? → yes: getReturnValue + return
  │                     → no:  original method body
  ├── SuspendThread → swap ConstMethod pointer + clear JIT → ResumeThread
  └── Backup original pointers for restore
```
