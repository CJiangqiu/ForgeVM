# ForgeVM

Welcome to ForgeVM (FVM) — a Java library that provides convenient low-level operation APIs.

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

ForgeVM operates through an **out-of-process Agent** that loads the native DLL. All memory writes go through OS-level `WriteProcessMemory` — not JVMTI, not JNI, not `sun.misc.Unsafe`. Field layout is resolved at runtime from HotSpot's self-describing structure tables (`gHotSpotVMStructs`), making it JDK-version-independent.

If the Agent or DLL is unavailable, ForgeVM reports `JVM_FALLBACK` — no crash, no exception from launch. The Agent includes a **parent-process watchdog** that automatically exits when the JVM process dies, preventing orphaned processes.

## Requirements

- Java 17+
- Windows x64
- HotSpot JVM (OpenJDK / Oracle JDK)
- `forgevm_agent.exe` + `forgevm_native.dll` (auto-extracted from bundled resources, or placed in `native/win-x64/`)
- Administrator or SeDebugPrivilege for `NATIVE_FULL`; debug privilege only for `NATIVE_RESTRICTED`

## Quick Start

### 1. Launch

```java
import forgevm.core.ForgeVM;
import forgevm.core.ForgeVM.LaunchResult;

// Silent launch (default) — no elevation prompt
LaunchResult result = ForgeVM.launch();

// Or with elevation prompt
LaunchResult result = ForgeVM.launchPrompt();

System.out.println(result.capabilityLevel()); // NATIVE_FULL / NATIVE_RESTRICTED / JVM_FALLBACK
System.out.println(result.nativeDllActive()); // true if native path is active
System.out.println(result.reason());          // diagnostic string
```

`ForgeVM.launch()` is the only required call. No `-D` flags, no environment variables, no manual path configuration.

### 2. Field Memory Write — Single Instance

```java
import forgevm.core.ForgeVM;

// Ensure agent is active
ForgeVM.launch();

// Get a live object reference (from your business logic, game, etc.)
LivingEntity entity = getEntity();

// Write a field value directly to JVM heap memory
ForgeVM.memory().putBooleanField(entity, "net.minecraft.entity.LivingEntity.dead", true);
ForgeVM.memory().putFloatField(entity, "net.minecraft.entity.LivingEntity.health", 20.0f);

// Object reference write (automatically updates GC card table)
ForgeVM.memory().putObjectField(entity, "net.minecraft.entity.Entity.level", newLevel);
```

The field descriptor format is `"fully.qualified.ClassName.fieldName"`. ForgeVM resolves the field offset by reading the object's klass pointer from its header, walking the inheritance chain, and matching the field name. The resolved offset is **cached** — subsequent writes to the same field skip resolution entirely.

### 3. Field Memory Write — Batch (Iterable)

```java
import forgevm.core.ForgeVM;

List<LivingEntity> entities = getAllEntities();

// Write the same value to a field across ALL instances
// All writes execute under a single thread-suspend window (SuspendThread / ResumeThread)
ForgeVM.memory().putBooleanField(entities, "net.minecraft.entity.LivingEntity.dead", false);
```

Single instance writes skip thread suspension (acceptable GC race for one atomic write). Batch writes suspend all JVM threads via Win32 `SuspendThread`, execute all writes, then resume — **zero GC interference**.

### 4. Supported Value Types

| Java Type | Bytes Written | Example |
|-----------|---------------|---------|
| `boolean` | 1 | `true` / `false` |
| `byte` | 1 | `(byte) 42` |
| `short` | 2 | `(short) 1000` |
| `char` | 2 | `'A'` |
| `int` | 4 | `100` |
| `float` | 4 | `20.0f` |
| `long` | 8 | `999999L` |
| `double` | 8 | `3.14` |

| `Object` | 4 or 8 (CompressedOops) | any object reference |

Object reference writes (`putObjectField`) are supported. The native DLL automatically updates the GC card table after writing the reference, preventing the garbage collector from missing the new reference.

### 5. JVM Control

```java
// Exit target JVM via Agent
ForgeVM.exit(0);

// Lock Agent to prevent rebind races (e.g., during Shadow JVM switch)
ForgeVM.lockAgent(30); // lock for up to 30 seconds
ForgeVM.unlockAgent();

// Rebind Agent to current JVM process
ForgeVM.lockAgent(10);
ForgeVM.rebindAgentToCurrentJvm();
```

## Capability Levels

| Level | Meaning |
|-------|---------|
| `NATIVE_FULL` | Agent + DLL active, admin + SeDebugPrivilege |
| `NATIVE_RESTRICTED` | Agent + DLL active, debug privilege only |
| `JVM_FALLBACK` | Agent/DLL unavailable — `putField` will throw `ForgeVMException` |

## How It Works

### Bootstrap

`ForgeVM.launch()` starts `forgevm_agent.exe` as a child process, which loads `forgevm_native.dll`. The DLL opens a handle to the calling JVM process and reads HotSpot's exported self-describing tables:

- `gHotSpotVMStructs` — C++ struct field offsets (e.g., `InstanceKlass::_fields`, `Klass::_super`)
- `gHotSpotVMTypes` — type sizes
- `gHotSpotVMIntConstants` / `gHotSpotVMLongConstants` — runtime flags (`UseCompressedOops`, etc.)

These tables make ForgeVM work across JDK versions without hardcoded offsets.

### putField Execution Chain

```
Java:  ForgeVM.memory().putXxxField(entity, "ClassName.field", value)
  │
  ├── Unsafe extracts raw OOP from object (narrow or full, depending on CompressedOops)
  ├── Value encoded to little-endian bytes
  ├── JSON IPC: {"cmd":"put_field","oop":...,"fieldName":"...","className":"...","valueHex":"..."}
  │
  ▼
Agent:  handlePutField() → calls forgevm_native.dll::forgevm_put_field()
  │
  ▼
Native DLL:
  ├── decodeRawOop(oop) → object address in target JVM heap
  ├── readKlass(objAddr + 8) → klass pointer from object header
  ├── Walk Klass._super chain → resolveFieldInKlass() → field offset
  ├── Cache field offset by "className#fieldName"
  └── WriteProcessMemory(objAddr + offset, valueBytes, size)
```

### Batch (Iterable) Execution Chain

```
Java:  ForgeVM.memory().putXxxField(entities, "ClassName.field", value)
  │
  ├── Unsafe extracts OOP for each instance
  ├── JSON IPC: {"cmd":"put_field_batch","oops":[...],...}
  │
  ▼
Native DLL:
  ├── Resolve field offset from first OOP (cached)
  ├── SuspendThread on all target JVM threads  ← freezes GC
  ├── For each OOP: WriteProcessMemory(objAddr + offset, valueBytes)
  └── ResumeThread on all threads
```

