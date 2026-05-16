#pragma once

#include <windows.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdarg>

// ============================================================
// File-based logging
//
// Writes to forgevm.log next to the DLL. Auto-flushed per line.
// FVM_LOG(fmt, ...) — printf-style, auto-prepends timestamp.
// FVM_LOG_HEX(label, data, len) — hex dump for bytecode etc.
// ============================================================

void fvm_log_init(const char* path);   // explicit path (set via forgevm_set_log_dir)
void fvm_log_write(const char* fmt, ...);
void fvm_log_hex(const char* label, const void* data, size_t len);

#define FVM_LOG(fmt, ...)     fvm_log_write(fmt, ##__VA_ARGS__)
#define FVM_LOG_HEX(l, d, n) fvm_log_hex(l, d, n)

// ============================================================
// Error state
// ============================================================

extern std::string g_lastError;

void setError(const char* value);
void setError(const std::string& value);

// ============================================================
// Target process state
// ============================================================

struct TargetProcess {
    HANDLE handle = NULL;
    DWORD pid = 0;
    uint64_t jvmDllBase = 0;
    uint64_t jvmDllSize = 0;
    bool structMapReady = false;
    bool useCompressedOops = false;
    bool useCompressedClassPointers = false;
    uint64_t narrowOopBase = 0;
    int narrowOopShift = 0;
    uint64_t narrowKlassBase = 0;
    int narrowKlassShift = 0;
};

extern TargetProcess g_target;

// ============================================================
// StructMap / TypeMap / Constants
// ============================================================

struct StructMapKey {
    std::string typeName;
    std::string fieldName;
    bool operator==(const StructMapKey& o) const {
        return typeName == o.typeName && fieldName == o.fieldName;
    }
};

struct StructMapKeyHash {
    size_t operator()(const StructMapKey& k) const {
        size_t h1 = std::hash<std::string>{}(k.typeName);
        size_t h2 = std::hash<std::string>{}(k.fieldName);
        return h1 ^ (h2 * 2654435761ULL);
    }
};

struct StructMapEntry {
    std::string typeName;
    std::string fieldName;
    bool isStatic;
    int64_t offset;
    uint64_t address;
};

struct TypeMapEntry {
    std::string typeName;
    int64_t size;
};

extern std::unordered_map<StructMapKey, StructMapEntry, StructMapKeyHash> g_structMap;
extern std::unordered_map<std::string, TypeMapEntry> g_typeMap;
extern std::unordered_map<std::string, int64_t> g_intConstants;
extern std::unordered_map<std::string, int64_t> g_longConstants;

// ============================================================
// Field resolution structs & cache
// ============================================================

struct ResolvedField {
    std::string fieldName;
    std::string descriptor;
    int32_t offset;
    uint64_t staticAddress;
    uint64_t klassAddr;
    bool isStatic;
    int32_t fieldSize;
};

struct CachedFieldInfo {
    int32_t offset;
    bool isStatic;
    uint64_t staticAddr;
    bool oopCompressed;
};

extern std::unordered_map<std::string, CachedFieldInfo> g_fieldInfoCache;

// ============================================================
// Compression detection diagnostic
// ============================================================

extern std::string g_compressionDetectLog;

// ============================================================
// StructMap lookup helpers
// ============================================================

bool structLookup(const std::string& typeName, const std::string& fieldName, StructMapEntry* out);
int64_t structOffset(const std::string& typeName, const std::string& fieldName);
uint64_t structStaticAddr(const std::string& typeName, const std::string& fieldName);
int64_t typeSize(const std::string& typeName);
int64_t intConst(const std::string& name, int64_t fallback = -1);
int64_t longConst(const std::string& name, int64_t fallback = -1);

// ============================================================
// Remote memory helpers
// ============================================================

bool readRemoteMem(HANDLE proc, uint64_t addr, void* buf, size_t size);
bool writeRemoteMem(HANDLE proc, uint64_t addr, const void* buf, size_t size);
bool readRemotePointer(HANDLE proc, uint64_t addr, uint64_t* out);
bool readRemoteU32(HANDLE proc, uint64_t addr, uint32_t* out);
bool readRemoteI32(HANDLE proc, uint64_t addr, int32_t* out);
bool readRemoteU16(HANDLE proc, uint64_t addr, uint16_t* out);
bool readRemoteString(HANDLE proc, uint64_t addr, std::string* out, size_t maxLen = 512);

// ============================================================
// Compressed oop/klass decode
// ============================================================

uint64_t decodeNarrowOop(uint32_t narrow);
uint64_t decodeRawOop(uint64_t rawOop);
uint64_t decodeRawOopWithMode(uint64_t rawOop, bool compressed);
uint64_t decodeNarrowKlass(uint32_t narrow);
uint64_t readOop(HANDLE proc, uint64_t addr, bool compressed);
uint64_t readKlass(HANDLE proc, uint64_t addr, bool compressed);

// ============================================================
// OOP/Klass resolution
// ============================================================

struct DecodedObjectInfo {
    uint64_t objAddr;
    uint64_t klassAddr;
    bool oopCompressed;
    bool klassCompressed;
};

bool looksLikeValidKlass(HANDLE proc, uint64_t klassAddr);
bool resolveObjectAndKlassFromRawOop(uint64_t rawOop, DecodedObjectInfo* out);

// ============================================================
// Thread suspend/resume
// ============================================================

bool suspendTargetThreads(DWORD pid, std::vector<DWORD>& threadIds);
void resumeTargetThreads(const std::vector<DWORD>& threadIds);

// ============================================================
// Field resolution
// ============================================================

bool readSymbolBody(HANDLE proc, uint64_t symbolAddr, std::string* out);
int32_t fieldSizeFromDescriptor(const std::string& desc);
bool resolveFieldInKlass(uint64_t klassAddr, const std::string& fieldName,
                         const std::string& descriptor, ResolvedField* out);
bool resolveAndCacheField(const char* fieldName, uint64_t objAddr,
                          uint64_t klassAddr, bool oopCompressed, CachedFieldInfo* out);

// ============================================================
// Privilege helpers
// ============================================================

bool enableDebugPrivilege();

// ============================================================
// Module / PE helpers
// ============================================================

bool findModuleBase(HANDLE proc, const wchar_t* moduleName, uint64_t* base, uint64_t* moduleSize);
bool parsePEExport(HANDLE proc, uint64_t moduleBase, const char* symbolName, uint64_t* outAddr);

// ============================================================
// Compression params extraction
// ============================================================

void extractCompressionParams();

// ============================================================
// Transform: bytecode rewriting (out-of-process)
// ============================================================

struct HookSpec {
    std::string hookClass;
    std::string hookMethod;
    std::string hookDesc;
    std::string injectAt;
};

// Per-class transform plan. One plan per InstanceKlass; all patched methods share one newCP.
// On unload the entire class reverts atomically — all hooks for the class are removed.

struct MethodCMBackup {
    uint64_t methodAddr;
    uint64_t origConstMethodAddr;  // CM* before any patch to this class
    uint64_t origConstantsPtr;     // CM._constants before any patch (= oldCPAddr)
};

struct PatchedMethodInfo {
    uint64_t methodAddr;
    uint64_t newCMAddr;   // most-recent newCM allocated for this method
    HookSpec hook;
};

struct ClassTransformPlan {
    std::string className;
    uint64_t klassAddr  = 0;
    uint64_t oldCPAddr  = 0;   // true original CP — used for restore

    std::vector<MethodCMBackup>   methodBackups;   // ALL class methods, captured before first patch
    std::vector<PatchedMethodInfo> patchedMethods;  // methods that have been patched

    // Most-recent active allocations (layered: each call appends to the previous newCP)
    uint64_t newCPAddr      = 0;
    uint64_t newCPCacheAddr = 0;
    uint64_t newRKAddr      = 0;
};

extern std::unordered_map<uint64_t, ClassTransformPlan> g_plans;  // key = klassAddr

// Find an InstanceKlass by internal name (e.g. "com/example/Foo")
bool findInstanceKlassByName(const std::string& internalName, uint64_t* outKlassAddr);

// Locate a Java Method* by class name, method name, and param descriptor
// Walks SystemDictionary -> InstanceKlass -> methods array
bool findJavaMethod(const char* className, const char* methodName,
                    const char* paramDesc, uint64_t* outMethodAddr);

// Read ConstMethod bytecode region
bool readConstMethodBytecode(uint64_t constMethodAddr, std::vector<uint8_t>* bytecodeOut,
                             uint64_t* bytecodeStartAddr, uint32_t* codeSizeOut);

// Read ConstantPool entries
bool readConstantPool(uint64_t constPoolAddr, std::vector<uint8_t>* poolBytesOut,
                      uint32_t* poolLengthOut, size_t* poolByteSizeOut);

// ============================================================
// Per-class plan-once-commit-once API
//
// commitClassPlan: one new ConstantPool per class, all patched methods share it,
// atomic class-level swap (§17.5 Phase A→D).
//
// unloadClassPlan: reverts the entire InstanceKlass plan to its original CP (§17.7).
// ============================================================

struct HookCandidate {
    std::string methodName;
    std::string paramDesc;
};

struct HookSpecExtended {
    std::string hookClass;
    std::string hookMethod;
    std::string hookDesc;
    std::string injectAt;       // "HEAD", "RETURN", "INVOKE:foo", "FIELD_GET:bar", etc.
    std::vector<HookCandidate> candidates;
};

struct HookOutcome {
    bool matched = false;
    std::string methodName;     // matched candidate (on success)
    std::string paramDesc;
    std::string reason;         // failure reason (on failure)
    uint64_t methodAddr = 0;    // resolved Method* (on success)
};

// Plan-once-commit-once (§17.5 Phase A→D). targetClassName is dot- or slash-
// separated. additionalHooks are merged with the plan's existing hooks (if any);
// the entire merged set is re-committed atomically with one merged newCP.
//
// outResults parallels additionalHooks (same size, same order) and reports
// per-hook match/failure. Returns 1 on commit success, 0 on commit failure.
int commitClassPlan(const char* targetClassName,
                    const std::vector<HookSpecExtended>& additionalHooks,
                    bool includeSubclasses,
                    bool deferDeopt,
                    std::vector<HookOutcome>* outResults);

// Class-level rollback (§17.7). Restores InstanceKlass._constants to the
// original CP and reverts all patched-method ConstMethod pointers from the
// plan's backups. Does not VirtualFreeEx — in-flight frames may still
// reference the new allocations. Returns 1 on success, 0 if no plan exists
// for the given class.
int unloadClassPlan(const char* targetClassName, bool includeSubclasses);
