#include "forgevm_internal.h"

#include <psapi.h>
#include <shellapi.h>
#include <string.h>
#include <algorithm>

/* ============================================================
 * File-based logging implementation
 * ============================================================ */

static FILE* g_logFile = nullptr;
static CRITICAL_SECTION g_logLock;
static bool g_logLockInit = false;

static void ensureLogLock() {
    if (!g_logLockInit) {
        InitializeCriticalSection(&g_logLock);
        g_logLockInit = true;
    }
}

void fvm_log_init(const char* path) {
    ensureLogLock();
    EnterCriticalSection(&g_logLock);
    if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    g_logFile = fopen(path, "w");
    if (g_logFile) {
        fprintf(g_logFile, "===== ForgeVM log session =====\n");
        fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logLock);
}

/* fvm_log_open_default() removed — all logging is routed through
 * forgevm_set_log_dir() which places the log in ForgeVM/logs/. */

void fvm_log_write(const char* fmt, ...) {
    ensureLogLock();
    EnterCriticalSection(&g_logLock);

    /* Log file is initialized by Agent via forgevm_set_log_dir().
     * If not set, silently discard — no random file creation. */
    if (!g_logFile) {
        LeaveCriticalSection(&g_logLock);
        return;
    }

    // Timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "%04d-%02d-%02d %02d:%02d:%02d.%03d | ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);

    fprintf(g_logFile, "\n");
    fflush(g_logFile);

    LeaveCriticalSection(&g_logLock);
}

void fvm_log_hex(const char* label, const void* data, size_t len) {
    ensureLogLock();
    EnterCriticalSection(&g_logLock);

    if (!g_logFile) { LeaveCriticalSection(&g_logLock); return; }

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "%04d-%02d-%02d %02d:%02d:%02d.%03d | %s [%zu bytes]: ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            label, len);

    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len && i < 256; i++) {
        fprintf(g_logFile, "%02X ", p[i]);
    }
    if (len > 256) fprintf(g_logFile, "... (%zu more)", len - 256);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);

    LeaveCriticalSection(&g_logLock);
}

/* ============================================================
 * Global state definitions
 * ============================================================ */

std::string g_lastError = "ok";
TargetProcess g_target;

std::unordered_map<StructMapKey, StructMapEntry, StructMapKeyHash> g_structMap;
std::unordered_map<std::string, TypeMapEntry> g_typeMap;
std::unordered_map<std::string, int64_t> g_intConstants;
std::unordered_map<std::string, int64_t> g_longConstants;
std::unordered_map<std::string, CachedFieldInfo> g_fieldInfoCache;

/* ============================================================
 * Error state
 * ============================================================ */

void setError(const char* value) {
    g_lastError = value;
    FVM_LOG("ERROR: %s", value);
}

void setError(const std::string& value) {
    g_lastError = value;
    FVM_LOG("ERROR: %s", value.c_str());
}

/* ============================================================
 * Remote memory helpers
 * ============================================================ */

bool readRemoteMem(HANDLE proc, uint64_t addr, void* buf, size_t size) {
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf, size, &bytesRead)) {
        return false;
    }
    return bytesRead == size;
}

bool writeRemoteMem(HANDLE proc, uint64_t addr, const void* buf, size_t size) {
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(proc, reinterpret_cast<LPVOID>(addr), buf, size, &bytesWritten)) {
        return false;
    }
    return bytesWritten == size;
}

bool readRemotePointer(HANDLE proc, uint64_t addr, uint64_t* out) {
    *out = 0;
    return readRemoteMem(proc, addr, out, 8);
}

bool readRemoteU32(HANDLE proc, uint64_t addr, uint32_t* out) {
    *out = 0;
    return readRemoteMem(proc, addr, out, 4);
}

bool readRemoteI32(HANDLE proc, uint64_t addr, int32_t* out) {
    *out = 0;
    return readRemoteMem(proc, addr, out, 4);
}

bool readRemoteU16(HANDLE proc, uint64_t addr, uint16_t* out) {
    *out = 0;
    return readRemoteMem(proc, addr, out, 2);
}

bool readRemoteString(HANDLE proc, uint64_t addr, std::string* out, size_t maxLen) {
    out->clear();
    if (addr == 0) return false;
    char buf[512];
    size_t toRead = (maxLen < sizeof(buf)) ? maxLen : sizeof(buf);
    if (!readRemoteMem(proc, addr, buf, toRead)) {
        if (!readRemoteMem(proc, addr, buf, 64)) {
            return false;
        }
        toRead = 64;
    }
    for (size_t i = 0; i < toRead; i++) {
        if (buf[i] == '\0') {
            *out = std::string(buf, i);
            return true;
        }
    }
    *out = std::string(buf, toRead);
    return true;
}

/* ============================================================
 * StructMap / TypeMap lookup helpers
 * ============================================================ */

bool structLookup(const std::string& typeName, const std::string& fieldName, StructMapEntry* out) {
    auto it = g_structMap.find(StructMapKey{typeName, fieldName});
    if (it == g_structMap.end()) return false;
    *out = it->second;
    return true;
}

int64_t structOffset(const std::string& typeName, const std::string& fieldName) {
    StructMapEntry e;
    if (!structLookup(typeName, fieldName, &e)) return -1;
    return e.offset;
}

uint64_t structStaticAddr(const std::string& typeName, const std::string& fieldName) {
    StructMapEntry e;
    if (!structLookup(typeName, fieldName, &e)) return 0;
    return e.address;
}

int64_t typeSize(const std::string& typeName) {
    auto it = g_typeMap.find(typeName);
    if (it == g_typeMap.end()) return -1;
    return it->second.size;
}

int64_t intConst(const std::string& name, int64_t fallback) {
    auto it = g_intConstants.find(name);
    if (it == g_intConstants.end()) return fallback;
    return it->second;
}

int64_t longConst(const std::string& name, int64_t fallback) {
    auto it = g_longConstants.find(name);
    if (it == g_longConstants.end()) return fallback;
    return it->second;
}

/* ============================================================
 * Module enumeration
 * ============================================================ */

bool findModuleBase(HANDLE proc, const wchar_t* moduleName, uint64_t* base, uint64_t* moduleSize) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(proc, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        return false;
    }

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        wchar_t name[MAX_PATH];
        if (GetModuleBaseNameW(proc, modules[i], name, MAX_PATH) > 0) {
            if (_wcsicmp(name, moduleName) == 0) {
                *base = reinterpret_cast<uint64_t>(modules[i]);
                MODULEINFO info;
                if (GetModuleInformation(proc, modules[i], &info, sizeof(info))) {
                    *moduleSize = info.SizeOfImage;
                } else {
                    *moduleSize = 0;
                }
                return true;
            }
        }
    }
    return false;
}

/* ============================================================
 * PE export table parsing
 * ============================================================ */

bool parsePEExport(HANDLE proc, uint64_t moduleBase, const char* symbolName, uint64_t* outAddr) {
    *outAddr = 0;

    IMAGE_DOS_HEADER dosHeader;
    if (!readRemoteMem(proc, moduleBase, &dosHeader, sizeof(dosHeader))) {
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    uint64_t ntAddr = moduleBase + dosHeader.e_lfanew;
    IMAGE_NT_HEADERS64 ntHeaders;
    if (!readRemoteMem(proc, ntAddr, &ntHeaders, sizeof(ntHeaders))) {
        return false;
    }
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
        return false;
    }

    uint64_t exportAddr = moduleBase + exportDir.VirtualAddress;
    IMAGE_EXPORT_DIRECTORY exportDirectory;
    if (!readRemoteMem(proc, exportAddr, &exportDirectory, sizeof(exportDirectory))) {
        return false;
    }

    uint64_t namesAddr = moduleBase + exportDirectory.AddressOfNames;
    uint64_t ordinalsAddr = moduleBase + exportDirectory.AddressOfNameOrdinals;
    uint64_t functionsAddr = moduleBase + exportDirectory.AddressOfFunctions;
    DWORD numNames = exportDirectory.NumberOfNames;

    std::vector<DWORD> nameRVAs(numNames);
    if (numNames > 0 && !readRemoteMem(proc, namesAddr, nameRVAs.data(), numNames * sizeof(DWORD))) {
        return false;
    }

    std::vector<WORD> ordinals(numNames);
    if (numNames > 0 && !readRemoteMem(proc, ordinalsAddr, ordinals.data(), numNames * sizeof(WORD))) {
        return false;
    }

    size_t symbolLen = strlen(symbolName);
    char nameBuf[256];

    for (DWORD i = 0; i < numNames; i++) {
        uint64_t nameAddr = moduleBase + nameRVAs[i];
        size_t toRead = (symbolLen + 1 < sizeof(nameBuf)) ? symbolLen + 1 : sizeof(nameBuf);
        if (!readRemoteMem(proc, nameAddr, nameBuf, toRead)) {
            continue;
        }
        nameBuf[toRead - 1] = '\0';
        if (strcmp(nameBuf, symbolName) == 0) {
            DWORD funcRVA = 0;
            uint64_t funcRVAAddr = functionsAddr + ordinals[i] * sizeof(DWORD);
            if (!readRemoteMem(proc, funcRVAAddr, &funcRVA, sizeof(DWORD))) {
                return false;
            }
            *outAddr = moduleBase + funcRVA;
            return true;
        }
    }
    return false;
}

/* ============================================================
 * HotSpot self-describing table readers
 * ============================================================ */

struct VMStructEntryLayout {
    size_t typeNameOffset = 0;
    size_t fieldNameOffset = 8;
    size_t typeStringOffset = 16;
    size_t isStaticOffset = 24;
    size_t offsetOffset = 32;
    size_t addressOffset = 40;
    size_t stride = 48;
};

struct VMTypeEntryLayout {
    size_t typeNameOffset = 0;
    size_t superNameOffset = 8;
    size_t isOopOffset = 16;
    size_t isIntegerOffset = 20;
    size_t isUnsignedOffset = 24;
    size_t sizeOffset = 32;
    size_t stride = 40;
};

struct VMIntConstantLayout {
    size_t nameOffset = 0;
    size_t valueOffset = 8;
    size_t stride = 16;
};

struct VMLongConstantLayout {
    size_t nameOffset = 0;
    size_t valueOffset = 8;
    size_t stride = 16;
};

static bool readEntryLayoutOffsets(HANDLE proc, uint64_t jvmBase,
                            VMStructEntryLayout* structLayout,
                            VMTypeEntryLayout* typeLayout,
                            VMIntConstantLayout* intLayout,
                            VMLongConstantLayout* longLayout) {
    uint64_t addr = 0;

    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryTypeNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->typeNameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryFieldNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->fieldNameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryTypeStringOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->typeStringOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryIsStaticOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->isStaticOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryOffsetOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->offsetOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryAddressOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->addressOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMStructEntryArrayStride", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &structLayout->stride, sizeof(size_t));
    }

    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntryTypeNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->typeNameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntrySuperclassNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->superNameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntryIsOopTypeOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->isOopOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntryIsIntegerTypeOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->isIntegerOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntryIsUnsignedOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->isUnsignedOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntrySizeOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->sizeOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMTypeEntryArrayStride", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &typeLayout->stride, sizeof(size_t));
    }

    if (parsePEExport(proc, jvmBase, "gHotSpotVMIntConstantEntryNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &intLayout->nameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMIntConstantEntryValueOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &intLayout->valueOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMIntConstantEntryArrayStride", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &intLayout->stride, sizeof(size_t));
    }

    if (parsePEExport(proc, jvmBase, "gHotSpotVMLongConstantEntryNameOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &longLayout->nameOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMLongConstantEntryValueOffset", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &longLayout->valueOffset, sizeof(size_t));
    }
    if (parsePEExport(proc, jvmBase, "gHotSpotVMLongConstantEntryArrayStride", &addr) && addr != 0) {
        readRemoteMem(proc, addr, &longLayout->stride, sizeof(size_t));
    }

    return structLayout->stride > 0 && typeLayout->stride > 0;
}

static bool readVMStructTable(HANDLE proc, uint64_t tablePtr, const VMStructEntryLayout& layout) {
    uint64_t tableAddr = 0;
    if (!readRemotePointer(proc, tablePtr, &tableAddr) || tableAddr == 0) {
        return false;
    }

    unsigned char entryBuf[256];
    for (int i = 0; i < 50000; i++) {
        uint64_t entryAddr = tableAddr + (uint64_t)i * layout.stride;
        if (!readRemoteMem(proc, entryAddr, entryBuf, layout.stride)) {
            break;
        }

        uint64_t typeNamePtr = 0;
        memcpy(&typeNamePtr, entryBuf + layout.typeNameOffset, 8);
        if (typeNamePtr == 0) break;

        uint64_t fieldNamePtr = 0;
        memcpy(&fieldNamePtr, entryBuf + layout.fieldNameOffset, 8);

        int32_t isStatic = 0;
        memcpy(&isStatic, entryBuf + layout.isStaticOffset, 4);

        uint64_t offset = 0;
        memcpy(&offset, entryBuf + layout.offsetOffset, 8);

        uint64_t address = 0;
        memcpy(&address, entryBuf + layout.addressOffset, 8);

        std::string typeName, fieldName;
        if (!readRemoteString(proc, typeNamePtr, &typeName)) continue;
        if (fieldNamePtr != 0) {
            readRemoteString(proc, fieldNamePtr, &fieldName);
        }

        StructMapKey key{typeName, fieldName};
        StructMapEntry entry{typeName, fieldName, isStatic != 0, static_cast<int64_t>(offset), address};
        g_structMap[key] = entry;
    }
    return !g_structMap.empty();
}

static bool readVMTypeTable(HANDLE proc, uint64_t tablePtr, const VMTypeEntryLayout& layout) {
    uint64_t tableAddr = 0;
    if (!readRemotePointer(proc, tablePtr, &tableAddr) || tableAddr == 0) {
        return false;
    }

    unsigned char entryBuf[256];
    for (int i = 0; i < 50000; i++) {
        uint64_t entryAddr = tableAddr + (uint64_t)i * layout.stride;
        if (!readRemoteMem(proc, entryAddr, entryBuf, layout.stride)) {
            break;
        }

        uint64_t namePtr = 0;
        memcpy(&namePtr, entryBuf + layout.typeNameOffset, 8);
        if (namePtr == 0) break;

        int64_t size = 0;
        memcpy(&size, entryBuf + layout.sizeOffset, 8);

        std::string name;
        if (!readRemoteString(proc, namePtr, &name)) continue;

        g_typeMap[name] = TypeMapEntry{name, size};
    }
    return true;
}

static bool readVMIntConstants(HANDLE proc, uint64_t tablePtr, const VMIntConstantLayout& layout) {
    uint64_t tableAddr = 0;
    if (!readRemotePointer(proc, tablePtr, &tableAddr) || tableAddr == 0) {
        return false;
    }

    unsigned char entryBuf[64];
    for (int i = 0; i < 50000; i++) {
        uint64_t entryAddr = tableAddr + (uint64_t)i * layout.stride;
        if (!readRemoteMem(proc, entryAddr, entryBuf, layout.stride)) {
            break;
        }

        uint64_t namePtr = 0;
        memcpy(&namePtr, entryBuf + layout.nameOffset, 8);
        if (namePtr == 0) break;

        int32_t value = 0;
        memcpy(&value, entryBuf + layout.valueOffset, 4);

        std::string name;
        if (!readRemoteString(proc, namePtr, &name)) continue;

        g_intConstants[name] = value;
    }
    return true;
}

static bool readVMLongConstants(HANDLE proc, uint64_t tablePtr, const VMLongConstantLayout& layout) {
    uint64_t tableAddr = 0;
    if (!readRemotePointer(proc, tablePtr, &tableAddr) || tableAddr == 0) {
        return false;
    }

    unsigned char entryBuf[64];
    for (int i = 0; i < 50000; i++) {
        uint64_t entryAddr = tableAddr + (uint64_t)i * layout.stride;
        if (!readRemoteMem(proc, entryAddr, entryBuf, layout.stride)) {
            break;
        }

        uint64_t namePtr = 0;
        memcpy(&namePtr, entryBuf + layout.nameOffset, 8);
        if (namePtr == 0) break;

        int64_t value = 0;
        memcpy(&value, entryBuf + layout.valueOffset, 8);

        std::string name;
        if (!readRemoteString(proc, namePtr, &name)) continue;

        g_longConstants[name] = value;
    }
    return true;
}

/* ============================================================
 * Privilege helpers
 * ============================================================ */

bool enableDebugPrivilege() {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        setError("open_process_token_failed");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(token);
        setError("lookup_debug_privilege_failed");
        return false;
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(token);
        setError("adjust_token_privilege_failed");
        return false;
    }

    DWORD adjustError = GetLastError();
    CloseHandle(token);
    if (adjustError == ERROR_NOT_ALL_ASSIGNED) {
        setError("debug_privilege_not_assigned");
        return false;
    }

    setError("ok");
    return true;
}

/* ============================================================
 * Exported functions
 * ============================================================ */

/* Probe: same-user OpenProcess does not require SeDebugPrivilege.
 * We opportunistically enable it (helps if target has a hostile DACL or
 * different integrity), but a normal-user JVM has no SeDebug in its token
 * and AdjustTokenPrivileges returns ERROR_NOT_ALL_ASSIGNED — that is NOT
 * a capability failure. The real capability gate is OpenProcess in
 * forgevm_bootstrap_target. */
extern "C" __declspec(dllexport) int forgevm_probe_capability() {
    if (enableDebugPrivilege()) {
        setError("ok");
    } else {
        FVM_LOG("probe: SeDebugPrivilege not available (%s) — continuing, not required for same-user access",
                g_lastError.c_str());
        setError("ok_no_sedebug");
    }
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_init() {
    FVM_LOG("forgevm_init() called");
    if (enableDebugPrivilege()) {
        setError("ok");
    } else {
        FVM_LOG("init: SeDebugPrivilege not available (%s) — continuing", g_lastError.c_str());
        setError("ok_no_sedebug");
    }
    return 1;
}

/* Patch trampoline state — declared up front because the bootstrap/attach
 * paths below clear these when the target PID changes. Definitions live in
 * the anonymous namespace further down for module-internal linkage. */
namespace {
    struct PatchState {
        uint64_t targetAddr = 0;
        uint8_t  original[16] = {};
        size_t   patchSize = 0;
        bool     patched = false;
        uint64_t trampolineAddr = 0;
        size_t   trampolineSize = 0;
        bool     trampolineInstalled = false;
    };
    extern PatchState g_javaAgentPatch;
    extern PatchState g_nativeLoadPatch;
    extern PatchState g_jvmtiPatch;
    extern PatchState g_processCreatePatch;
    extern uint64_t g_jvmtiGetEnvAddr;
    extern bool g_jvmtiGetEnvLocateFailed;
}

extern "C" __declspec(dllexport) int forgevm_bootstrap_target(unsigned long long targetPid) {
    FVM_LOG("forgevm_bootstrap_target(pid=%llu)", targetPid);
    DWORD oldPid = g_target.pid;
    DWORD newPid = static_cast<DWORD>(targetPid);
    if (g_target.handle != NULL) {
        CloseHandle(g_target.handle);
        g_target = TargetProcess{};
    }
    /* Patch state is per-target: when the target PID changes, the previous
     * target's trampolines live in an address space that's gone, so reset to
     * avoid future install calls bailing with "already_patched". */
    if (oldPid != newPid) {
        g_javaAgentPatch     = PatchState{};
        g_nativeLoadPatch    = PatchState{};
        g_jvmtiPatch         = PatchState{};
        g_jvmtiGetEnvAddr = 0;
        g_jvmtiGetEnvLocateFailed = false;
        g_processCreatePatch = PatchState{};
        FVM_LOG("bootstrap_target: target pid changed %lu -> %lu, patch state cleared",
                (unsigned long)oldPid, (unsigned long)newPid);
    }
    g_structMap.clear();
    g_typeMap.clear();
    g_intConstants.clear();
    g_longConstants.clear();
    g_fieldInfoCache.clear();

    if (targetPid == 0ULL) {
        setError("target_pid_zero");
        return 0;
    }

    HANDLE proc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, static_cast<DWORD>(targetPid));
    if (proc == NULL) {
        setError("open_target_process_failed");
        return 0;
    }

    g_target.handle = proc;
    g_target.pid = static_cast<DWORD>(targetPid);

    if (!findModuleBase(proc, L"jvm.dll", &g_target.jvmDllBase, &g_target.jvmDllSize)) {
        setError("jvm_dll_not_found");
        return 0;
    }

    uint64_t jvmBase = g_target.jvmDllBase;

    VMStructEntryLayout structLayout;
    VMTypeEntryLayout typeLayout;
    VMIntConstantLayout intLayout;
    VMLongConstantLayout longLayout;
    readEntryLayoutOffsets(proc, jvmBase, &structLayout, &typeLayout, &intLayout, &longLayout);

    uint64_t structsPtr = 0, typesPtr = 0, intConstsPtr = 0, longConstsPtr = 0;

    if (!parsePEExport(proc, jvmBase, "gHotSpotVMStructs", &structsPtr) || structsPtr == 0) {
        setError("export_not_found:gHotSpotVMStructs");
        return 0;
    }
    if (!parsePEExport(proc, jvmBase, "gHotSpotVMTypes", &typesPtr) || typesPtr == 0) {
        setError("export_not_found:gHotSpotVMTypes");
        return 0;
    }
    parsePEExport(proc, jvmBase, "gHotSpotVMIntConstants", &intConstsPtr);
    parsePEExport(proc, jvmBase, "gHotSpotVMLongConstants", &longConstsPtr);

    if (!readVMStructTable(proc, structsPtr, structLayout)) {
        setError("read_struct_table_failed");
        return 0;
    }
    readVMTypeTable(proc, typesPtr, typeLayout);
    if (intConstsPtr != 0) readVMIntConstants(proc, intConstsPtr, intLayout);
    if (longConstsPtr != 0) readVMLongConstants(proc, longConstsPtr, longLayout);

    extractCompressionParams();

    g_target.structMapReady = true;
    FVM_LOG("bootstrap_target complete: pid=%lu, jvmBase=0x%llX, structMap=%zu, typeMap=%zu",
            (unsigned long)g_target.pid, (unsigned long long)g_target.jvmDllBase,
            g_structMap.size(), g_typeMap.size());
    FVM_LOG("compression: useCompressedOops=%d, narrowOopBase=0x%llX, narrowOopShift=%d",
            (int)g_target.useCompressedOops,
            (unsigned long long)g_target.narrowOopBase, g_target.narrowOopShift);
    FVM_LOG("compression: useCompressedClassPtrs=%d, narrowKlassBase=0x%llX, narrowKlassShift=%d",
            (int)g_target.useCompressedClassPointers,
            (unsigned long long)g_target.narrowKlassBase, g_target.narrowKlassShift);
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_shutdown() {
    if (g_target.handle != NULL) {
        CloseHandle(g_target.handle);
        g_target = TargetProcess{};
    }
    g_structMap.clear();
    g_typeMap.clear();
    g_intConstants.clear();
    g_longConstants.clear();
    g_fieldInfoCache.clear();

    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) const char* forgevm_last_error() {
    return g_lastError.c_str();
}

extern "C" __declspec(dllexport) void forgevm_exit_jvm(int exitCode) {
    ExitProcess((UINT)exitCode);
}

extern "C" __declspec(dllexport) int forgevm_exit_process(unsigned long long pid, int exitCode) {
    HANDLE target = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (target == NULL) {
        setError("open_target_process_failed");
        return 0;
    }
    BOOL ok = TerminateProcess(target, (UINT)exitCode);
    CloseHandle(target);
    if (!ok) {
        setError("terminate_target_process_failed");
        return 0;
    }
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) void forgevm_set_log_dir(const char* logDir) {
    std::string path(logDir);
    if (!path.empty() && path.back() != '\\' && path.back() != '/')
        path += '\\';
    path += "fvm-transform.log";
    fvm_log_init(path.c_str());
}

extern "C" __declspec(dllexport) unsigned long long forgevm_structmap_count() {
    return static_cast<unsigned long long>(g_structMap.size());
}

extern "C" __declspec(dllexport) unsigned long long forgevm_typemap_count() {
    return static_cast<unsigned long long>(g_typeMap.size());
}

extern "C" __declspec(dllexport) const char* forgevm_compression_info() {
    return g_compressionDetectLog.c_str();
}

/* ============================================================
 * Load-time filters.
 *
 *   Java agent attach:
 *     hook jvm.dll!JVM_EnqueueOperation — arg0 (rdx) is the agent
 *     library path as UTF-8. attach() uses CreateRemoteThread to
 *     reach this entry, so DisableAttachMechanism can't cover it.
 *
 *   Native library load:
 *     hook ntdll!LdrLoadDll — the bottom of every user-mode DLL
 *     load path (LoadLibraryW / LoadLibraryExW / kernelbase / JNI
 *     direct LoadLibrary / etc. all funnel here). The DLL name
 *     arrives in r8 as a UNICODE_STRING; the trampoline matches it
 *     against a resident pattern blob in-process (no IPC). On block
 *     we return STATUS_DLL_NOT_FOUND (0xC0000135) so callers see the
 *     normal "DLL not found" error path, not a crash.
 *
 *   Process creation:
 *     hook ntdll!NtCreateUserProcess — same in-process matching
 *     against the wide image path. Block returns STATUS_ACCESS_DENIED.
 *
 *   All three trampolines own a resident mode + pattern blob refreshed
 *   in place by the install path on each filter update — fully
 *   self-contained, no per-call IPC.
 * ============================================================ */

namespace {
    /* Definitions for the forward-declared globals above. */
    PatchState g_javaAgentPatch;
    PatchState g_nativeLoadPatch;
    PatchState g_jvmtiPatch;
    PatchState g_processCreatePatch;
    uint64_t g_jvmtiGetEnvAddr = 0;
    bool g_jvmtiGetEnvLocateFailed = false;
}

// Write to remote code section (handles VirtualProtectEx for .text pages)
static bool writeRemoteCode(HANDLE proc, uint64_t addr, const void* buf, size_t size) {
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        FVM_LOG("ban_java_agent: VirtualProtectEx failed: %lu", GetLastError());
        return false;
    }
    bool ok = writeRemoteMem(proc, addr, buf, size);
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(addr), size);
    DWORD dummy;
    VirtualProtectEx(proc, reinterpret_cast<LPVOID>(addr), size, oldProtect, &dummy);
    return ok;
}

/* Resolve a jvm.dll export in the target process. Fast path uses a local
 * DONT_RESOLVE_DLL_REFERENCES load + RVA translation; falls back to the
 * existing parsePEExport() which walks the remote PE export table. */
static uint64_t resolveJvmExport(HANDLE proc, const char* name) {
    HMODULE localJvm = LoadLibraryExA("jvm.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (localJvm) {
        FARPROC localAddr = GetProcAddress(localJvm, name);
        if (localAddr) {
            uint64_t rva = reinterpret_cast<uint64_t>(localAddr) - reinterpret_cast<uint64_t>(localJvm);
            FreeLibrary(localJvm);
            return g_target.jvmDllBase + rva;
        }
        FreeLibrary(localJvm);
    }
    uint64_t addr = 0;
    if (parsePEExport(proc, g_target.jvmDllBase, name, &addr) && addr != 0) {
        return addr;
    }
    return 0;
}

/* Find free region within 2GB of `near` big enough for `size`.
 * A Windows E9 rel32 requires the trampoline to be reachable from the patch site. */
static uint64_t findFreeRegionNear(HANDLE proc, uint64_t anchor, size_t size) {
    const uint64_t MAX_DELTA = (1ULL << 31) - (1ULL << 21); // a bit under 2GB to leave slack
    const uint64_t GRANULARITY = 0x10000ULL;                // 64KB
    uint64_t minAddr = (anchor > MAX_DELTA) ? (anchor - MAX_DELTA) : GRANULARITY;
    uint64_t maxAddr = anchor + MAX_DELTA;

    // Round up to allocation granularity
    minAddr = (minAddr + GRANULARITY - 1) & ~(GRANULARITY - 1);

    uint64_t addr = minAddr;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxAddr) {
        if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            break;
        }
        if (mbi.State == MEM_FREE) {
            uint64_t base   = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            uint64_t region = (base + GRANULARITY - 1) & ~(GRANULARITY - 1);
            uint64_t end    = base + mbi.RegionSize;
            if (region + size <= end && region + size <= maxAddr) {
                return region;
            }
        }
        addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr == 0) break;
    }
    return 0;
}

static void emitBytes(std::vector<uint8_t>& out, std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) out.push_back(b);
}

static void writeU64(std::vector<uint8_t>& out, size_t off, uint64_t v) {
    for (int i = 0; i < 8; i++) out[off + i] = static_cast<uint8_t>(v >> (i * 8));
}

/* Minimal label-based assembler for trampoline code. All control-flow uses
 * rel32 jumps whose displacements are computed by resolve() from recorded
 * labels, so jump offsets are never hand-counted (one wrong disp = crash on
 * every hooked call). RIP-relative data references target fixed page offsets
 * and are computed inline (the slot offset is a known constant), valid only for
 * instructions whose disp32 is the final field (mov/lea/movzx reg,[rip+d] and
 * jmp qword [rip+d]) — never a form with a trailing immediate. */
struct TrampAsm {
    std::vector<uint8_t>& code;
    std::unordered_map<std::string, size_t> labels;
    struct Fixup { size_t at; std::string target; };
    std::vector<Fixup> fixups;
    explicit TrampAsm(std::vector<uint8_t>& c) : code(c) {}

    void emit(std::initializer_list<uint8_t> b) { for (uint8_t x : b) code.push_back(x); }
    void label(const std::string& n) { labels[n] = code.size(); }

    // jmp rel32
    void jmp(const std::string& t) { code.push_back(0xE9); fixup32(t); }
    /* jcc rel32; cc is the two-byte opcode's second byte (0x84=JE, 0x85=JNE,
     * 0x82=JB, 0x86=JBE, 0x87=JA, ...) */
    void jcc(uint8_t cc, const std::string& t) { code.push_back(0x0F); code.push_back(cc); fixup32(t); }

    /* RIP-relative disp32 to a fixed page offset; emit the opcode/ModRM bytes
     * first, then call this to append the 4 disp bytes. */
    void ripDisp(size_t slot) {
        size_t at = code.size();
        int64_t disp = static_cast<int64_t>(slot) - static_cast<int64_t>(at + 4);
        int32_t d = static_cast<int32_t>(disp);
        emit({(uint8_t)d, (uint8_t)(d >> 8), (uint8_t)(d >> 16), (uint8_t)(d >> 24)});
    }

    void fixup32(const std::string& t) {
        size_t at = code.size();
        emit({0, 0, 0, 0});
        fixups.push_back({at, t});
    }

    bool resolve() {
        for (const auto& f : fixups) {
            auto it = labels.find(f.target);
            if (it == labels.end()) return false;
            int64_t disp = static_cast<int64_t>(it->second) - static_cast<int64_t>(f.at + 4);
            if (disp < INT32_MIN || disp > INT32_MAX) return false;
            int32_t d = static_cast<int32_t>(disp);
            code[f.at + 0] = (uint8_t)d;
            code[f.at + 1] = (uint8_t)(d >> 8);
            code[f.at + 2] = (uint8_t)(d >> 16);
            code[f.at + 3] = (uint8_t)(d >> 24);
        }
        return true;
    }
};

/* Shared in-process substring matcher. Precondition on entry: [rsp+0x48] holds
 * the path buffer pointer and [rsp+0x50] holds the element count N. Reads the
 * resident mode byte at page+0x308 and the pattern blob at page+0x310
 * ([count:1] then per pattern [len:1][lowercased '\'→'/' bytes]; len 0 = "*").
 * Matching is case-insensitive ASCII substring; on completion it jumps to label
 * "allow" or "block", which the caller MUST define. `wide` reads 2-byte wchars
 * (non-ASCII wc skips the window); else 1-byte chars. Clobbers rax/rcx/rdx/r8/
 * r9/r10/r11 and scratch slots [rsp+0x40,0x58,0x60,0x68,0x70,0x78]. Label names
 * pat_loop/have_len/i_loop/j_loop/no_lower/no_slash/mismatch/decide/whitelist
 * are reserved — the caller must not reuse them. */
static void emitSubstringMatcher(TrampAsm& a, bool wide) {
    const size_t SLOT_MODE = 0x308;
    const size_t SLOT_BLOB = 0x310;

    a.emit({0x0F, 0xB6, 0x05}); a.ripDisp(SLOT_MODE);  // movzx eax, byte [rip+mode]
    a.emit({0x84, 0xC0});                       // test al, al
    a.jcc(0x84, "block");                       // je block  (mode None → block all)

    a.emit({0x4C, 0x8D, 0x15}); a.ripDisp(SLOT_BLOB);  // lea r10, [rip+blob]
    a.emit({0x41, 0x0F, 0xB6, 0x02});           // movzx eax, byte [r10]  ; pattern count
    a.emit({0x48, 0x89, 0x44, 0x24, 0x68});     // mov [rsp+0x68], rax
    a.emit({0x49, 0x83, 0xC2, 0x01});           // add r10, 1
    a.emit({0x4C, 0x89, 0x54, 0x24, 0x58});     // mov [rsp+0x58], r10    ; walker
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x00});     // mov byte [rsp+0x40], 0 ; matched=0

    a.label("pat_loop");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x68});     // mov rax, [rsp+0x68]
    a.emit({0x48, 0x85, 0xC0});                 // test rax, rax
    a.jcc(0x84, "decide");
    a.emit({0x48, 0xFF, 0xC8});                 // dec rax
    a.emit({0x48, 0x89, 0x44, 0x24, 0x68});     // mov [rsp+0x68], rax
    a.emit({0x4C, 0x8B, 0x54, 0x24, 0x58});     // mov r10, [rsp+0x58]
    a.emit({0x41, 0x0F, 0xB6, 0x0A});           // movzx ecx, byte [r10]  ; L
    a.emit({0x49, 0x83, 0xC2, 0x01});           // add r10, 1
    a.emit({0x48, 0x89, 0x4C, 0x24, 0x60});     // mov [rsp+0x60], rcx    ; L
    a.emit({0x4C, 0x89, 0x54, 0x24, 0x70});     // mov [rsp+0x70], r10    ; pattern bytes
    a.emit({0x4C, 0x89, 0xD0});                 // mov rax, r10
    a.emit({0x48, 0x01, 0xC8});                 // add rax, rcx
    a.emit({0x48, 0x89, 0x44, 0x24, 0x58});     // mov [rsp+0x58], rax    ; walker → next
    a.emit({0x48, 0x85, 0xC9});                 // test rcx, rcx          ; L==0 ("*")
    a.jcc(0x85, "have_len");
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x01});     // matched=1
    a.jmp("decide");
    a.label("have_len");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x50});     // mov rax, [rsp+0x50]    ; N
    a.emit({0x48, 0x39, 0xC8});                 // cmp rax, rcx
    a.jcc(0x82, "pat_loop");                    // jb (N<L → next pattern)
    a.emit({0x48, 0x29, 0xC8});                 // sub rax, rcx           ; maxStart
    a.emit({0x48, 0xFF, 0xC0});                 // inc rax                ; positions
    a.emit({0x48, 0x89, 0x44, 0x24, 0x78});     // mov [rsp+0x78], rax
    a.emit({0x4C, 0x8B, 0x44, 0x24, 0x48});     // mov r8, [rsp+0x48]     ; cur = buffer

    a.label("i_loop");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x78});     // mov rax, [rsp+0x78]
    a.emit({0x48, 0x85, 0xC0});                 // test rax, rax
    a.jcc(0x84, "pat_loop");
    a.emit({0x48, 0xFF, 0xC8});                 // dec rax
    a.emit({0x48, 0x89, 0x44, 0x24, 0x78});     // mov [rsp+0x78], rax
    a.emit({0x4C, 0x8B, 0x4C, 0x24, 0x70});     // mov r9, [rsp+0x70]     ; pattern bytes
    a.emit({0x48, 0x8B, 0x4C, 0x24, 0x60});     // mov rcx, [rsp+0x60]    ; L (j)
    a.emit({0x4D, 0x89, 0xC2});                 // mov r10, r8            ; scan = cur

    a.label("j_loop");
    if (wide) {
        a.emit({0x41, 0x0F, 0xB7, 0x02});       // movzx eax, word [r10]
        a.emit({0x3D, 0xFF, 0x00, 0x00, 0x00}); // cmp eax, 0xFF
        a.jcc(0x87, "mismatch");                // ja mismatch (non-ASCII)
    } else {
        a.emit({0x41, 0x0F, 0xB6, 0x02});       // movzx eax, byte [r10]
    }
    a.emit({0x3C, 0x41});                       // cmp al, 'A'
    a.jcc(0x82, "no_lower");
    a.emit({0x3C, 0x5A});                       // cmp al, 'Z'
    a.jcc(0x87, "no_lower");
    a.emit({0x04, 0x20});                       // add al, 0x20
    a.label("no_lower");
    a.emit({0x3C, 0x5C});                       // cmp al, '\\'
    a.jcc(0x85, "no_slash");
    a.emit({0xB0, 0x2F});                       // mov al, '/'
    a.label("no_slash");
    a.emit({0x41, 0x0F, 0xB6, 0x11});           // movzx edx, byte [r9]   ; pattern[j]
    a.emit({0x38, 0xD0});                       // cmp al, dl
    a.jcc(0x85, "mismatch");
    if (wide) a.emit({0x49, 0x83, 0xC2, 0x02}); // add r10, 2
    else      a.emit({0x49, 0x83, 0xC2, 0x01}); // add r10, 1
    a.emit({0x49, 0x83, 0xC1, 0x01});           // add r9, 1
    a.emit({0x48, 0xFF, 0xC9});                 // dec rcx
    a.jcc(0x85, "j_loop");
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x01});     // matched=1
    a.jmp("decide");
    a.label("mismatch");
    if (wide) a.emit({0x49, 0x83, 0xC0, 0x02}); // add r8, 2
    else      a.emit({0x49, 0x83, 0xC0, 0x01}); // add r8, 1
    a.jmp("i_loop");

    a.label("decide");
    a.emit({0x0F, 0xB6, 0x05}); a.ripDisp(SLOT_MODE);  // movzx eax, byte [rip+mode]
    a.emit({0x0F, 0xB6, 0x54, 0x24, 0x40});     // movzx edx, byte [rsp+0x40] ; matched
    a.emit({0x3C, 0x01});                       // cmp al, 1 (Blacklist?)
    a.jcc(0x85, "whitelist");
    a.emit({0x84, 0xD2});                       // test dl, dl
    a.jcc(0x85, "block");                       // blacklist + match → block
    a.jmp("allow");
    a.label("whitelist");
    a.emit({0x84, 0xD2});                       // test dl, dl
    a.jcc(0x84, "block");                       // whitelist + no match → block
    a.jmp("allow");
}

/* ---- conservative x64 prologue length decoder ----------------------------
 * A 5-byte E9 patch must not split an instruction, or the trampoline's
 * prologue replay mis-decodes and crashes (observed on the NtCreateUserProcess
 * syscall stub). alignedPrologueLen decodes whole instructions from `p` until
 * the cumulative length reaches `need`, returning that instruction-aligned
 * length. It only advances over encodings it fully understands (the forms that
 * appear in real function prologues) and returns 0 on anything unfamiliar, so
 * callers fall back to the legacy fixed 5-byte copy rather than guess wrong. */
static size_t modrmBytes(const uint8_t* p, size_t avail) {
    if (avail < 1) return 0;
    uint8_t modrm = p[0];
    uint8_t mod = modrm >> 6;
    uint8_t rm  = modrm & 7;
    size_t len = 1;                            // ModRM byte
    if (mod == 3) return len;                  // register-direct: no SIB/disp
    bool hasSib = (rm == 4);
    uint8_t base = 0;
    if (hasSib) {
        if (avail < 2) return 0;
        base = p[1] & 7;
        len += 1;                              // SIB byte
    }
    if (mod == 0) {
        if (!hasSib && rm == 5) len += 4;          // RIP-relative disp32
        else if (hasSib && base == 5) len += 4;    // SIB, no base → disp32
    } else if (mod == 1) {
        len += 1;                              // disp8
    } else {                                   // mod == 2
        len += 4;                              // disp32
    }
    return len;
}

static size_t alignedPrologueLen(const uint8_t* p, size_t avail, size_t need) {
    size_t i = 0;
    int guard = 0;
    while (i < need) {
        if (++guard > 16) return 0;
        size_t start = i;
        uint8_t rex = 0;
        // prefixes: skip legacy + REX (REX last before opcode). Bail on operand/
        // address-size overrides — they change immediate/disp widths we don't model.
        for (;;) {
            if (i >= avail) return 0;
            uint8_t b = p[i];
            if (b == 0x66 || b == 0x67) return 0;
            if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                b == 0x64 || b == 0x65) { i++; continue; }
            if ((b & 0xF0) == 0x40) { rex = b; i++; continue; }
            break;
        }
        if (i >= avail) return 0;
        uint8_t op = p[i++];
        bool rexW = (rex & 0x08) != 0;

        if (op == 0x0F) {                       // two-byte opcode (whitelist)
            if (i >= avail) return 0;
            uint8_t op2 = p[i++];
            if (op2 == 0x1E || op2 == 0x1F ||           // hint-NOP / endbr64
                op2 == 0xB6 || op2 == 0xB7 ||           // movzx
                op2 == 0xBE || op2 == 0xBF) {           // movsx
                size_t m = modrmBytes(p + i, avail - i);
                if (m == 0) return 0;
                i += m;
            } else {
                return 0;
            }
        } else if (op >= 0x50 && op <= 0x5F) {          // push/pop reg
            // no extra bytes
        } else if (op >= 0xB8 && op <= 0xBF) {          // mov reg, imm32 / imm64
            i += rexW ? 8 : 4;
        } else if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B ||
                   op == 0x8D ||                        // lea
                   op == 0x01 || op == 0x03 || op == 0x09 || op == 0x0B ||
                   op == 0x21 || op == 0x23 || op == 0x29 || op == 0x2B ||
                   op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3B ||
                   op == 0x84 || op == 0x85) {          // ModRM, no immediate
            size_t m = modrmBytes(p + i, avail - i);
            if (m == 0) return 0;
            i += m;
        } else if (op == 0x83 || op == 0xC6) {          // grp1 imm8 / mov r/m8,imm8
            size_t m = modrmBytes(p + i, avail - i);
            if (m == 0) return 0;
            i += m + 1;
        } else if (op == 0x81 || op == 0xC7) {          // grp1 imm32 / mov r/m,imm32
            size_t m = modrmBytes(p + i, avail - i);
            if (m == 0) return 0;
            i += m + 4;
        } else if (op == 0x90) {                        // nop
            // no extra bytes
        } else {
            return 0;                           // unknown — caller falls back to 5
        }
        if (i > avail || i <= start) return 0;
    }
    return i;
}

/* Serialize a filter (mode + patterns) into the trampoline data page at 0x310:
 *   [count:1] then per pattern [len:1][lowercased '\'→'/' normalized bytes].
 * "*" → len 0 (match-all). Patterns with internal '*'/'?' are unsupported by the
 * in-process substring matcher and are skipped (logged). buf must be >= 0x400. */
static void serializeFilterBlob(std::vector<uint8_t>& buf, int mode,
                                const std::vector<std::string>& patterns);

/* Java-agent filter trampoline (JVM_EnqueueOperation). In-process pattern match
 * on the narrow (char*) path argument — no pipe/IPC. Data layout:
 *   +0x300  qword  abs jump target (origPlusN)
 *   +0x308  byte   mode (0=None/block all, 1=Blacklist, 2=Whitelist)
 *   +0x310  pattern blob ([count:1] then per pattern [len:1][lowercased bytes])
 *
 * Entry saves rcx/rdx/r8/r9, allows when the path pointer is null, else measures
 * the string (capped 900) and runs emitSubstringMatcher. Block returns -1 (see
 * note at the _block label). `pathInRdx` picks rdx (EnqueueOperation arg) vs rcx. */
static std::vector<uint8_t> buildFilterTrampoline(const uint8_t* savedPrologue,
                                                  size_t prologueLen,
                                                  uint64_t origPlusN,
                                                  int mode,
                                                  const std::vector<std::string>& patterns,
                                                  bool pathInRdx) {
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC);

    const size_t SLOT_JMP  = 0x300;
    const size_t SLOT_MODE = 0x308;
    const size_t SLOT_BLOB = 0x310;
    (void)SLOT_BLOB;

    std::vector<uint8_t> code;
    code.reserve(0x300);
    TrampAsm a(code);

    // --- prologue: frame + save arg regs ---
    a.emit({0x48, 0x81, 0xEC, 0x78, 0x04, 0x00, 0x00});        // sub rsp, 0x478
    a.emit({0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov [rsp+0x458], rcx
    a.emit({0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov [rsp+0x460], rdx
    a.emit({0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov [rsp+0x468], r8
    a.emit({0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov [rsp+0x470], r9

    // --- path ptr (narrow char*): rdx (java agent) or rcx → r8 ---
    if (pathInRdx) a.emit({0x4C, 0x8B, 0x84, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov r8, [rsp+0x460]
    else           a.emit({0x4C, 0x8B, 0x84, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov r8, [rsp+0x458]
    a.emit({0x4D, 0x85, 0xC0});                 // test r8, r8
    a.jcc(0x84, "allow");                       // je allow

    // --- N = strnlen(r8, 900) ---
    a.emit({0x4D, 0x89, 0xC2});                 // mov r10, r8
    a.emit({0x48, 0x31, 0xC9});                 // xor rcx, rcx
    a.label("nlen");
    a.emit({0x48, 0x81, 0xF9, 0x84, 0x03, 0x00, 0x00});  // cmp rcx, 0x384
    a.jcc(0x83, "nlen_done");                   // jae nlen_done
    a.emit({0x41, 0x8A, 0x02});                 // mov al, [r10]
    a.emit({0x84, 0xC0});                       // test al, al
    a.jcc(0x84, "nlen_done");                   // je nlen_done
    a.emit({0x49, 0xFF, 0xC2});                 // inc r10
    a.emit({0x48, 0xFF, 0xC1});                 // inc rcx
    a.jmp("nlen");
    a.label("nlen_done");
    a.emit({0x4C, 0x89, 0x44, 0x24, 0x48});     // mov [rsp+0x48], r8   ; buffer
    a.emit({0x48, 0x89, 0x4C, 0x24, 0x50});     // mov [rsp+0x50], rcx  ; N

    emitSubstringMatcher(a, /*wide=*/false);

    // --- allow: restore args, replay prologue, jump on ---
    a.label("allow");
    a.emit({0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov rcx, [rsp+0x458]
    a.emit({0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov rdx, [rsp+0x460]
    a.emit({0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov r8, [rsp+0x468]
    a.emit({0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov r9, [rsp+0x470]
    a.emit({0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});        // add rsp, 0x478
    // replay the whole saved prologue (instruction-aligned, may be >5) then jump on
    for (size_t i = 0; i < prologueLen; i++) code.push_back(savedPrologue[i]);
    a.emit({0xFF, 0x25}); a.ripDisp(SLOT_JMP);  // jmp qword [rip+abs_jump]

    /* _block — return -1 (not 0). HotSpot attach protocol: JVM_EnqueueOperation
     * returning 0 means "enqueued, wait for response on pipe"; the attacher then
     * blocks on connectPipe() forever since we short-circuited. Non-zero makes
     * the JDK-side native enqueue throw IOException immediately, handled cleanly. */
    a.label("block");
    a.emit({0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});  // add rsp, 0x478
    a.emit({0xB8, 0xFF, 0xFF, 0xFF, 0xFF});              // mov eax, -1
    a.emit({0xC3});                                       // ret

    if (!a.resolve()) {
        FVM_LOG("buildFilterTrampoline: label resolve failed");
        return {};
    }
    if (code.size() > SLOT_JMP) {
        FVM_LOG("buildFilterTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    writeU64(buf, SLOT_JMP, origPlusN);
    buf[SLOT_MODE] = static_cast<uint8_t>(mode);
    serializeFilterBlob(buf, mode, patterns);
    return buf;
}

/* Core install routine shared by ban_java_agent and ban_native_load.
 * Looks up `exportName` in jvm.dll, saves the first 5 bytes, allocates
 * a nearby trampoline page, writes the trampoline image, and redirects
 * the export's prologue via E9 rel32. On any failure, frees the page. */
static int installFilterTrampoline(PatchState& state,
                                    const char* exportName,
                                    bool pathInRdx,
                                    int mode,
                                    const std::vector<std::string>& patterns,
                                    const char* logTag) {
    if (!g_target.structMapReady) {
        setError("not_bootstrapped");
        return 0;
    }
    HANDLE proc = g_target.handle;

    if (state.patched) {
        /* Already hooked — refresh the resident mode + pattern blob in place. */
        std::vector<uint8_t> data(0x400, 0xCC);
        data[0x308] = static_cast<uint8_t>(mode);
        serializeFilterBlob(data, mode, patterns);
        if (!writeRemoteMem(proc, state.trampolineAddr + 0x308,
                            &data[0x308], 0x400 - 0x308)) {
            setError("blob_update_failed");
            return 0;
        }
        FVM_LOG("%s: refreshed resident pattern blob (mode=%d, %zu patterns)",
                logTag, mode, patterns.size());
        setError("ok");
        return 1;
    }

    uint64_t addr = resolveJvmExport(proc, exportName);
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("%s: %s @ 0x%llX", logTag, exportName, (unsigned long long)addr);

    uint8_t saved[16] = {};
    if (!readRemoteMem(proc, addr, saved, sizeof(saved))) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("%s: original prologue: %02X %02X %02X %02X %02X", logTag,
            saved[0], saved[1], saved[2], saved[3], saved[4]);

    /* MSVC incremental-linking emits each exported function as a 5-byte
     * `JMP rel32` thunk that jumps to the real function body. Modern JDK 17+
     * jvm.dll ships this way, so `JVM_EnqueueOperation`'s prologue is
     * `E9 xx xx xx xx`. Patching the thunk itself would corrupt other code
     * (the byte after E9+4 may be the next thunk's first byte), but we can
     * just follow the jump and hook the real body instead. */
    for (int hop = 0; hop < 2 && saved[0] == 0xE9; hop++) {
        int32_t rel = (int32_t)saved[1]
                    | ((int32_t)saved[2] << 8)
                    | ((int32_t)saved[3] << 16)
                    | ((int32_t)saved[4] << 24);
        uint64_t realAddr = addr + 5 + (int64_t)rel;
        FVM_LOG("%s: prologue is JMP thunk, following 0x%llX -> 0x%llX",
                logTag, (unsigned long long)addr, (unsigned long long)realAddr);
        if (!readRemoteMem(proc, realAddr, saved, sizeof(saved))) {
            setError("read_real_prologue_failed");
            return 0;
        }
        FVM_LOG("%s: real prologue: %02X %02X %02X %02X %02X", logTag,
                saved[0], saved[1], saved[2], saved[3], saved[4]);
        addr = realAddr;
    }

    // Refuse dangerous starters (rel jumps/calls we can't safely relocate).
    uint8_t b0 = saved[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        setError("unsafe_prologue");
        return 0;
    }

    // Copy a whole number of instructions (>=5) so the E9 patch never splits one.
    size_t prologueLen = alignedPrologueLen(saved, sizeof(saved), 5);
    if (prologueLen == 0) prologueLen = 5;
    FVM_LOG("%s: prologue copy length = %zu bytes", logTag, prologueLen);

    const size_t kPage = 0x400;
    uint64_t allocHint = findFreeRegionNear(proc, addr, kPage);
    if (allocHint == 0) {
        setError("no_nearby_free_region");
        return 0;
    }
    void* allocated = VirtualAllocEx(proc, reinterpret_cast<LPVOID>(allocHint), kPage,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocated) {
        setError("virtual_alloc_failed");
        return 0;
    }
    uint64_t trampAddr = reinterpret_cast<uint64_t>(allocated);

    int64_t delta = static_cast<int64_t>(trampAddr) - static_cast<int64_t>(addr + 5);
    if (delta < static_cast<int64_t>(INT32_MIN) || delta > static_cast<int64_t>(INT32_MAX)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("tramp_out_of_rel32_range");
        return 0;
    }
    FVM_LOG("%s: trampoline @ 0x%llX (delta=%lld)", logTag,
            (unsigned long long)trampAddr, (long long)delta);

    std::vector<uint8_t> image = buildFilterTrampoline(
        saved, prologueLen, addr + prologueLen, mode, patterns, pathInRdx);
    if (image.empty()) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_build_failed");
        return 0;
    }
    if (!writeRemoteMem(proc, trampAddr, image.data(), image.size())) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_write_failed");
        return 0;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(trampAddr), image.size());

    uint8_t patch[16];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);
    for (size_t i = 5; i < prologueLen; i++) patch[i] = 0x90;  // NOP-pad split tail

    if (!writeRemoteCode(proc, addr, patch, prologueLen)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[16] = {};
    readRemoteMem(proc, addr, verify, prologueLen);
    if (memcmp(verify, patch, prologueLen) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = prologueLen;
    memcpy(state.original, saved, prologueLen);
    state.patched = true;
    state.trampolineAddr = trampAddr;
    state.trampolineSize = kPage;
    state.trampolineInstalled = true;

    FVM_LOG("%s: installed trampoline + E9 patch (verified)", logTag);
    setError("ok");
    return 1;
}

static int uninstallFilterTrampoline(PatchState& state, const char* logTag) {
    /* Only requires a valid handle — see installLdrLoadDllFilter rationale. */
    if (g_target.handle == NULL) {
        setError("no_target_handle");
        return 0;
    }
    if (!state.patched || state.targetAddr == 0) {
        setError("not_patched");
        return 0;
    }

    HANDLE proc = g_target.handle;
    if (!writeRemoteCode(proc, state.targetAddr, state.original, state.patchSize)) {
        setError("restore_failed");
        return 0;
    }

    uint8_t verify[16] = {};
    readRemoteMem(proc, state.targetAddr, verify, state.patchSize);
    if (memcmp(verify, state.original, state.patchSize) != 0) {
        setError("restore_verify_failed");
        return 0;
    }
    state.patched = false;
    FVM_LOG("%s: restored original bytes (verified)", logTag);

    if (state.trampolineInstalled && state.trampolineAddr != 0) {
        VirtualFreeEx(proc, reinterpret_cast<LPVOID>(state.trampolineAddr), 0, MEM_RELEASE);
        FVM_LOG("%s: released trampoline @ 0x%llX", logTag,
                (unsigned long long)state.trampolineAddr);
        state.trampolineAddr = 0;
        state.trampolineSize = 0;
        state.trampolineInstalled = false;
    }
    setError("ok");
    return 1;
}

/* ============================================================
 * ntdll!LdrLoadDll hook — native library load filter (deeper sink)
 *
 * LdrLoadDll is the bottom of every user-mode DLL load path. All of
 * LoadLibraryA/W, LoadLibraryExA/W, kernelbase internals and JNI code
 * that calls LoadLibrary directly funnel here. Hooking jvm.dll's
 * JVM_LoadLibrary (our earlier approach) only caught System.load /
 * Runtime.load; it missed any DLL that JNI / malware loaded directly.
 * ============================================================ */

static uint64_t resolveNtdllExport(HANDLE proc, const char* exportName) {
    uint64_t base = 0, size = 0;
    if (!findModuleBase(proc, L"ntdll.dll", &base, &size) || base == 0) {
        /* A CREATE_SUSPENDED process has not run LdrInitializeThunk yet, so its
         * PEB loader module list is empty and EnumProcessModulesEx returns
         * nothing. ntdll.dll is nonetheless already mapped by the kernel, and
         * its load base is shared by every process in the same boot session,
         * so this process's own ntdll base is a valid stand-in for the remote
         * one. The export table is then read out of the remote mapping at that
         * base, which is present and readable even while suspended. */
        base = reinterpret_cast<uint64_t>(GetModuleHandleW(L"ntdll.dll"));
        if (base == 0) {
            return 0;
        }
    }
    uint64_t addr = 0;
    if (parsePEExport(proc, base, exportName, &addr) && addr != 0) {
        return addr;
    }
    return 0;
}

/* LdrLoadDll x64 signature:
 *   NTSTATUS NTAPI LdrLoadDll(PWSTR SearchPath,          // rcx  (may be NULL)
 *                             PULONG DllCharacteristics, // rdx
 *                             PUNICODE_STRING DllName,   // r8   ← the name
 *                             PHANDLE DllHandle);        // r9
 * UNICODE_STRING: { USHORT Length (+0); USHORT MaxLength (+2); PWSTR Buffer (+8); }
 *
 * Trampoline data layout (in-process matcher, no IPC):
 *   +0x300  qword  abs jump target (origPlusN or chain head)
 *   +0x308  byte   mode (0=None/block all, 1=Blacklist, 2=Whitelist)
 *   +0x310  pattern blob ([count:1] then per pattern [len:1][lowercased bytes])
 *
 * Control flow: a null UNICODE_STRING or Buffer falls through to allow.
 * Otherwise the wide name is matched directly against the resident pattern
 * blob via emitSubstringMatcher. On block we return STATUS_DLL_NOT_FOUND
 * (0xC0000135) so the loader maps it to a normal "DLL not found" error. */
/* replaySavedPrologue: true for a clean prologue — the trampoline replays the
 * original prologueLen bytes (instruction-aligned, >=5) then jumps to origPlusN
 * (= addr+prologueLen). false when chaining onto a pre-existing inline hook: the
 * saved prologue is itself a 5-byte rel jmp whose rel32 is relative to
 * LdrLoadDll, so replaying it from the trampoline would land at the wrong
 * address. Instead origPlusN carries the absolute resolved hook target and the
 * prologue bytes are NOP'd, so on allow we jump straight into the prior hook's
 * stub (which replays the genuine original bytes and returns to LdrLoadDll+5 on
 * its own — the chain completes itself). */
static std::vector<uint8_t> buildLdrLoadDllTrampoline(const uint8_t* savedPrologue,
                                                      size_t prologueLen,
                                                      uint64_t origPlusN,
                                                      int mode,
                                                      const std::vector<std::string>& patterns,
                                                      bool replaySavedPrologue) {
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC);

    const size_t SLOT_JMP  = 0x300;   // qword: absolute jump-on / chain target
    const size_t SLOT_MODE = 0x308;   // byte: 0=None(block all), 1=Blacklist, 2=Whitelist
    const size_t SLOT_BLOB = 0x310;   // [count:1] then per pattern [len:1][bytes]

    std::vector<uint8_t> code;
    code.reserve(0x300);
    TrampAsm a(code);

    // --- prologue: frame + save arg regs (rcx/rdx/r8/r9) ---
    a.emit({0x48, 0x81, 0xEC, 0x78, 0x04, 0x00, 0x00});        // sub rsp, 0x478
    a.emit({0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov [rsp+0x458], rcx
    a.emit({0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov [rsp+0x460], rdx
    a.emit({0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov [rsp+0x468], r8
    a.emit({0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov [rsp+0x470], r9

    // --- extract DllName (r8 = PUNICODE_STRING) Buffer + wchar count ---
    a.emit({0x4D, 0x85, 0xC0});                 // test r8, r8
    a.jcc(0x84, "allow");                       // je allow
    a.emit({0x41, 0x0F, 0xB7, 0x00});           // movzx eax, word [r8]   ; Length (bytes)
    a.emit({0x85, 0xC0});                       // test eax, eax
    a.jcc(0x84, "allow");                       // je allow
    a.emit({0x4D, 0x8B, 0x40, 0x08});           // mov r8, [r8+8]         ; Buffer (wchar*)
    a.emit({0x4D, 0x85, 0xC0});                 // test r8, r8
    a.jcc(0x84, "allow");                       // je allow
    a.emit({0xD1, 0xE8});                       // shr eax, 1             ; N = wchar count
    a.emit({0x3D, 0x00, 0x04, 0x00, 0x00});     // cmp eax, 0x400
    a.jcc(0x86, "n_ok");                        // jbe n_ok
    a.emit({0xB8, 0x00, 0x04, 0x00, 0x00});     // mov eax, 0x400         ; clamp N
    a.label("n_ok");
    a.emit({0x4C, 0x89, 0x44, 0x24, 0x48});     // mov [rsp+0x48], r8     ; buffer
    a.emit({0x48, 0x89, 0x44, 0x24, 0x50});     // mov [rsp+0x50], rax    ; N

    // --- mode 0 (None) → block everything ---
    a.emit({0x0F, 0xB6, 0x05}); a.ripDisp(SLOT_MODE);  // movzx eax, byte [rip+mode]
    a.emit({0x84, 0xC0});                       // test al, al
    a.jcc(0x84, "block");                       // je block

    // --- set up pattern walk ---
    a.emit({0x4C, 0x8D, 0x15}); a.ripDisp(SLOT_BLOB);  // lea r10, [rip+blob]
    a.emit({0x41, 0x0F, 0xB6, 0x02});           // movzx eax, byte [r10]  ; pattern count
    a.emit({0x48, 0x89, 0x44, 0x24, 0x68});     // mov [rsp+0x68], rax    ; count remaining
    a.emit({0x49, 0x83, 0xC2, 0x01});           // add r10, 1             ; → first len byte
    a.emit({0x4C, 0x89, 0x54, 0x24, 0x58});     // mov [rsp+0x58], r10    ; walker
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x00});     // mov byte [rsp+0x40], 0 ; matched = 0

    // --- per-pattern loop ---
    a.label("pat_loop");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x68});     // mov rax, [rsp+0x68]    ; count
    a.emit({0x48, 0x85, 0xC0});                 // test rax, rax
    a.jcc(0x84, "decide");                      // je decide
    a.emit({0x48, 0xFF, 0xC8});                 // dec rax
    a.emit({0x48, 0x89, 0x44, 0x24, 0x68});     // mov [rsp+0x68], rax
    a.emit({0x4C, 0x8B, 0x54, 0x24, 0x58});     // mov r10, [rsp+0x58]    ; → len byte
    a.emit({0x41, 0x0F, 0xB6, 0x0A});           // movzx ecx, byte [r10]  ; L
    a.emit({0x49, 0x83, 0xC2, 0x01});           // add r10, 1             ; → pattern bytes
    a.emit({0x48, 0x89, 0x4C, 0x24, 0x60});     // mov [rsp+0x60], rcx    ; L
    a.emit({0x4C, 0x89, 0x54, 0x24, 0x70});     // mov [rsp+0x70], r10    ; pattern bytes ptr
    a.emit({0x4C, 0x89, 0xD0});                 // mov rax, r10
    a.emit({0x48, 0x01, 0xC8});                 // add rax, rcx           ; next = bytes + L
    a.emit({0x48, 0x89, 0x44, 0x24, 0x58});     // mov [rsp+0x58], rax    ; walker → next
    a.emit({0x48, 0x85, 0xC9});                 // test rcx, rcx          ; L == 0 ? ("*")
    a.jcc(0x85, "have_len");                    // jne have_len
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x01});     // mov byte [rsp+0x40], 1 ; match-all
    a.jmp("decide");
    a.label("have_len");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x50});     // mov rax, [rsp+0x50]    ; N
    a.emit({0x48, 0x39, 0xC8});                 // cmp rax, rcx           ; N vs L
    a.jcc(0x82, "pat_loop");                    // jb pat_loop  (N<L → next pattern)
    a.emit({0x48, 0x29, 0xC8});                 // sub rax, rcx           ; maxStart = N-L
    a.emit({0x48, 0xFF, 0xC0});                 // inc rax                ; start position count
    a.emit({0x48, 0x89, 0x44, 0x24, 0x78});     // mov [rsp+0x78], rax
    a.emit({0x4C, 0x8B, 0x44, 0x24, 0x48});     // mov r8, [rsp+0x48]     ; cur = buffer

    // --- outer: each start position ---
    a.label("i_loop");
    a.emit({0x48, 0x8B, 0x44, 0x24, 0x78});     // mov rax, [rsp+0x78]
    a.emit({0x48, 0x85, 0xC0});                 // test rax, rax
    a.jcc(0x84, "pat_loop");                    // je pat_loop  (positions exhausted)
    a.emit({0x48, 0xFF, 0xC8});                 // dec rax
    a.emit({0x48, 0x89, 0x44, 0x24, 0x78});     // mov [rsp+0x78], rax
    a.emit({0x4C, 0x8B, 0x4C, 0x24, 0x70});     // mov r9, [rsp+0x70]     ; pattern bytes
    a.emit({0x48, 0x8B, 0x4C, 0x24, 0x60});     // mov rcx, [rsp+0x60]    ; L (j remaining)
    a.emit({0x4D, 0x89, 0xC2});                 // mov r10, r8            ; scan = cur

    // --- inner: compare L wchars at scan vs pattern ---
    a.label("j_loop");
    a.emit({0x41, 0x0F, 0xB7, 0x02});           // movzx eax, word [r10]  ; wc
    a.emit({0x3D, 0xFF, 0x00, 0x00, 0x00});     // cmp eax, 0xFF
    a.jcc(0x87, "mismatch");                    // ja mismatch  (non-ASCII)
    a.emit({0x3C, 0x41});                       // cmp al, 'A'
    a.jcc(0x82, "no_lower");                    // jb no_lower
    a.emit({0x3C, 0x5A});                       // cmp al, 'Z'
    a.jcc(0x87, "no_lower");                    // ja no_lower
    a.emit({0x04, 0x20});                       // add al, 0x20  (to lowercase)
    a.label("no_lower");
    a.emit({0x3C, 0x5C});                       // cmp al, '\\'
    a.jcc(0x85, "no_slash");                    // jne no_slash
    a.emit({0xB0, 0x2F});                       // mov al, '/'
    a.label("no_slash");
    a.emit({0x41, 0x0F, 0xB6, 0x11});           // movzx edx, byte [r9]   ; pattern[j]
    a.emit({0x38, 0xD0});                       // cmp al, dl
    a.jcc(0x85, "mismatch");                    // jne mismatch
    a.emit({0x49, 0x83, 0xC2, 0x02});           // add r10, 2             ; next wchar
    a.emit({0x49, 0x83, 0xC1, 0x01});           // add r9, 1              ; next pattern byte
    a.emit({0x48, 0xFF, 0xC9});                 // dec rcx
    a.jcc(0x85, "j_loop");                       // jne j_loop
    a.emit({0xC6, 0x44, 0x24, 0x40, 0x01});     // mov byte [rsp+0x40], 1 ; full match
    a.jmp("decide");
    a.label("mismatch");
    a.emit({0x49, 0x83, 0xC0, 0x02});           // add r8, 2              ; cur += 1 wchar
    a.jmp("i_loop");

    // --- decide allow/block from mode + matched ---
    a.label("decide");
    a.emit({0x0F, 0xB6, 0x05}); a.ripDisp(SLOT_MODE);  // movzx eax, byte [rip+mode]
    a.emit({0x0F, 0xB6, 0x54, 0x24, 0x40});     // movzx edx, byte [rsp+0x40] ; matched
    a.emit({0x3C, 0x01});                       // cmp al, 1   (Blacklist?)
    a.jcc(0x85, "whitelist");                   // jne whitelist
    a.emit({0x84, 0xD2});                       // test dl, dl
    a.jcc(0x85, "block");                       // jne block  (blacklist + match → block)
    a.jmp("allow");
    a.label("whitelist");
    a.emit({0x84, 0xD2});                       // test dl, dl
    a.jcc(0x84, "block");                       // je block   (whitelist + no match → block)
    // fallthrough → allow

    // --- allow: restore args, replay/skip prologue, jump on ---
    a.label("allow");
    a.emit({0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov rcx, [rsp+0x458]
    a.emit({0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov rdx, [rsp+0x460]
    a.emit({0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov r8, [rsp+0x468]
    a.emit({0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov r9, [rsp+0x470]
    a.emit({0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});        // add rsp, 0x478
    if (replaySavedPrologue) {
        // replay the whole saved prologue (instruction-aligned, may be >5) then jump on
        for (size_t i = 0; i < prologueLen; i++) code.push_back(savedPrologue[i]);
    } else {
        for (size_t i = 0; i < prologueLen; i++) code.push_back(0x90);  // chaining: prior hook replays original
    }
    a.emit({0xFF, 0x25}); a.ripDisp(SLOT_JMP);  // jmp qword [rip+abs_jump]

    // --- block: return STATUS_DLL_NOT_FOUND ---
    a.label("block");
    a.emit({0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});  // add rsp, 0x478
    a.emit({0xB8, 0x35, 0x01, 0x00, 0xC0});              // mov eax, 0xC0000135
    a.emit({0xC3});                                       // ret

    if (!a.resolve()) {
        FVM_LOG("buildLdrLoadDllTrampoline: label resolve failed");
        return {};
    }

    if (code.size() > SLOT_JMP) {
        FVM_LOG("buildLdrLoadDllTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    writeU64(buf, SLOT_JMP, origPlusN);
    buf[SLOT_MODE] = static_cast<uint8_t>(mode);
    serializeFilterBlob(buf, mode, patterns);
    return buf;
}

static void serializeFilterBlob(std::vector<uint8_t>& buf, int mode,
                                const std::vector<std::string>& patterns) {
    const size_t kBlob = 0x310;
    const size_t kEnd  = 0x400;
    size_t pos = kBlob + 1;   // reserve count byte
    uint8_t count = 0;
    for (const auto& pat : patterns) {
        if (count >= 255) break;
        size_t s = 0, e = pat.size();
        while (s < e && pat[s] == '*') s++;
        while (e > s && pat[e - 1] == '*') e--;
        std::string core = pat.substr(s, e - s);
        bool matchAll = core.empty() && !pat.empty();   // "*" / "**" → match all
        if (!matchAll && core.empty()) {
            continue;   // empty pattern matches nothing useful — skip
        }
        if (!matchAll && (core.find('*') != std::string::npos ||
                          core.find('?') != std::string::npos)) {
            /* The resident matcher is deliberately allocation-free and accepts
             * one literal core. Never silently drop a security rule: an
             * unsupported blacklist entry becomes match-all (block all), while
             * an unsupported whitelist entry is omitted (allow none through
             * that entry). Both directions fail closed. */
            FVM_LOG("serializeFilterBlob: unsupported pattern '%s' -> fail closed",
                    pat.c_str());
            if (mode == 1) {
                if (pos + 1 > kEnd) break;
                buf[pos++] = 0;
                count++;
                break;
            }
            continue;
        }
        if (matchAll) {
            if (pos + 1 > kEnd) break;
            buf[pos++] = 0;   // len 0 = match all
            count++;
            continue;
        }
        std::string norm;
        norm.reserve(core.size());
        for (unsigned char c : core) {
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
            if (c == '\\') c = '/';
            norm.push_back(static_cast<char>(c));
        }
        if (norm.size() > 200) norm.resize(200);
        if (pos + 1 + norm.size() > kEnd) break;
        buf[pos++] = static_cast<uint8_t>(norm.size());
        for (char c : norm) buf[pos++] = static_cast<uint8_t>(c);
        count++;
    }
    buf[kBlob] = count;
}

static int installLdrLoadDllFilter(PatchState& state, int mode,
                                   const std::vector<std::string>& patterns) {
    /* ntdll!LdrLoadDll patching only needs a valid process handle — ntdll is
     * mapped into every Win32 process from creation. structMapReady (which
     * requires jvm.dll) is not required, so this can run on a CREATE_SUSPENDED
     * new JVM during relaunch. */
    if (g_target.handle == NULL) {
        setError("no_target_handle");
        return 0;
    }
    HANDLE proc = g_target.handle;

    if (state.patched) {
        /* Already hooked — refresh the resident mode + pattern blob in place.
         * The trampoline code is unchanged (and may be executing on other
         * threads), so only the data region [0x308, 0x400) is rewritten. */
        std::vector<uint8_t> data(0x400, 0xCC);
        data[0x308] = static_cast<uint8_t>(mode);
        serializeFilterBlob(data, mode, patterns);
        if (!writeRemoteMem(proc, state.trampolineAddr + 0x308,
                            &data[0x308], 0x400 - 0x308)) {
            setError("blob_update_failed");
            return 0;
        }
        FVM_LOG("ban_native_load: refreshed resident pattern blob (mode=%d, %zu patterns)",
                mode, patterns.size());
        setError("ok");
        return 1;
    }

    uint64_t addr = resolveNtdllExport(proc, "LdrLoadDll");
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("ban_native_load: ntdll!LdrLoadDll @ 0x%llX", (unsigned long long)addr);

    uint8_t saved[16] = {};
    if (!readRemoteMem(proc, addr, saved, sizeof(saved))) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("ban_native_load: original prologue: %02X %02X %02X %02X %02X",
            saved[0], saved[1], saved[2], saved[3], saved[4]);

    /* When the prologue is already a 5-byte rel jmp (a pre-existing inline hook,
     * e.g. an EDR), we chain onto it rather than refuse: our trampoline jumps to
     * the prior hook's absolute target on allow, and that stub replays the
     * genuine original bytes and returns to LdrLoadDll+5 itself. Other dangerous
     * starters (call/short-jmp/Jcc/indirect) are rarer hook shapes we don't
     * understand well enough to relocate, so those are still refused. */
    bool chaining = false;
    uint64_t origJumpTarget = addr + 5;

    uint8_t b0 = saved[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        /* Dump enough state to identify the party that installed the prior hook:
         * where the jump lands (which module owns that address) and the full
         * module list of the target process so a suspicious unknown DLL stands
         * out. For the E9 case this also feeds the chain target. */
        if (b0 == 0xE9) {
            int32_t rel = (int32_t)saved[1]
                        | ((int32_t)saved[2] << 8)
                        | ((int32_t)saved[3] << 16)
                        | ((int32_t)saved[4] << 24);
            uint64_t target = addr + 5 + (int64_t)rel;
            chaining = true;
            origJumpTarget = target;
            FVM_LOG("ban_native_load: pre-hook JMP target = 0x%llX (rel32=%d) — chaining onto it",
                    (unsigned long long)target, (int)rel);

            HMODULE mods[1024];
            DWORD needed = 0;
            if (EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
                DWORD count = needed / sizeof(HMODULE);
                bool ownerFound = false;
                for (DWORD i = 0; i < count; i++) {
                    MODULEINFO info{};
                    if (!GetModuleInformation(proc, mods[i], &info, sizeof(info))) continue;
                    uint64_t base = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
                    uint64_t end  = base + info.SizeOfImage;
                    if (target >= base && target < end) {
                        wchar_t nameW[MAX_PATH] = {};
                        wchar_t pathW[MAX_PATH] = {};
                        GetModuleBaseNameW(proc, mods[i], nameW, MAX_PATH);
                        GetModuleFileNameExW(proc, mods[i], pathW, MAX_PATH);
                        char nameU8[MAX_PATH] = {};
                        char pathU8[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, nameW, -1, nameU8, sizeof(nameU8), nullptr, nullptr);
                        WideCharToMultiByte(CP_UTF8, 0, pathW, -1, pathU8, sizeof(pathU8), nullptr, nullptr);
                        FVM_LOG("ban_native_load: pre-hook JMP target owner = %s (base=0x%llX, +0x%llX) path=%s",
                                nameU8, (unsigned long long)base,
                                (unsigned long long)(target - base), pathU8);
                        ownerFound = true;
                        break;
                    }
                }
                if (!ownerFound) {
                    FVM_LOG("ban_native_load: pre-hook JMP target owner = (no module — likely VirtualAlloc'd trampoline, target in unmapped region)");
                }

                FVM_LOG("ban_native_load: target process module list (%lu entries):", (unsigned long)count);
                for (DWORD i = 0; i < count; i++) {
                    wchar_t nameW[MAX_PATH] = {};
                    wchar_t pathW[MAX_PATH] = {};
                    if (GetModuleBaseNameW(proc, mods[i], nameW, MAX_PATH) == 0) continue;
                    GetModuleFileNameExW(proc, mods[i], pathW, MAX_PATH);
                    MODULEINFO info{};
                    GetModuleInformation(proc, mods[i], &info, sizeof(info));
                    uint64_t base = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
                    char nameU8[MAX_PATH] = {};
                    char pathU8[MAX_PATH] = {};
                    WideCharToMultiByte(CP_UTF8, 0, nameW, -1, nameU8, sizeof(nameU8), nullptr, nullptr);
                    WideCharToMultiByte(CP_UTF8, 0, pathW, -1, pathU8, sizeof(pathU8), nullptr, nullptr);
                    FVM_LOG("  [%3lu] %s  base=0x%llX  size=0x%lX  path=%s",
                            (unsigned long)i, nameU8, (unsigned long long)base,
                            (unsigned long)info.SizeOfImage, pathU8);
                }
            } else {
                FVM_LOG("ban_native_load: EnumProcessModulesEx failed: %lu", (unsigned long)GetLastError());
            }
        }
        if (!chaining) {
            setError("unsafe_prologue");
            return 0;
        }
    }

    // Clean replay copies a whole number of instructions (>=5) so the E9 patch
    // never splits one; chaining just NOPs the 5-byte rel-jmp it overwrites.
    size_t prologueLen = 5;
    if (!chaining) {
        prologueLen = alignedPrologueLen(saved, sizeof(saved), 5);
        if (prologueLen == 0) prologueLen = 5;
        origJumpTarget = addr + prologueLen;
    }
    FVM_LOG("ban_native_load: prologue copy length = %zu bytes", prologueLen);

    const size_t kPage = 0x400;
    uint64_t allocHint = findFreeRegionNear(proc, addr, kPage);
    if (allocHint == 0) {
        setError("no_nearby_free_region");
        return 0;
    }
    void* allocated = VirtualAllocEx(proc, reinterpret_cast<LPVOID>(allocHint), kPage,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocated) {
        setError("virtual_alloc_failed");
        return 0;
    }
    uint64_t trampAddr = reinterpret_cast<uint64_t>(allocated);

    int64_t delta = static_cast<int64_t>(trampAddr) - static_cast<int64_t>(addr + 5);
    if (delta < static_cast<int64_t>(INT32_MIN) || delta > static_cast<int64_t>(INT32_MAX)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("tramp_out_of_rel32_range");
        return 0;
    }
    FVM_LOG("ban_native_load: trampoline @ 0x%llX (delta=%lld)",
            (unsigned long long)trampAddr, (long long)delta);

    std::vector<uint8_t> image = buildLdrLoadDllTrampoline(
        saved, prologueLen, origJumpTarget, mode, patterns,
        /*replaySavedPrologue=*/!chaining);
    if (image.empty()) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_build_failed");
        return 0;
    }
    if (!writeRemoteMem(proc, trampAddr, image.data(), image.size())) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_write_failed");
        return 0;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(trampAddr), image.size());

    uint8_t patch[16];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);
    for (size_t i = 5; i < prologueLen; i++) patch[i] = 0x90;  // NOP-pad split tail

    if (!writeRemoteCode(proc, addr, patch, prologueLen)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[16] = {};
    readRemoteMem(proc, addr, verify, prologueLen);
    if (memcmp(verify, patch, prologueLen) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = prologueLen;
    memcpy(state.original, saved, prologueLen);
    state.patched = true;
    state.trampolineAddr = trampAddr;
    state.trampolineSize = kPage;
    state.trampolineInstalled = true;

    FVM_LOG("ban_native_load: installed LdrLoadDll trampoline + E9 patch (verified)");
    setError("ok");
    return 1;
}

// Split a '\n'-joined pattern list (possibly empty/NULL) into a vector.
static std::vector<std::string> splitPatternsLF(const char* patternsLF) {
    std::vector<std::string> patterns;
    if (patternsLF != nullptr) {
        std::string acc;
        for (const char* p = patternsLF; *p; ++p) {
            if (*p == '\n') { if (!acc.empty()) patterns.push_back(acc); acc.clear(); }
            else acc.push_back(*p);
        }
        if (!acc.empty()) patterns.push_back(acc);
    }
    return patterns;
}

extern "C" __declspec(dllexport) int forgevm_ban_java_agent(int mode, const char* patternsLF) {
    return installFilterTrampoline(g_javaAgentPatch, "JVM_EnqueueOperation",
                                    /*pathInRdx=*/true, mode, splitPatternsLF(patternsLF),
                                    "ban_java_agent");
}

extern "C" __declspec(dllexport) int forgevm_unban_java_agent() {
    return uninstallFilterTrampoline(g_javaAgentPatch, "unban_java_agent");
}

/* mode: 0=None(block all), 1=Blacklist, 2=Whitelist. patternsLF: patterns
 * joined by '\n' (may be empty/NULL). Decisions are made in-process by the
 * trampoline against this resident pattern set — no per-load IPC. */
extern "C" __declspec(dllexport) int forgevm_ban_native_load(int mode, const char* patternsLF) {
    return installLdrLoadDllFilter(g_nativeLoadPatch, mode, splitPatternsLF(patternsLF));
}

extern "C" __declspec(dllexport) int forgevm_unban_native_load() {
    return uninstallFilterTrampoline(g_nativeLoadPatch, "unban_native_load");
}

/* ============================================================
 * JavaVM::GetEnv hook — JVMTI acquisition guard
 *
 * JNIInvokeInterface begins with three reserved NULL pointers followed by
 * DestroyJavaVM, AttachCurrentThread, DetachCurrentThread, GetEnv and
 * AttachCurrentThreadAsDaemon.  HotSpot keeps this immutable table inside
 * jvm.dll.  We locate it structurally instead of relying on private symbols or
 * version-specific RVAs, and accept the result only when every candidate agrees
 * on one executable GetEnv address.
 *
 * Caller identity is compiled to module address ranges when the policy is
 * installed/refreshed.  A module that appears later is deliberately unknown and
 * therefore denied: this keeps both blacklist and whitelist modes fail-closed.
 * Reissuing banJvmti(filter) refreshes the range table without repatching code.
 * ============================================================ */

struct JvmtiModuleRule {
    uint64_t begin = 0;
    uint64_t end = 0;
    bool allow = false;
};

static bool globMatchPath(const std::string& pattern, const std::string& text) {
    auto norm = [](unsigned char c) -> unsigned char {
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
        if (c == '\\') c = '/';
        return c;
    };
    size_t pi = 0, ti = 0, starPi = std::string::npos, starTi = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && pattern[pi] == '*') {
            starPi = pi++;
            starTi = ti;
        } else if (pi < pattern.size() &&
                   (pattern[pi] == '?' || norm((unsigned char)pattern[pi]) == norm((unsigned char)text[ti]))) {
            ++pi; ++ti;
        } else if (starPi != std::string::npos) {
            pi = starPi + 1;
            ti = ++starTi;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

static std::string widePathToUtf8(const wchar_t* value) {
    if (value == nullptr || *value == L'\0') return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, &out[0], n, nullptr, nullptr);
    out.pop_back();
    return out;
}

static bool isExecutableImageAddress(HANDLE proc, uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) return false;
    DWORD p = mbi.Protect & 0xFF;
    bool exec = p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    return mbi.State == MEM_COMMIT && exec;
}

static bool isReadonlyDataAddress(HANDLE proc, uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) return false;
    DWORD p = mbi.Protect & 0xFF;
    bool executable = p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                      p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    return mbi.State == MEM_COMMIT && !executable &&
           (p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY);
}

static uint64_t locateJavaVmGetEnv(HANDLE proc) {
    if (g_jvmtiGetEnvAddr != 0) return g_jvmtiGetEnvAddr;
    if (g_jvmtiGetEnvLocateFailed) return 0;

    const uint64_t base = g_target.jvmDllBase;
    const uint64_t size = g_target.jvmDllSize;
    if (base == 0 || size < 64) {
        g_jvmtiGetEnvLocateFailed = true;
        return 0;
    }

    const size_t chunkSize = 1 << 20;
    std::vector<uint8_t> chunk(chunkSize + 64);
    struct Candidate { uint64_t tableAddr; uint64_t getEnvAddr; };
    std::vector<Candidate> candidates;
    std::unordered_set<uint64_t> candidateTables;
    for (uint64_t off = 0; off < size; off += chunkSize) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(chunk.size(), size - off));
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(base + off), chunk.data(), want, &got) || got < 64) {
            continue;
        }
        for (size_t i = 0; i + 64 <= got; i += sizeof(uint64_t)) {
            const uint64_t* q = reinterpret_cast<const uint64_t*>(chunk.data() + i);
            if (q[0] != 0 || q[1] != 0 || q[2] != 0) continue;
            uint64_t tableAddr = base + off + i;
            if (!isReadonlyDataAddress(proc, tableAddr)) continue;
            bool functionsValid = true;
            for (int k = 3; k <= 7; ++k) {
                if (q[k] < base || q[k] >= base + size || !isExecutableImageAddress(proc, q[k])) {
                    functionsValid = false;
                    break;
                }
            }
            if (functionsValid && candidateTables.insert(tableAddr).second) {
                candidates.push_back({tableAddr, q[6]});
            }
        }
    }

    /* A function-table-shaped block alone is not unique in modern HotSpot. The
     * real JNI invocation table is referenced by the JavaVM object in jvm.dll's
     * writable data. Require exactly one non-executable pointer reference before
     * accepting it; this is the discriminator Oracle JDK 17 needs. */
    std::unordered_set<uint64_t> getEnvTargets;
    size_t referencedTables = 0;
    for (const auto& candidate : candidates) {
        size_t refs = 0;
        for (uint64_t off = 0; off < size; off += chunkSize) {
            size_t want = static_cast<size_t>(std::min<uint64_t>(chunk.size(), size - off));
            SIZE_T got = 0;
            if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(base + off), chunk.data(), want, &got) || got < sizeof(uint64_t)) {
                continue;
            }
            for (size_t i = 0; i + sizeof(uint64_t) <= got; i += sizeof(uint64_t)) {
                uint64_t value = *reinterpret_cast<const uint64_t*>(chunk.data() + i);
                uint64_t refAddr = base + off + i;
                if (value == candidate.tableAddr && isReadonlyDataAddress(proc, refAddr)) ++refs;
            }
        }
        if (refs == 1) {
            ++referencedTables;
            getEnvTargets.insert(candidate.getEnvAddr);
        }
    }
    if (referencedTables != 1 || getEnvTargets.size() != 1) {
        FVM_LOG("ban_jvmti: JNIInvokeInterface shapes=%zu referenced=%zu GetEnv targets=%zu",
                candidates.size(), referencedTables, getEnvTargets.size());
        g_jvmtiGetEnvLocateFailed = true;
        return 0;
    }
    g_jvmtiGetEnvAddr = *getEnvTargets.begin();
    FVM_LOG("ban_jvmti: uniquely located JNIInvokeInterface GetEnv @ 0x%llX",
            (unsigned long long)g_jvmtiGetEnvAddr);
    return g_jvmtiGetEnvAddr;
}

static bool buildJvmtiModuleRules(int mode, const std::vector<std::string>& patterns,
                                  std::vector<JvmtiModuleRule>* out) {
    out->clear();
    HANDLE proc = g_target.handle;
    std::vector<HMODULE> modules(256);
    DWORD needed = 0;
    for (;;) {
        if (!EnumProcessModulesEx(proc, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                  &needed, LIST_MODULES_ALL)) return false;
        if (needed <= modules.size() * sizeof(HMODULE)) break;
        modules.resize(needed / sizeof(HMODULE) + 32);
    }
    modules.resize(needed / sizeof(HMODULE));
    for (HMODULE module : modules) {
        MODULEINFO mi = {};
        wchar_t path[32768] = {};
        if (!GetModuleInformation(proc, module, &mi, sizeof(mi)) || mi.lpBaseOfDll == nullptr || mi.SizeOfImage == 0) continue;
        if (GetModuleFileNameExW(proc, module, path, ARRAYSIZE(path)) == 0) continue;
        std::string utf8 = widePathToUtf8(path);
        bool matched = false;
        for (const auto& pattern : patterns) {
            if (globMatchPath(pattern, utf8)) { matched = true; break; }
        }
        bool allow = mode == 0 ? false : (mode == 1 ? !matched : matched);
        uint64_t begin = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        out->push_back({begin, begin + mi.SizeOfImage, allow});
    }
    return !out->empty();
}

static std::vector<uint8_t> buildJvmtiGetEnvTrampoline(const uint8_t* savedPrologue,
                                                        size_t prologueLen,
                                                        uint64_t origPlusN,
                                                        int mode,
                                                        const std::vector<JvmtiModuleRule>& rules) {
    const size_t kPage = 0x1000;
    const size_t SLOT_JMP = 0x400;
    const size_t SLOT_MODE = 0x408;
    const size_t SLOT_COUNT = 0x409;
    const size_t SLOT_RULES = 0x410;
    std::vector<uint8_t> image(kPage, 0xCC);
    std::vector<uint8_t> code;
    TrampAsm a(code);

    // Preserve GetEnv arguments. Original return address is at [rsp+0x88].
    a.emit({0x48,0x81,0xEC,0x88,0x00,0x00,0x00});
    a.emit({0x48,0x89,0x4C,0x24,0x40});
    a.emit({0x48,0x89,0x54,0x24,0x48});
    a.emit({0x4C,0x89,0x44,0x24,0x50});
    a.emit({0x4C,0x89,0x4C,0x24,0x58});

    // Only JVMTI versions (interface type 0x30000000) are policy-controlled.
    a.emit({0x44,0x89,0xC0});                         // mov eax,r8d
    a.emit({0x25,0x00,0x00,0x00,0x70});              // and eax,70000000h
    a.emit({0x3D,0x00,0x00,0x00,0x30});              // cmp eax,30000000h
    a.jcc(0x85, "allow");
    a.emit({0x0F,0xB6,0x05}); a.ripDisp(SLOT_MODE);
    a.emit({0x84,0xC0});
    a.jcc(0x84, "block");                            // mode 0 = block all

    a.emit({0x48,0x8B,0x84,0x24,0x88,0x00,0x00,0x00}); // caller return address
    a.emit({0x0F,0xB6,0x0D}); a.ripDisp(SLOT_COUNT);  // ecx=count
    a.emit({0x4C,0x8D,0x15}); a.ripDisp(SLOT_RULES);  // r10=rules
    a.label("range_loop");
    a.emit({0x85,0xC9});
    a.jcc(0x84, "block");                            // unknown future module: fail closed
    a.emit({0x4D,0x8B,0x1A});                        // r11=[r10].begin
    a.emit({0x4C,0x39,0xD8});                        // cmp rax,r11
    a.jcc(0x82, "range_next");
    a.emit({0x4D,0x8B,0x5A,0x08});                   // r11=[r10+8].end
    a.emit({0x4C,0x39,0xD8});
    a.jcc(0x83, "range_next");
    a.emit({0x41,0x0F,0xB6,0x52,0x10});              // edx=allow
    a.emit({0x84,0xD2});
    a.jcc(0x85, "allow");
    a.jmp("block");
    a.label("range_next");
    a.emit({0x49,0x83,0xC2,0x18});                   // next 24-byte record
    a.emit({0xFF,0xC9});
    a.jmp("range_loop");

    a.label("allow");
    a.emit({0x48,0x8B,0x4C,0x24,0x40});
    a.emit({0x48,0x8B,0x54,0x24,0x48});
    a.emit({0x4C,0x8B,0x44,0x24,0x50});
    a.emit({0x4C,0x8B,0x4C,0x24,0x58});
    a.emit({0x48,0x81,0xC4,0x88,0x00,0x00,0x00});
    for (size_t i = 0; i < prologueLen; ++i) code.push_back(savedPrologue[i]);
    a.emit({0xFF,0x25}); a.ripDisp(SLOT_JMP);

    a.label("block");
    a.emit({0x48,0x8B,0x54,0x24,0x48});              // penv
    a.emit({0x48,0x85,0xD2});
    a.jcc(0x84, "block_ret");
    a.emit({0x48,0xC7,0x02,0x00,0x00,0x00,0x00});   // *penv=null
    a.label("block_ret");
    a.emit({0x48,0x81,0xC4,0x88,0x00,0x00,0x00});
    a.emit({0xB8,0xFD,0xFF,0xFF,0xFF});              // JNI_EVERSION (-3)
    a.emit({0xC3});

    if (!a.resolve() || code.size() > SLOT_JMP || rules.size() > 255 ||
        SLOT_RULES + rules.size() * 24 > image.size()) return {};
    memcpy(image.data(), code.data(), code.size());
    writeU64(image, SLOT_JMP, origPlusN);
    image[SLOT_MODE] = static_cast<uint8_t>(mode);
    image[SLOT_COUNT] = static_cast<uint8_t>(rules.size());
    size_t pos = SLOT_RULES;
    for (const auto& rule : rules) {
        writeU64(image, pos, rule.begin);
        writeU64(image, pos + 8, rule.end);
        image[pos + 16] = rule.allow ? 1 : 0;
        pos += 24;
    }
    return image;
}

static int installJvmtiFilter(int mode, const std::vector<std::string>& patterns) {
    HANDLE proc = g_target.handle;
    if (proc == NULL || g_target.jvmDllBase == 0) { setError("no_target_handle"); return 0; }

    std::vector<JvmtiModuleRule> rules;
    if (!buildJvmtiModuleRules(mode, patterns, &rules)) { setError("module_rules_failed"); return 0; }
    if (rules.size() > 255) { setError("too_many_modules"); return 0; }

    if (g_jvmtiPatch.patched) {
        auto image = buildJvmtiGetEnvTrampoline(g_jvmtiPatch.original, g_jvmtiPatch.patchSize,
                                                g_jvmtiPatch.targetAddr + g_jvmtiPatch.patchSize,
                                                mode, rules);
        if (image.empty() || !writeRemoteMem(proc, g_jvmtiPatch.trampolineAddr, image.data(), image.size())) {
            setError("policy_refresh_failed"); return 0;
        }
        FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(g_jvmtiPatch.trampolineAddr), image.size());
        setError("ok"); return 1;
    }

    uint64_t addr = locateJavaVmGetEnv(proc);
    if (addr == 0) { setError("jni_getenv_not_found_or_ambiguous"); return 0; }
    uint8_t saved[16] = {};
    if (!readRemoteMem(proc, addr, saved, sizeof(saved))) { setError("read_original_failed"); return 0; }
    uint8_t b0 = saved[0];
    if (b0 == 0xE8 || b0 == 0xE9 || b0 == 0xEB || (b0 >= 0x70 && b0 <= 0x7F) || b0 == 0xFF) {
        setError("dangerous_prologue"); return 0;
    }
    size_t prologueLen = alignedPrologueLen(saved, sizeof(saved), 5);
    if (prologueLen == 0 || prologueLen > sizeof(g_jvmtiPatch.original)) {
        setError("unsupported_prologue"); return 0;
    }

    const size_t kPage = 0x1000;
    uint64_t hint = findFreeRegionNear(proc, addr, kPage);
    if (hint == 0) { setError("no_near_region"); return 0; }
    void* allocated = VirtualAllocEx(proc, reinterpret_cast<LPVOID>(hint), kPage,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocated) { setError("trampoline_alloc_failed"); return 0; }
    uint64_t tramp = reinterpret_cast<uint64_t>(allocated);
    int64_t delta64 = static_cast<int64_t>(tramp) - static_cast<int64_t>(addr + 5);
    if (delta64 < INT32_MIN || delta64 > INT32_MAX) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE); setError("trampoline_out_of_range"); return 0;
    }
    auto image = buildJvmtiGetEnvTrampoline(saved, prologueLen, addr + prologueLen, mode, rules);
    if (image.empty() || !writeRemoteMem(proc, tramp, image.data(), image.size())) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE); setError("trampoline_write_failed"); return 0;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(tramp), image.size());

    uint8_t patch[16] = {0xE9};
    int32_t delta = static_cast<int32_t>(delta64);
    memcpy(patch + 1, &delta, sizeof(delta));
    for (size_t i = 5; i < prologueLen; ++i) patch[i] = 0x90;
    if (!writeRemoteCode(proc, addr, patch, prologueLen)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE); setError("write_patch_failed"); return 0;
    }
    uint8_t verify[16] = {};
    if (!readRemoteMem(proc, addr, verify, prologueLen) || memcmp(verify, patch, prologueLen) != 0) {
        writeRemoteCode(proc, addr, saved, prologueLen);
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE); setError("verify_failed"); return 0;
    }
    g_jvmtiPatch.targetAddr = addr;
    memcpy(g_jvmtiPatch.original, saved, prologueLen);
    g_jvmtiPatch.patchSize = prologueLen;
    g_jvmtiPatch.patched = true;
    g_jvmtiPatch.trampolineAddr = tramp;
    g_jvmtiPatch.trampolineSize = kPage;
    g_jvmtiPatch.trampolineInstalled = true;
    FVM_LOG("ban_jvmti: JavaVM::GetEnv @ 0x%llX, modules=%zu", (unsigned long long)addr, rules.size());
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_ban_jvmti(int mode, const char* patternsLF) {
    return installJvmtiFilter(mode, splitPatternsLF(patternsLF));
}

extern "C" __declspec(dllexport) int forgevm_unban_jvmti() {
    return uninstallFilterTrampoline(g_jvmtiPatch, "unban_jvmti");
}

/* ============================================================
 * ntdll!NtCreateUserProcess hook — process creation filter
 *
 * NtCreateUserProcess is the single kernel-mode entry point for all user-mode
 * process creation: CreateProcessW, ProcessBuilder, and any native code calling
 * CreateProcess* directly all funnel here.
 *
 * NtCreateUserProcess x64 signature (11 parameters):
 *   NTSTATUS NTAPI NtCreateUserProcess(
 *       PHANDLE  ProcessHandle,              // rcx
 *       PHANDLE  ThreadHandle,               // rdx
 *       ACCESS_MASK ProcessDesiredAccess,    // r8
 *       ACCESS_MASK ThreadDesiredAccess,     // r9
 *       POBJECT_ATTRIBUTES ProcessObjAttrs,  // [rsp+0x28]  ← image path here
 *       POBJECT_ATTRIBUTES ThreadObjAttrs,   // [rsp+0x30]
 *       ULONG    ProcessFlags,               // [rsp+0x38]
 *       ULONG    ThreadFlags,                // [rsp+0x40]
 *       PRTL_USER_PROCESS_PARAMETERS Params, // [rsp+0x48]
 *       PPS_CREATE_INFO CreateInfo,          // [rsp+0x50]
 *       PPS_ATTRIBUTE_LIST AttrList);        // [rsp+0x58]
 *
 * Image path: ProcessObjAttrs->ObjectName (UNICODE_STRING* at OA+0x10). The NT
 * path may carry a \??\ prefix; substring matching on the full path still works
 * with patterns like *processproxy*. In-process match against the resident
 * pattern blob (no IPC). Data layout matches the LdrLoadDll trampoline. Frame
 * is `sub rsp, 0x4A8` (larger than 0x478) so the 5th stack arg,
 * ProcessObjAttrs, sits at [rsp+0x4D0] = [caller_rsp+0x28]. Block returns
 * STATUS_ACCESS_DENIED (0xC0000005).
 * ============================================================ */
static std::vector<uint8_t> buildNtCreateUserProcessTrampoline(
    const uint8_t* savedPrologue,
    size_t prologueLen,
    uint64_t origPlusN,
    int mode,
    const std::vector<std::string>& patterns)
{
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC);

    const size_t SLOT_JMP  = 0x300;
    const size_t SLOT_MODE = 0x308;
    const size_t SLOT_BLOB = 0x310;
    (void)SLOT_BLOB;

    std::vector<uint8_t> code;
    code.reserve(0x300);
    TrampAsm a(code);

    // --- prologue (frame 0x4A8) + save arg regs ---
    a.emit({0x48, 0x81, 0xEC, 0xA8, 0x04, 0x00, 0x00});        // sub rsp, 0x4A8
    a.emit({0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov [rsp+0x458], rcx
    a.emit({0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov [rsp+0x460], rdx
    a.emit({0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov [rsp+0x468], r8
    a.emit({0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov [rsp+0x470], r9

    // --- arg5 ProcessObjAttrs → ObjectName → UNICODE_STRING Buffer/Length ---
    a.emit({0x4C, 0x8B, 0x94, 0x24, 0xD0, 0x04, 0x00, 0x00});  // mov r10, [rsp+0x4D0]
    a.emit({0x4D, 0x85, 0xD2}); a.jcc(0x84, "allow");          // test r10,r10; je allow
    a.emit({0x4D, 0x8B, 0x52, 0x10});                          // mov r10, [r10+0x10] ; ObjectName
    a.emit({0x4D, 0x85, 0xD2}); a.jcc(0x84, "allow");
    a.emit({0x45, 0x0F, 0xB7, 0x1A});                          // movzx r11d, word [r10] ; Length
    a.emit({0x45, 0x85, 0xDB}); a.jcc(0x84, "allow");          // test r11d,r11d; je allow
    a.emit({0x4D, 0x8B, 0x52, 0x08});                          // mov r10, [r10+8] ; Buffer
    a.emit({0x4D, 0x85, 0xD2}); a.jcc(0x84, "allow");
    a.emit({0x41, 0xD1, 0xEB});                                // shr r11d, 1 ; wchar count
    a.emit({0x41, 0x81, 0xFB, 0x90, 0x01, 0x00, 0x00});        // cmp r11d, 400
    a.jcc(0x86, "len_ok");                                     // jbe len_ok
    a.emit({0x41, 0xBB, 0x90, 0x01, 0x00, 0x00});              // mov r11d, 400
    a.label("len_ok");
    a.emit({0x4C, 0x89, 0x54, 0x24, 0x48});                    // mov [rsp+0x48], r10 ; buffer
    a.emit({0x4C, 0x89, 0x5C, 0x24, 0x50});                    // mov [rsp+0x50], r11 ; N

    emitSubstringMatcher(a, /*wide=*/true);

    // --- allow: restore args, replay prologue, jump on ---
    a.label("allow");
    a.emit({0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});  // mov rcx, [rsp+0x458]
    a.emit({0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});  // mov rdx, [rsp+0x460]
    a.emit({0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});  // mov r8, [rsp+0x468]
    a.emit({0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});  // mov r9, [rsp+0x470]
    a.emit({0x48, 0x81, 0xC4, 0xA8, 0x04, 0x00, 0x00});        // add rsp, 0x4A8
    // replay the whole saved prologue (instruction-aligned, may be >5) then jump on
    for (size_t i = 0; i < prologueLen; i++) code.push_back(savedPrologue[i]);
    a.emit({0xFF, 0x25}); a.ripDisp(SLOT_JMP);                 // jmp qword [rip+abs_jump]

    // --- block: STATUS_ACCESS_DENIED ---
    a.label("block");
    a.emit({0x48, 0x81, 0xC4, 0xA8, 0x04, 0x00, 0x00});        // add rsp, 0x4A8
    a.emit({0xB8, 0x05, 0x00, 0x00, 0xC0});                    // mov eax, 0xC0000005
    a.emit({0xC3});                                             // ret

    if (!a.resolve()) {
        FVM_LOG("buildNtCreateUserProcessTrampoline: label resolve failed");
        return {};
    }
    if (code.size() > SLOT_JMP) {
        FVM_LOG("buildNtCreateUserProcessTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    writeU64(buf, SLOT_JMP, origPlusN);
    buf[SLOT_MODE] = static_cast<uint8_t>(mode);
    serializeFilterBlob(buf, mode, patterns);
    return buf;
}

static int installNtCreateUserProcessFilter(PatchState& state, int mode,
                                            const std::vector<std::string>& patterns) {
    if (g_target.handle == NULL) {
        setError("no_target_handle");
        return 0;
    }
    HANDLE proc = g_target.handle;

    if (state.patched) {
        /* Already hooked — refresh the resident mode + pattern blob in place. */
        std::vector<uint8_t> data(0x400, 0xCC);
        data[0x308] = static_cast<uint8_t>(mode);
        serializeFilterBlob(data, mode, patterns);
        if (!writeRemoteMem(proc, state.trampolineAddr + 0x308,
                            &data[0x308], 0x400 - 0x308)) {
            setError("blob_update_failed");
            return 0;
        }
        FVM_LOG("ban_process_create: refreshed resident pattern blob (mode=%d, %zu patterns)",
                mode, patterns.size());
        setError("ok");
        return 1;
    }

    uint64_t addr = resolveNtdllExport(proc, "NtCreateUserProcess");
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("ban_process_create: ntdll!NtCreateUserProcess @ 0x%llX", (unsigned long long)addr);

    uint8_t saved[8] = {};
    if (!readRemoteMem(proc, addr, saved, sizeof(saved))) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("ban_process_create: original prologue: %02X %02X %02X %02X %02X %02X %02X %02X",
            saved[0], saved[1], saved[2], saved[3], saved[4], saved[5], saved[6], saved[7]);

    uint8_t b0 = saved[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        setError("unsafe_prologue");
        return 0;
    }

    // The 5-byte E9 patch must not split an instruction, or the trampoline's
    // prologue replay mis-decodes and crashes. ntdll syscall stubs begin with
    // `mov r10,rcx` (4C 8B D1) + `mov eax,imm32` (B8 ........) — an 8-byte pair
    // whose 2nd instruction straddles the 5-byte boundary. Copy the whole pair
    // and resume at addr+8; the 3 leftover bytes after the E9 are NOP-padded.
    // Any other prologue keeps the classic 5-byte aligned copy.
    size_t prologueLen = 5;
    if (saved[0] == 0x4C && saved[1] == 0x8B && saved[2] == 0xD1 && saved[3] == 0xB8) {
        prologueLen = 8;
    }
    FVM_LOG("ban_process_create: prologue copy length = %zu bytes", prologueLen);

    const size_t kPage = 0x400;
    uint64_t allocHint = findFreeRegionNear(proc, addr, kPage);
    if (allocHint == 0) {
        setError("no_nearby_free_region");
        return 0;
    }
    void* allocated = VirtualAllocEx(proc, reinterpret_cast<LPVOID>(allocHint), kPage,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocated) {
        setError("virtual_alloc_failed");
        return 0;
    }
    uint64_t trampAddr = reinterpret_cast<uint64_t>(allocated);

    int64_t delta = static_cast<int64_t>(trampAddr) - static_cast<int64_t>(addr + 5);
    if (delta < static_cast<int64_t>(INT32_MIN) || delta > static_cast<int64_t>(INT32_MAX)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("tramp_out_of_rel32_range");
        return 0;
    }
    FVM_LOG("ban_process_create: trampoline @ 0x%llX (delta=%lld)",
            (unsigned long long)trampAddr, (long long)delta);

    std::vector<uint8_t> image = buildNtCreateUserProcessTrampoline(
        saved, prologueLen, addr + prologueLen, mode, patterns);
    if (image.empty()) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_build_failed");
        return 0;
    }
    if (!writeRemoteMem(proc, trampAddr, image.data(), image.size())) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("trampoline_write_failed");
        return 0;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(trampAddr), image.size());

    uint8_t patch[16];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);
    for (size_t i = 5; i < prologueLen; i++) patch[i] = 0x90;  // NOP-pad split tail

    if (!writeRemoteCode(proc, addr, patch, prologueLen)) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[16] = {};
    readRemoteMem(proc, addr, verify, prologueLen);
    if (memcmp(verify, patch, prologueLen) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = prologueLen;
    memcpy(state.original, saved, prologueLen);
    state.patched = true;
    state.trampolineAddr = trampAddr;
    state.trampolineSize = kPage;
    state.trampolineInstalled = true;

    FVM_LOG("ban_process_create: installed NtCreateUserProcess trampoline + E9 patch (verified)");
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_ban_process_create(int mode, const char* patternsLF) {
    return installNtCreateUserProcessFilter(g_processCreatePatch, mode, splitPatternsLF(patternsLF));
}

extern "C" __declspec(dllexport) int forgevm_unban_process_create() {
    return uninstallFilterTrampoline(g_processCreatePatch, "unban_process_create");
}
