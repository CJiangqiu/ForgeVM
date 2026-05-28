#include "forgevm_internal.h"

#include <psapi.h>
#include <shellapi.h>
#include <string.h>

// ============================================================
// File-based logging implementation
// ============================================================

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

// fvm_log_open_default() removed — all logging is routed through
// forgevm_set_log_dir() which places the log in ForgeVM/logs/.

void fvm_log_write(const char* fmt, ...) {
    ensureLogLock();
    EnterCriticalSection(&g_logLock);

    // Log file is initialized by Agent via forgevm_set_log_dir().
    // If not set, silently discard — no random file creation.
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

// ============================================================
// Global state definitions
// ============================================================

std::string g_lastError = "ok";
TargetProcess g_target;

std::unordered_map<StructMapKey, StructMapEntry, StructMapKeyHash> g_structMap;
std::unordered_map<std::string, TypeMapEntry> g_typeMap;
std::unordered_map<std::string, int64_t> g_intConstants;
std::unordered_map<std::string, int64_t> g_longConstants;
std::unordered_map<std::string, CachedFieldInfo> g_fieldInfoCache;

// ============================================================
// Error state
// ============================================================

void setError(const char* value) {
    g_lastError = value;
    FVM_LOG("ERROR: %s", value);
}

void setError(const std::string& value) {
    g_lastError = value;
    FVM_LOG("ERROR: %s", value.c_str());
}

// ============================================================
// Remote memory helpers
// ============================================================

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

// ============================================================
// StructMap / TypeMap lookup helpers
// ============================================================

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

// ============================================================
// Module enumeration
// ============================================================

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

// ============================================================
// PE export table parsing
// ============================================================

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

// ============================================================
// HotSpot self-describing table readers
// ============================================================

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

// ============================================================
// Privilege helpers
// ============================================================

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

// ============================================================
// Exported functions
// ============================================================

// Probe: same-user OpenProcess does not require SeDebugPrivilege.
// We opportunistically enable it (helps if target has a hostile DACL or
// different integrity), but a normal-user JVM has no SeDebug in its token
// and AdjustTokenPrivileges returns ERROR_NOT_ALL_ASSIGNED — that is NOT
// a capability failure. The real capability gate is OpenProcess in
// forgevm_bootstrap_target.
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
    extern PatchState g_processCreatePatch;
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

// ============================================================
// Load-time filters.
//
//   Java agent attach:
//     hook jvm.dll!JVM_EnqueueOperation — arg0 (rdx) is the agent
//     library path as UTF-8. attach() uses CreateRemoteThread to
//     reach this entry, so DisableAttachMechanism can't cover it.
//
//   Native library load:
//     hook ntdll!LdrLoadDll — the bottom of every user-mode DLL
//     load path (LoadLibraryW / LoadLibraryExW / kernelbase / JNI
//     direct LoadLibrary / etc. all funnel here). The DLL name
//     arrives in r8 as a UNICODE_STRING; the trampoline converts
//     it to UTF-8 via WideCharToMultiByte before querying the
//     filter pipe. On block we return STATUS_DLL_NOT_FOUND
//     (0xC0000135) so callers see the normal "DLL not found"
//     error path, not a crash.
//
//   Both hooks query a named pipe served by the Agent to decide
//   allow/block per call. Pipe failure → fail-open, to keep the
//   JVM healthy when the Agent exits unexpectedly.
// ============================================================

namespace {
    /* Definitions for the forward-declared globals above. */
    PatchState g_javaAgentPatch;
    PatchState g_nativeLoadPatch;
    PatchState g_processCreatePatch;
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

// Resolve a jvm.dll export in the target process. Fast path uses a local
// DONT_RESOLVE_DLL_REFERENCES load + RVA translation; falls back to the
// existing parsePEExport() which walks the remote PE export table.
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

// Find free region within 2GB of `near` big enough for `size`.
// A Windows E9 rel32 requires the trampoline to be reachable from the patch site.
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

// Build the trampoline page (code + data). Layout:
//   +0x000..0x300  executable code
//   +0x300  qword  fn_CreateFileA
//   +0x308  qword  fn_WriteFile
//   +0x310  qword  fn_ReadFile
//   +0x318  qword  fn_CloseHandle
//   +0x320  qword  abs_orig_plus_5  (jmp target after saved prologue runs)
//   +0x330  byte   kind_byte        ('A' = java agent, 'N' = native load)
//   +0x340  char[] pipe_name        (NUL-terminated, <= 128 bytes)
//
// Entry: intercepted call saves rcx/rdx/r8/r9, early-allows if the
// path pointer is null, else opens the pipe and writes "<kind><path>\n",
// reads a 1-byte decision. '0' => block (return 0). Anything else (or
// any IPC failure) => allow: restore regs, run saved prologue, jmp to
// target+5. `pathInRdx` selects whether the path pointer is in rdx
// (Java agent, EnqueueOperation arg0) or rcx (native load, LoadLibrary arg0).
static std::vector<uint8_t> buildFilterTrampoline(const uint8_t* savedPrologue,
                                                   uint64_t origPlus5,
                                                   uint64_t fnCreateFileA,
                                                   uint64_t fnWriteFile,
                                                   uint64_t fnReadFile,
                                                   uint64_t fnCloseHandle,
                                                   char kindByte,
                                                   const char* pipeName,
                                                   bool pathInRdx) {
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC); // INT3-fill unused bytes

    // ---- Emit code (linear), then back-patch forward-jump displacements ----
    std::vector<uint8_t> code;
    code.reserve(0x200);

    // 0x000: sub rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xEC, 0x78, 0x04, 0x00, 0x00});
    // 0x007: mov [rsp+0x458], rcx
    emitBytes(code, {0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    // 0x00F: mov [rsp+0x460], rdx
    emitBytes(code, {0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    // 0x017: mov [rsp+0x468], r8
    emitBytes(code, {0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    // 0x01F: mov [rsp+0x470], r9
    emitBytes(code, {0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});
    // 0x027: test rdx,rdx (path-in-rdx) or test rcx,rcx (path-in-rcx) — same 3 bytes
    if (pathInRdx) emitBytes(code, {0x48, 0x85, 0xD2});
    else           emitBytes(code, {0x48, 0x85, 0xC9});
    // 0x02A: je _allow_direct (rel32 fixup to 0x155)
    emitBytes(code, {0x0F, 0x84, 0x25, 0x01, 0x00, 0x00});

    // 0x030: lea rcx, [rip+0x309]  -> pipe_name at 0x340
    emitBytes(code, {0x48, 0x8D, 0x0D, 0x09, 0x03, 0x00, 0x00});
    // 0x037: mov edx, 0xC0000000 (GENERIC_READ | GENERIC_WRITE)
    emitBytes(code, {0xBA, 0x00, 0x00, 0x00, 0xC0});
    // 0x03C: xor r8d, r8d
    emitBytes(code, {0x45, 0x33, 0xC0});
    // 0x03F: xor r9d, r9d
    emitBytes(code, {0x45, 0x33, 0xC9});
    // 0x042: mov dword [rsp+0x20], 3  (OPEN_EXISTING)
    emitBytes(code, {0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00});
    // 0x04A: mov dword [rsp+0x28], 0
    emitBytes(code, {0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00});
    // 0x052: mov qword [rsp+0x30], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00});
    // 0x05B: mov rax, [rip+0x29E]  -> fn_CreateFileA at 0x300
    emitBytes(code, {0x48, 0x8B, 0x05, 0x9E, 0x02, 0x00, 0x00});
    // 0x062: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x064: cmp rax, -1
    emitBytes(code, {0x48, 0x83, 0xF8, 0xFF});
    // 0x068: je _allow_direct (rel32 to 0x155, disp = 0xE7)
    emitBytes(code, {0x0F, 0x84, 0xE7, 0x00, 0x00, 0x00});
    // 0x06E: mov [rsp+0x440], rax  (save handle)
    emitBytes(code, {0x48, 0x89, 0x84, 0x24, 0x40, 0x04, 0x00, 0x00});

    // 0x076: movzx eax, byte [rip+0x2B3]  -> kind_byte at 0x330
    emitBytes(code, {0x0F, 0xB6, 0x05, 0xB3, 0x02, 0x00, 0x00});
    // 0x07D: mov [rsp+0x40], al
    emitBytes(code, {0x88, 0x44, 0x24, 0x40});
    // 0x081: mov r10, [rsp+0x460] (rdx slot) or [rsp+0x458] (rcx slot)
    {
        uint8_t disp = pathInRdx ? 0x60 : 0x58;
        emitBytes(code, {0x4C, 0x8B, 0x94, 0x24, disp, 0x04, 0x00, 0x00});
    }
    // 0x089: xor r11d, r11d
    emitBytes(code, {0x45, 0x33, 0xDB});

    // _cpyloop at 0x08C
    // 0x08C: cmp r11, 0x384 (900)
    emitBytes(code, {0x49, 0x81, 0xFB, 0x84, 0x03, 0x00, 0x00});
    // 0x093: jae _cpydone (rel8 +0x15 -> 0x0AA)
    emitBytes(code, {0x73, 0x15});
    // 0x095: mov al, [r10+r11]
    emitBytes(code, {0x43, 0x8A, 0x04, 0x1A});
    // 0x099: test al, al
    emitBytes(code, {0x84, 0xC0});
    // 0x09B: je _cpydone (rel8 +0x0D -> 0x0AA)
    emitBytes(code, {0x74, 0x0D});
    // 0x09D: mov [rsp+r11+0x41], al
    emitBytes(code, {0x42, 0x88, 0x84, 0x1C, 0x41, 0x00, 0x00, 0x00});
    // 0x0A5: inc r11
    emitBytes(code, {0x49, 0xFF, 0xC3});
    // 0x0A8: jmp _cpyloop (rel8 -0x1E -> 0x08C)
    emitBytes(code, {0xEB, 0xE2});

    // _cpydone at 0x0AA
    // 0x0AA: mov byte [rsp+r11+0x41], 0x0A
    emitBytes(code, {0x42, 0xC6, 0x84, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x0A});

    // 0x0B3: mov rcx, [rsp+0x440]  (handle)
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x0BB: lea rdx, [rsp+0x40]   (buf)
    emitBytes(code, {0x48, 0x8D, 0x54, 0x24, 0x40});
    // 0x0C0: lea r8, [r11+2]
    emitBytes(code, {0x4D, 0x8D, 0x43, 0x02});
    // 0x0C4: lea r9, [rsp+0x448]   (&wrote)
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x48, 0x04, 0x00, 0x00});
    // 0x0CC: mov qword [rsp+0x20], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    // 0x0D5: mov rax, [rip+0x22C]  -> fn_WriteFile at 0x308
    emitBytes(code, {0x48, 0x8B, 0x05, 0x2C, 0x02, 0x00, 0x00});
    // 0x0DC: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x0DE: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x0E0: je _close_and_allow (rel32 to 0x144, disp = 0x5E)
    emitBytes(code, {0x0F, 0x84, 0x5E, 0x00, 0x00, 0x00});

    // 0x0E6: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x0EE: lea rdx, [rsp+0x450]  (&reply)
    emitBytes(code, {0x48, 0x8D, 0x94, 0x24, 0x50, 0x04, 0x00, 0x00});
    // 0x0F6: mov r8d, 1
    emitBytes(code, {0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});
    // 0x0FC: lea r9, [rsp+0x44C]   (&got)
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x4C, 0x04, 0x00, 0x00});
    // 0x104: mov qword [rsp+0x20], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    // 0x10D: mov rax, [rip+0x1FC]  -> fn_ReadFile at 0x310
    emitBytes(code, {0x48, 0x8B, 0x05, 0xFC, 0x01, 0x00, 0x00});
    // 0x114: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x116: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x118: je _close_and_allow (rel32 to 0x144, disp = 0x26)
    emitBytes(code, {0x0F, 0x84, 0x26, 0x00, 0x00, 0x00});

    // 0x11E: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x126: mov rax, [rip+0x1EB]  -> fn_CloseHandle at 0x318
    emitBytes(code, {0x48, 0x8B, 0x05, 0xEB, 0x01, 0x00, 0x00});
    // 0x12D: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x12F: movzx eax, byte [rsp+0x450]  (reply)
    emitBytes(code, {0x0F, 0xB6, 0x84, 0x24, 0x50, 0x04, 0x00, 0x00});
    // 0x137: cmp al, '0'
    emitBytes(code, {0x3C, 0x30});
    // 0x139: je _block (rel32 to 0x187, disp = 0x48)
    emitBytes(code, {0x0F, 0x84, 0x48, 0x00, 0x00, 0x00});
    // 0x13F: jmp _allow_direct (rel32 to 0x155, disp = 0x11)
    emitBytes(code, {0xE9, 0x11, 0x00, 0x00, 0x00});

    // _close_and_allow at 0x144
    // 0x144: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x14C: mov rax, [rip+0x1C5]  -> fn_CloseHandle at 0x318
    emitBytes(code, {0x48, 0x8B, 0x05, 0xC5, 0x01, 0x00, 0x00});
    // 0x153: call rax
    emitBytes(code, {0xFF, 0xD0});
    // fallthrough to _allow_direct

    // _allow_direct at 0x155
    // 0x155: mov rcx, [rsp+0x458]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    // 0x15D: mov rdx, [rsp+0x460]
    emitBytes(code, {0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    // 0x165: mov r8, [rsp+0x468]
    emitBytes(code, {0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    // 0x16D: mov r9, [rsp+0x470]
    emitBytes(code, {0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});
    // 0x175: add rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});
    // 0x17C: <5 saved prologue bytes>
    for (int i = 0; i < 5; i++) code.push_back(savedPrologue[i]);
    // 0x181: jmp qword [rip+0x199]  -> abs_orig_plus_5 at 0x320
    emitBytes(code, {0xFF, 0x25, 0x99, 0x01, 0x00, 0x00});

    // _block
    /* Return -1 (not 0). HotSpot attach protocol: JVM_EnqueueOperation returns
     * 0 = "operation enqueued, wait for response on pipe". The attacher then
     * calls connectPipe() and blocks until the AttachListener thread writes the
     * response — but we short-circuited, so no one ever writes, and attacher
     * deadlocks forever. Returning non-zero makes the JDK-side native `enqueue`
     * throw IOException immediately (before reaching connectPipe), which the
     * caller's catch handles cleanly. */
    // add rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});
    // mov eax, 0xFFFFFFFF  (return -1)
    emitBytes(code, {0xB8, 0xFF, 0xFF, 0xFF, 0xFF});
    // ret
    emitBytes(code, {0xC3});

    // Sanity: the code section must fit below the data region at 0x300
    if (code.size() > 0x300) {
        FVM_LOG("buildFilterTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }

    // Copy code into page-buffer
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    // Data section
    writeU64(buf, 0x300, fnCreateFileA);
    writeU64(buf, 0x308, fnWriteFile);
    writeU64(buf, 0x310, fnReadFile);
    writeU64(buf, 0x318, fnCloseHandle);
    writeU64(buf, 0x320, origPlus5);
    buf[0x330] = static_cast<uint8_t>(kindByte);

    // Pipe name (bounded copy, NUL-terminate)
    size_t pn = 0;
    if (pipeName != nullptr) {
        while (pipeName[pn] != '\0' && pn < 127) {
            buf[0x340 + pn] = static_cast<uint8_t>(pipeName[pn]);
            pn++;
        }
    }
    buf[0x340 + pn] = 0;

    return buf;
}

// Core install routine shared by ban_java_agent and ban_native_load.
// Looks up `exportName` in jvm.dll, saves the first 5 bytes, allocates
// a nearby trampoline page, writes the trampoline image, and redirects
// the export's prologue via E9 rel32. On any failure, frees the page.
static int installFilterTrampoline(PatchState& state,
                                    const char* exportName,
                                    bool pathInRdx,
                                    char kindByte,
                                    const char* pipeName,
                                    const char* logTag) {
    if (!g_target.structMapReady) {
        setError("not_bootstrapped");
        return 0;
    }
    if (state.patched) {
        setError("already_patched");
        return 0;
    }
    if (pipeName == nullptr || pipeName[0] == '\0') {
        setError("missing_pipe_name");
        return 0;
    }

    HANDLE proc = g_target.handle;

    uint64_t addr = resolveJvmExport(proc, exportName);
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("%s: %s @ 0x%llX", logTag, exportName, (unsigned long long)addr);

    uint8_t saved5[5] = {};
    if (!readRemoteMem(proc, addr, saved5, 5)) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("%s: original prologue: %02X %02X %02X %02X %02X", logTag,
            saved5[0], saved5[1], saved5[2], saved5[3], saved5[4]);

    /* MSVC incremental-linking emits each exported function as a 5-byte
     * `JMP rel32` thunk that jumps to the real function body. Modern JDK 17+
     * jvm.dll ships this way, so `JVM_EnqueueOperation`'s prologue is
     * `E9 xx xx xx xx`. Patching the thunk itself would corrupt other code
     * (the byte after E9+4 may be the next thunk's first byte), but we can
     * just follow the jump and hook the real body instead. */
    for (int hop = 0; hop < 2 && saved5[0] == 0xE9; hop++) {
        int32_t rel = (int32_t)saved5[1]
                    | ((int32_t)saved5[2] << 8)
                    | ((int32_t)saved5[3] << 16)
                    | ((int32_t)saved5[4] << 24);
        uint64_t realAddr = addr + 5 + (int64_t)rel;
        FVM_LOG("%s: prologue is JMP thunk, following 0x%llX -> 0x%llX",
                logTag, (unsigned long long)addr, (unsigned long long)realAddr);
        if (!readRemoteMem(proc, realAddr, saved5, 5)) {
            setError("read_real_prologue_failed");
            return 0;
        }
        FVM_LOG("%s: real prologue: %02X %02X %02X %02X %02X", logTag,
                saved5[0], saved5[1], saved5[2], saved5[3], saved5[4]);
        addr = realAddr;
    }

    // Refuse dangerous starters (rel jumps/calls we can't safely relocate).
    uint8_t b0 = saved5[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        setError("unsafe_prologue");
        return 0;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        setError("kernel32_not_loaded");
        return 0;
    }
    uint64_t fnCreate = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CreateFileA"));
    uint64_t fnWrite  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "WriteFile"));
    uint64_t fnRead   = reinterpret_cast<uint64_t>(GetProcAddress(k32, "ReadFile"));
    uint64_t fnClose  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CloseHandle"));
    if (!fnCreate || !fnWrite || !fnRead || !fnClose) {
        setError("kernel32_resolve_failed");
        return 0;
    }

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
        saved5, addr + 5, fnCreate, fnWrite, fnRead, fnClose,
        kindByte, pipeName, pathInRdx);
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

    uint8_t patch[5];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);

    if (!writeRemoteCode(proc, addr, patch, sizeof(patch))) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[5] = {};
    readRemoteMem(proc, addr, verify, sizeof(verify));
    if (memcmp(verify, patch, sizeof(patch)) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = 5;
    memcpy(state.original, saved5, 5);
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

// ============================================================
// ntdll!LdrLoadDll hook — native library load filter (deeper sink)
//
// LdrLoadDll is the bottom of every user-mode DLL load path. All of
// LoadLibraryA/W, LoadLibraryExA/W, kernelbase internals and JNI code
// that calls LoadLibrary directly funnel here. Hooking jvm.dll's
// JVM_LoadLibrary (our earlier approach) only caught System.load /
// Runtime.load; it missed any DLL that JNI / malware loaded directly.
// ============================================================

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

// LdrLoadDll x64 signature:
//   NTSTATUS NTAPI LdrLoadDll(PWSTR SearchPath,         // rcx  (may be NULL)
//                             PULONG DllCharacteristics,// rdx
//                             PUNICODE_STRING DllName,  // r8   ← the name
//                             PHANDLE DllHandle);       // r9
// UNICODE_STRING: { USHORT Length (+0); USHORT MaxLength (+2); PWSTR Buffer (+8); }
//
// Data layout (matches buildFilterTrampoline where possible; adds a
// WideCharToMultiByte slot so the wchar name can be converted in-place):
//   +0x300  fn_CreateFileA
//   +0x308  fn_WriteFile
//   +0x310  fn_ReadFile
//   +0x318  fn_CloseHandle
//   +0x320  abs_orig_plus_5
//   +0x328  fn_WideCharToMultiByte
//   +0x330  kind_byte ('N')
//   +0x340  pipe_name (NUL-terminated, <=127 bytes)
//
// Stack frame after `sub rsp, 0x478`:
//   +0x20..0x3F   shadow space + extra args for API calls
//   +0x40         kind byte (copied from data at 0x330)
//   +0x41..0x3F0  UTF-8 path buffer (WideCharToMultiByte output); we
//                 cap at 400 wide chars in, 800 bytes out
//   +0x440        saved pipe HANDLE
//   +0x448        WriteFile bytes-written (DWORD)
//   +0x44C        ReadFile bytes-read (DWORD)
//   +0x450        reply byte
//   +0x458..0x470 saved rcx/rdx/r8/r9
//
// Control flow: if the UNICODE_STRING or its Buffer is NULL, or if
// WideCharToMultiByte fails, we fall through to _allow_direct (fail-open).
// On pipe '0' reply we branch to _block and return STATUS_DLL_NOT_FOUND
// (0xC0000135); the loader maps that to a normal "DLL not found" error.
static std::vector<uint8_t> buildLdrLoadDllTrampoline(const uint8_t* savedPrologue,
                                                      uint64_t origPlus5,
                                                      uint64_t fnCreateFileA,
                                                      uint64_t fnWriteFile,
                                                      uint64_t fnReadFile,
                                                      uint64_t fnCloseHandle,
                                                      uint64_t fnWideCharToMultiByte,
                                                      const char* pipeName) {
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC);

    std::vector<uint8_t> code;
    code.reserve(0x200);

    // 0x000: sub rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xEC, 0x78, 0x04, 0x00, 0x00});
    // 0x007: mov [rsp+0x458], rcx
    emitBytes(code, {0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    // 0x00F: mov [rsp+0x460], rdx
    emitBytes(code, {0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    // 0x017: mov [rsp+0x468], r8
    emitBytes(code, {0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    // 0x01F: mov [rsp+0x470], r9
    emitBytes(code, {0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});
    // 0x027: test r8, r8
    emitBytes(code, {0x4D, 0x85, 0xC0});
    // 0x02A: je _allow_direct (rel32 -> 0x1A4, disp=0x174)
    emitBytes(code, {0x0F, 0x84, 0x74, 0x01, 0x00, 0x00});

    // 0x030: movzx eax, word [r8]         ; UNICODE_STRING.Length (bytes)
    emitBytes(code, {0x41, 0x0F, 0xB7, 0x00});
    // 0x034: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x036: je _allow_direct (rel32, disp=0x168)
    emitBytes(code, {0x0F, 0x84, 0x68, 0x01, 0x00, 0x00});
    // 0x03C: mov rdx, [r8+8]              ; UNICODE_STRING.Buffer (PWSTR)
    emitBytes(code, {0x49, 0x8B, 0x50, 0x08});
    // 0x040: test rdx, rdx
    emitBytes(code, {0x48, 0x85, 0xD2});
    // 0x043: je _allow_direct (rel32, disp=0x15B)
    emitBytes(code, {0x0F, 0x84, 0x5B, 0x01, 0x00, 0x00});

    // 0x049: shr eax, 1                    ; Length(bytes) -> wchar count
    emitBytes(code, {0xD1, 0xE8});
    // 0x04B: cmp eax, 400
    emitBytes(code, {0x3D, 0x90, 0x01, 0x00, 0x00});
    // 0x050: jbe _len_ok (rel8 +5 -> 0x57)
    emitBytes(code, {0x76, 0x05});
    // 0x052: mov eax, 400
    emitBytes(code, {0xB8, 0x90, 0x01, 0x00, 0x00});

    // _len_ok at 0x57
    // 0x057: movzx ecx, byte [rip+kind_byte]   ; kind at 0x330, disp=0x2D2
    emitBytes(code, {0x0F, 0xB6, 0x0D, 0xD2, 0x02, 0x00, 0x00});
    // 0x05E: mov [rsp+0x40], cl
    emitBytes(code, {0x88, 0x4C, 0x24, 0x40});
    // 0x062: mov r11d, eax                 ; stash wchar count
    emitBytes(code, {0x41, 0x89, 0xC3});

    // --- WideCharToMultiByte(CP_UTF8, 0, Buffer, cchWide, outBuf, 800, NULL, NULL)
    // 0x065: mov ecx, 65001                ; CP_UTF8
    emitBytes(code, {0xB9, 0xE9, 0xFD, 0x00, 0x00});
    // 0x06A: xor edx, edx                  ; flags = 0
    emitBytes(code, {0x33, 0xD2});
    // 0x06C: mov r8, [rsp+0x468]           ; PUNICODE_STRING
    emitBytes(code, {0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    // 0x074: mov r8, [r8+8]                ; Buffer
    emitBytes(code, {0x4D, 0x8B, 0x40, 0x08});
    // 0x078: mov r9d, r11d                 ; cchWideChar
    emitBytes(code, {0x45, 0x89, 0xD9});
    // 0x07B: lea rax, [rsp+0x41]           ; outBuf
    emitBytes(code, {0x48, 0x8D, 0x44, 0x24, 0x41});
    // 0x080: mov [rsp+0x20], rax
    emitBytes(code, {0x48, 0x89, 0x44, 0x24, 0x20});
    // 0x085: mov dword [rsp+0x28], 800     ; cbMultiByte
    emitBytes(code, {0xC7, 0x44, 0x24, 0x28, 0x20, 0x03, 0x00, 0x00});
    // 0x08D: mov qword [rsp+0x30], 0       ; lpDefaultChar
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00});
    // 0x096: mov qword [rsp+0x38], 0       ; lpUsedDefaultChar
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00});
    // 0x09F: mov rax, [rip+fn_WideCharToMultiByte]   ; slot 0x328, disp=0x282
    emitBytes(code, {0x48, 0x8B, 0x05, 0x82, 0x02, 0x00, 0x00});
    // 0x0A6: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x0A8: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x0AA: je _allow_direct (rel32, disp=0xF4) — conversion failure → fail-open
    emitBytes(code, {0x0F, 0x84, 0xF4, 0x00, 0x00, 0x00});

    // 0x0B0: mov r11d, eax                 ; UTF-8 byte count
    emitBytes(code, {0x41, 0x89, 0xC3});
    // 0x0B3: mov byte [rsp+r11+0x41], 0x0A ; append newline terminator
    emitBytes(code, {0x42, 0xC6, 0x84, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x0A});

    // --- CreateFileA(pipe, GENERIC_READ|WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
    // 0x0BC: lea rcx, [rip+pipe_name]      ; pipe_name at 0x340, disp=0x27D
    emitBytes(code, {0x48, 0x8D, 0x0D, 0x7D, 0x02, 0x00, 0x00});
    // 0x0C3: mov edx, 0xC0000000
    emitBytes(code, {0xBA, 0x00, 0x00, 0x00, 0xC0});
    // 0x0C8: xor r8d, r8d
    emitBytes(code, {0x45, 0x33, 0xC0});
    // 0x0CB: xor r9d, r9d
    emitBytes(code, {0x45, 0x33, 0xC9});
    // 0x0CE: mov dword [rsp+0x20], 3       ; OPEN_EXISTING
    emitBytes(code, {0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00});
    // 0x0D6: mov dword [rsp+0x28], 0
    emitBytes(code, {0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00});
    // 0x0DE: mov qword [rsp+0x30], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00});
    // 0x0E7: mov rax, [rip+fn_CreateFileA] ; slot 0x300, disp=0x212
    emitBytes(code, {0x48, 0x8B, 0x05, 0x12, 0x02, 0x00, 0x00});
    // 0x0EE: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x0F0: cmp rax, -1
    emitBytes(code, {0x48, 0x83, 0xF8, 0xFF});
    // 0x0F4: je _allow_direct (rel32, disp=0xAA)
    emitBytes(code, {0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00});
    // 0x0FA: mov [rsp+0x440], rax
    emitBytes(code, {0x48, 0x89, 0x84, 0x24, 0x40, 0x04, 0x00, 0x00});

    // --- WriteFile(handle, &buf[0x40], r11+2, &wrote, NULL)
    // 0x102: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x10A: lea rdx, [rsp+0x40]
    emitBytes(code, {0x48, 0x8D, 0x54, 0x24, 0x40});
    // 0x10F: lea r8, [r11+2]                ; kind byte + path + '\n'
    emitBytes(code, {0x4D, 0x8D, 0x43, 0x02});
    // 0x113: lea r9, [rsp+0x448]
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x48, 0x04, 0x00, 0x00});
    // 0x11B: mov qword [rsp+0x20], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    // 0x124: mov rax, [rip+fn_WriteFile]    ; slot 0x308, disp=0x1DD
    emitBytes(code, {0x48, 0x8B, 0x05, 0xDD, 0x01, 0x00, 0x00});
    // 0x12B: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x12D: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x12F: je _close_and_allow (rel32 -> 0x193, disp=0x5E)
    emitBytes(code, {0x0F, 0x84, 0x5E, 0x00, 0x00, 0x00});

    // --- ReadFile(handle, &reply, 1, &got, NULL)
    // 0x135: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x13D: lea rdx, [rsp+0x450]
    emitBytes(code, {0x48, 0x8D, 0x94, 0x24, 0x50, 0x04, 0x00, 0x00});
    // 0x145: mov r8d, 1
    emitBytes(code, {0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});
    // 0x14B: lea r9, [rsp+0x44C]
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x4C, 0x04, 0x00, 0x00});
    // 0x153: mov qword [rsp+0x20], 0
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    // 0x15C: mov rax, [rip+fn_ReadFile]     ; slot 0x310, disp=0x1AD
    emitBytes(code, {0x48, 0x8B, 0x05, 0xAD, 0x01, 0x00, 0x00});
    // 0x163: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x165: test eax, eax
    emitBytes(code, {0x85, 0xC0});
    // 0x167: je _close_and_allow (rel32 -> 0x193, disp=0x26)
    emitBytes(code, {0x0F, 0x84, 0x26, 0x00, 0x00, 0x00});

    // 0x16D: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x175: mov rax, [rip+fn_CloseHandle]  ; slot 0x318, disp=0x19C
    emitBytes(code, {0x48, 0x8B, 0x05, 0x9C, 0x01, 0x00, 0x00});
    // 0x17C: call rax
    emitBytes(code, {0xFF, 0xD0});

    // 0x17E: movzx eax, byte [rsp+0x450]
    emitBytes(code, {0x0F, 0xB6, 0x84, 0x24, 0x50, 0x04, 0x00, 0x00});
    // 0x186: cmp al, '0'
    emitBytes(code, {0x3C, 0x30});
    // 0x188: je _block (rel32 -> 0x1D6, disp=0x48)
    emitBytes(code, {0x0F, 0x84, 0x48, 0x00, 0x00, 0x00});
    // 0x18E: jmp _allow_direct (rel32 -> 0x1A4, disp=0x11)
    emitBytes(code, {0xE9, 0x11, 0x00, 0x00, 0x00});

    // _close_and_allow at 0x193
    // 0x193: mov rcx, [rsp+0x440]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    // 0x19B: mov rax, [rip+fn_CloseHandle]  ; slot 0x318, disp=0x176
    emitBytes(code, {0x48, 0x8B, 0x05, 0x76, 0x01, 0x00, 0x00});
    // 0x1A2: call rax
    emitBytes(code, {0xFF, 0xD0});
    // fallthrough to _allow_direct

    // _allow_direct at 0x1A4
    // 0x1A4: mov rcx, [rsp+0x458]
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    // 0x1AC: mov rdx, [rsp+0x460]
    emitBytes(code, {0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    // 0x1B4: mov r8, [rsp+0x468]
    emitBytes(code, {0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    // 0x1BC: mov r9, [rsp+0x470]
    emitBytes(code, {0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});
    // 0x1C4: add rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});
    // 0x1CB: <5 saved prologue bytes>
    for (int i = 0; i < 5; i++) code.push_back(savedPrologue[i]);
    // 0x1D0: jmp qword [rip+abs_orig_plus_5] ; slot 0x320, disp=0x14A
    emitBytes(code, {0xFF, 0x25, 0x4A, 0x01, 0x00, 0x00});

    // _block at 0x1D6
    // 0x1D6: add rsp, 0x478
    emitBytes(code, {0x48, 0x81, 0xC4, 0x78, 0x04, 0x00, 0x00});
    // 0x1DD: mov eax, 0xC0000135            ; STATUS_DLL_NOT_FOUND
    emitBytes(code, {0xB8, 0x35, 0x01, 0x00, 0xC0});
    // 0x1E2: ret
    emitBytes(code, {0xC3});

    if (code.size() > 0x300) {
        FVM_LOG("buildLdrLoadDllTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    writeU64(buf, 0x300, fnCreateFileA);
    writeU64(buf, 0x308, fnWriteFile);
    writeU64(buf, 0x310, fnReadFile);
    writeU64(buf, 0x318, fnCloseHandle);
    writeU64(buf, 0x320, origPlus5);
    writeU64(buf, 0x328, fnWideCharToMultiByte);
    buf[0x330] = static_cast<uint8_t>('N');

    size_t pn = 0;
    if (pipeName != nullptr) {
        while (pipeName[pn] != '\0' && pn < 127) {
            buf[0x340 + pn] = static_cast<uint8_t>(pipeName[pn]);
            pn++;
        }
    }
    buf[0x340 + pn] = 0;

    return buf;
}

static int installLdrLoadDllFilter(PatchState& state, const char* pipeName) {
    /* ntdll!LdrLoadDll patching only needs a valid process handle — ntdll is
     * mapped into every Win32 process from creation. structMapReady (which
     * requires jvm.dll) is not required, so this can run on a CREATE_SUSPENDED
     * new JVM during relaunch. */
    if (g_target.handle == NULL) {
        setError("no_target_handle");
        return 0;
    }
    if (state.patched) {
        setError("already_patched");
        return 0;
    }
    if (pipeName == nullptr || pipeName[0] == '\0') {
        setError("missing_pipe_name");
        return 0;
    }

    HANDLE proc = g_target.handle;
    uint64_t addr = resolveNtdllExport(proc, "LdrLoadDll");
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("ban_native_load: ntdll!LdrLoadDll @ 0x%llX", (unsigned long long)addr);

    uint8_t saved5[5] = {};
    if (!readRemoteMem(proc, addr, saved5, 5)) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("ban_native_load: original prologue: %02X %02X %02X %02X %02X",
            saved5[0], saved5[1], saved5[2], saved5[3], saved5[4]);

    uint8_t b0 = saved5[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        setError("unsafe_prologue");
        return 0;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        setError("kernel32_not_loaded");
        return 0;
    }
    uint64_t fnCreate = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CreateFileA"));
    uint64_t fnWrite  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "WriteFile"));
    uint64_t fnRead   = reinterpret_cast<uint64_t>(GetProcAddress(k32, "ReadFile"));
    uint64_t fnClose  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CloseHandle"));
    uint64_t fnWcm    = reinterpret_cast<uint64_t>(GetProcAddress(k32, "WideCharToMultiByte"));
    if (!fnCreate || !fnWrite || !fnRead || !fnClose || !fnWcm) {
        setError("kernel32_resolve_failed");
        return 0;
    }

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
        saved5, addr + 5, fnCreate, fnWrite, fnRead, fnClose, fnWcm, pipeName);
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

    uint8_t patch[5];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);

    if (!writeRemoteCode(proc, addr, patch, sizeof(patch))) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[5] = {};
    readRemoteMem(proc, addr, verify, sizeof(verify));
    if (memcmp(verify, patch, sizeof(patch)) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = 5;
    memcpy(state.original, saved5, 5);
    state.patched = true;
    state.trampolineAddr = trampAddr;
    state.trampolineSize = kPage;
    state.trampolineInstalled = true;

    FVM_LOG("ban_native_load: installed LdrLoadDll trampoline + E9 patch (verified)");
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_ban_java_agent(const char* pipeName) {
    return installFilterTrampoline(g_javaAgentPatch, "JVM_EnqueueOperation",
                                    /*pathInRdx=*/true, 'A', pipeName, "ban_java_agent");
}

extern "C" __declspec(dllexport) int forgevm_unban_java_agent() {
    return uninstallFilterTrampoline(g_javaAgentPatch, "unban_java_agent");
}

extern "C" __declspec(dllexport) int forgevm_ban_native_load(const char* pipeName) {
    return installLdrLoadDllFilter(g_nativeLoadPatch, pipeName);
}

extern "C" __declspec(dllexport) int forgevm_unban_native_load() {
    return uninstallFilterTrampoline(g_nativeLoadPatch, "unban_native_load");
}

// ============================================================
// ntdll!NtCreateUserProcess hook — process creation filter
//
// NtCreateUserProcess is the single kernel-mode entry point for all
// user-mode process creation: CreateProcessW, ProcessBuilder,
// and any native code calling CreateProcess* directly all funnel here.
//
// NtCreateUserProcess x64 signature (11 parameters):
//   NTSTATUS NTAPI NtCreateUserProcess(
//       PHANDLE  ProcessHandle,               // rcx
//       PHANDLE  ThreadHandle,                // rdx
//       ACCESS_MASK ProcessDesiredAccess,     // r8
//       ACCESS_MASK ThreadDesiredAccess,      // r9
//       POBJECT_ATTRIBUTES ProcessObjAttrs,  // [rsp+0x28]  ← image path here
//       POBJECT_ATTRIBUTES ThreadObjAttrs,   // [rsp+0x30]
//       ULONG    ProcessFlags,               // [rsp+0x38]
//       ULONG    ThreadFlags,                // [rsp+0x40]
//       PRTL_USER_PROCESS_PARAMETERS Params, // [rsp+0x48]
//       PPS_CREATE_INFO CreateInfo,          // [rsp+0x50]
//       PPS_ATTRIBUTE_LIST AttrList);        // [rsp+0x58]
//
// Image path: ProcessObjAttrs->ObjectName (UNICODE_STRING* at OA+0x10).
// The NT path may carry a \??\ prefix; glob matching on the full path
// (including prefix) still works with patterns like *processproxy*.
// Block return: STATUS_ACCESS_DENIED (0xC0000005).
//
// Data layout (identical slot offsets to LdrLoadDll trampoline):
//   +0x300  fn_CreateFileA
//   +0x308  fn_WriteFile
//   +0x310  fn_ReadFile
//   +0x318  fn_CloseHandle
//   +0x320  abs_orig_plus_5
//   +0x328  fn_WideCharToMultiByte
//   +0x330  kind_byte ('P')
//   +0x340  pipe_name
//
// Stack frame after `sub rsp, 0x4A8`:
//   +0x20..0x3F   shadow space for API calls
//   +0x40         kind byte
//   +0x41..0x3F0  UTF-8 path buffer (800 bytes)
//   +0x440        saved pipe HANDLE
//   +0x448        WriteFile bytes-written (DWORD)
//   +0x44C        ReadFile bytes-read (DWORD)
//   +0x450        reply byte
//   +0x458        saved rcx
//   +0x460        saved rdx
//   +0x468        saved r8
//   +0x470        saved r9
//   +0x4D0        original arg5 (ProcessObjAttrs) — [caller_rsp+0x28]
// ============================================================
static std::vector<uint8_t> buildNtCreateUserProcessTrampoline(
    const uint8_t* savedPrologue,
    uint64_t origPlus5,
    uint64_t fnCreateFileA,
    uint64_t fnWriteFile,
    uint64_t fnReadFile,
    uint64_t fnCloseHandle,
    uint64_t fnWideCharToMultiByte,
    const char* pipeName)
{
    const size_t kPageSize = 0x400;
    std::vector<uint8_t> buf(kPageSize, 0xCC);

    std::vector<uint8_t> code;
    code.reserve(0x200);

    /* === Prologue: allocate frame, save register args === */
    /* 0x000: sub rsp, 0x4A8 */
    emitBytes(code, {0x48, 0x81, 0xEC, 0xA8, 0x04, 0x00, 0x00});
    /* 0x007: mov [rsp+0x458], rcx */
    emitBytes(code, {0x48, 0x89, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    /* 0x00F: mov [rsp+0x460], rdx */
    emitBytes(code, {0x48, 0x89, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    /* 0x017: mov [rsp+0x468], r8 */
    emitBytes(code, {0x4C, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    /* 0x01F: mov [rsp+0x470], r9 */
    emitBytes(code, {0x4C, 0x89, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});

    /* === Load ProcessObjectAttributes (arg5 = [rsp+0x4D0] after frame alloc) === */
    /* 0x027: mov r10, [rsp+0x4D0] */
    emitBytes(code, {0x4C, 0x8B, 0x94, 0x24, 0xD0, 0x04, 0x00, 0x00});
    /* 0x02F: test r10, r10 */
    emitBytes(code, {0x4D, 0x85, 0xD2});
    /* 0x032: je _allow_direct  (disp32 = 0x1B2 - 0x038 = 0x17A) */
    emitBytes(code, {0x0F, 0x84, 0x7A, 0x01, 0x00, 0x00});

    /* === Load OBJECT_ATTRIBUTES.ObjectName (at OA+0x10) === */
    /* 0x038: mov r10, [r10+0x10] */
    emitBytes(code, {0x4D, 0x8B, 0x52, 0x10});
    /* 0x03C: test r10, r10 */
    emitBytes(code, {0x4D, 0x85, 0xD2});
    /* 0x03F: je _allow_direct  (disp32 = 0x1B2 - 0x045 = 0x16D) */
    emitBytes(code, {0x0F, 0x84, 0x6D, 0x01, 0x00, 0x00});

    /* === Load UNICODE_STRING.Length (r11d) and .Buffer (r10) === */
    /* 0x045: movzx r11d, word [r10]  — UNICODE_STRING.Length (bytes) */
    emitBytes(code, {0x45, 0x0F, 0xB7, 0x1A});
    /* 0x049: test r11d, r11d */
    emitBytes(code, {0x45, 0x85, 0xDB});
    /* 0x04C: je _allow_direct  (disp32 = 0x1B2 - 0x052 = 0x160) */
    emitBytes(code, {0x0F, 0x84, 0x60, 0x01, 0x00, 0x00});
    /* 0x052: mov r10, [r10+0x08]  — UNICODE_STRING.Buffer */
    emitBytes(code, {0x4D, 0x8B, 0x52, 0x08});
    /* 0x056: test r10, r10 */
    emitBytes(code, {0x4D, 0x85, 0xD2});
    /* 0x059: je _allow_direct  (disp32 = 0x1B2 - 0x05F = 0x153) */
    emitBytes(code, {0x0F, 0x84, 0x53, 0x01, 0x00, 0x00});

    /* === Clamp wchar count === */
    /* 0x05F: shr r11d, 1  — Length(bytes) → wchar count */
    emitBytes(code, {0x41, 0xD1, 0xEB});
    /* 0x062: cmp r11d, 400 */
    emitBytes(code, {0x41, 0x81, 0xFB, 0x90, 0x01, 0x00, 0x00});
    /* 0x069: jbe _len_ok  (rel8: target=0x071, disp=0x071-0x06B=0x06) */
    emitBytes(code, {0x76, 0x06});
    /* 0x06B: mov r11d, 400 */
    emitBytes(code, {0x41, 0xBB, 0x90, 0x01, 0x00, 0x00});

    /* _len_ok at 0x071 */
    /* 0x071: movzx ecx, byte [rip+kind_byte]  (kind_byte@0x330, disp=0x330-0x078=0x2B8) */
    emitBytes(code, {0x0F, 0xB6, 0x0D, 0xB8, 0x02, 0x00, 0x00});
    /* 0x078: mov [rsp+0x40], cl */
    emitBytes(code, {0x88, 0x4C, 0x24, 0x40});

    /* === WideCharToMultiByte(CP_UTF8, 0, Buffer, cchWide, outBuf, 800, NULL, NULL) === */
    /* 0x07C: mov ecx, 65001 */
    emitBytes(code, {0xB9, 0xE9, 0xFD, 0x00, 0x00});
    /* 0x081: xor edx, edx */
    emitBytes(code, {0x33, 0xD2});
    /* 0x083: mov r8, r10  (Buffer) */
    emitBytes(code, {0x4D, 0x8B, 0xC2});
    /* 0x086: mov r9d, r11d  (wchar count) */
    emitBytes(code, {0x45, 0x8B, 0xCB});
    /* 0x089: lea rax, [rsp+0x41]  (outBuf) */
    emitBytes(code, {0x48, 0x8D, 0x44, 0x24, 0x41});
    /* 0x08E: mov [rsp+0x20], rax */
    emitBytes(code, {0x48, 0x89, 0x44, 0x24, 0x20});
    /* 0x093: mov dword [rsp+0x28], 800 */
    emitBytes(code, {0xC7, 0x44, 0x24, 0x28, 0x20, 0x03, 0x00, 0x00});
    /* 0x09B: mov qword [rsp+0x30], 0  (lpDefaultChar) */
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00});
    /* 0x0A4: mov qword [rsp+0x38], 0  (lpUsedDefaultChar) */
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00});
    /* 0x0AD: mov rax, [rip+fn_WideCharToMultiByte]  (slot@0x328, disp=0x328-0x0B4=0x274) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0x74, 0x02, 0x00, 0x00});
    /* 0x0B4: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* 0x0B6: test eax, eax */
    emitBytes(code, {0x85, 0xC0});
    /* 0x0B8: je _allow_direct  (conversion failed → fail-open; disp=0x1B2-0x0BE=0xF4) */
    emitBytes(code, {0x0F, 0x84, 0xF4, 0x00, 0x00, 0x00});

    /* 0x0BE: mov r11d, eax  (UTF-8 byte count) */
    emitBytes(code, {0x41, 0x89, 0xC3});
    /* 0x0C1: mov byte [rsp+r11+0x41], 0x0A  (newline terminator) */
    emitBytes(code, {0x42, 0xC6, 0x84, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x0A});

    /* === CreateFileA(pipe, GENERIC_READ|WRITE, 0, NULL, OPEN_EXISTING, 0, NULL) === */
    /* 0x0CA: lea rcx, [rip+pipe_name]  (pipe_name@0x340, disp=0x340-0x0D1=0x26F) */
    emitBytes(code, {0x48, 0x8D, 0x0D, 0x6F, 0x02, 0x00, 0x00});
    /* 0x0D1: mov edx, 0xC0000000 */
    emitBytes(code, {0xBA, 0x00, 0x00, 0x00, 0xC0});
    /* 0x0D6: xor r8d, r8d */
    emitBytes(code, {0x45, 0x33, 0xC0});
    /* 0x0D9: xor r9d, r9d */
    emitBytes(code, {0x45, 0x33, 0xC9});
    /* 0x0DC: mov dword [rsp+0x20], 3  (OPEN_EXISTING) */
    emitBytes(code, {0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00});
    /* 0x0E4: mov dword [rsp+0x28], 0 */
    emitBytes(code, {0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00});
    /* 0x0EC: mov qword [rsp+0x30], 0 */
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00});
    /* 0x0F5: mov rax, [rip+fn_CreateFileA]  (slot@0x300, disp=0x300-0x0FC=0x204) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0x04, 0x02, 0x00, 0x00});
    /* 0x0FC: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* 0x0FE: cmp rax, -1  (INVALID_HANDLE_VALUE) */
    emitBytes(code, {0x48, 0x83, 0xF8, 0xFF});
    /* 0x102: je _allow_direct  (disp=0x1B2-0x108=0xAA) */
    emitBytes(code, {0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00});
    /* 0x108: mov [rsp+0x440], rax  (save pipe handle) */
    emitBytes(code, {0x48, 0x89, 0x84, 0x24, 0x40, 0x04, 0x00, 0x00});

    /* === WriteFile(handle, &buf[0x40], r11+2, &wrote, NULL) === */
    /* 0x110: mov rcx, [rsp+0x440] */
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    /* 0x118: lea rdx, [rsp+0x40] */
    emitBytes(code, {0x48, 0x8D, 0x54, 0x24, 0x40});
    /* 0x11D: lea r8, [r11+2]  (kind byte + path bytes + '\n') */
    emitBytes(code, {0x4D, 0x8D, 0x43, 0x02});
    /* 0x121: lea r9, [rsp+0x448] */
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x48, 0x04, 0x00, 0x00});
    /* 0x129: mov qword [rsp+0x20], 0 */
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    /* 0x132: mov rax, [rip+fn_WriteFile]  (slot@0x308, disp=0x308-0x139=0x1CF) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0xCF, 0x01, 0x00, 0x00});
    /* 0x139: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* 0x13B: test eax, eax */
    emitBytes(code, {0x85, 0xC0});
    /* 0x13D: je _close_and_allow  (disp=0x1A1-0x143=0x5E) */
    emitBytes(code, {0x0F, 0x84, 0x5E, 0x00, 0x00, 0x00});

    /* === ReadFile(handle, &reply, 1, &got, NULL) === */
    /* 0x143: mov rcx, [rsp+0x440] */
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    /* 0x14B: lea rdx, [rsp+0x450] */
    emitBytes(code, {0x48, 0x8D, 0x94, 0x24, 0x50, 0x04, 0x00, 0x00});
    /* 0x153: mov r8d, 1 */
    emitBytes(code, {0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});
    /* 0x159: lea r9, [rsp+0x44C] */
    emitBytes(code, {0x4C, 0x8D, 0x8C, 0x24, 0x4C, 0x04, 0x00, 0x00});
    /* 0x161: mov qword [rsp+0x20], 0 */
    emitBytes(code, {0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00});
    /* 0x16A: mov rax, [rip+fn_ReadFile]  (slot@0x310, disp=0x310-0x171=0x19F) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0x9F, 0x01, 0x00, 0x00});
    /* 0x171: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* 0x173: test eax, eax */
    emitBytes(code, {0x85, 0xC0});
    /* 0x175: je _close_and_allow  (disp=0x1A1-0x17B=0x26) */
    emitBytes(code, {0x0F, 0x84, 0x26, 0x00, 0x00, 0x00});

    /* === CloseHandle + check reply === */
    /* 0x17B: mov rcx, [rsp+0x440] */
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    /* 0x183: mov rax, [rip+fn_CloseHandle]  (slot@0x318, disp=0x318-0x18A=0x18E) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0x8E, 0x01, 0x00, 0x00});
    /* 0x18A: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* 0x18C: movzx eax, byte [rsp+0x450] */
    emitBytes(code, {0x0F, 0xB6, 0x84, 0x24, 0x50, 0x04, 0x00, 0x00});
    /* 0x194: cmp al, '0' */
    emitBytes(code, {0x3C, 0x30});
    /* 0x196: je _block  (disp=0x1E4-0x19C=0x48) */
    emitBytes(code, {0x0F, 0x84, 0x48, 0x00, 0x00, 0x00});
    /* 0x19C: jmp _allow_direct  (disp=0x1B2-0x1A1=0x11) */
    emitBytes(code, {0xE9, 0x11, 0x00, 0x00, 0x00});

    /* === _close_and_allow at 0x1A1 === */
    /* 0x1A1: mov rcx, [rsp+0x440] */
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x40, 0x04, 0x00, 0x00});
    /* 0x1A9: mov rax, [rip+fn_CloseHandle]  (slot@0x318, disp=0x318-0x1B0=0x168) */
    emitBytes(code, {0x48, 0x8B, 0x05, 0x68, 0x01, 0x00, 0x00});
    /* 0x1B0: call rax */
    emitBytes(code, {0xFF, 0xD0});

    /* === _allow_direct at 0x1B2 === */
    /* 0x1B2: mov rcx, [rsp+0x458] */
    emitBytes(code, {0x48, 0x8B, 0x8C, 0x24, 0x58, 0x04, 0x00, 0x00});
    /* 0x1BA: mov rdx, [rsp+0x460] */
    emitBytes(code, {0x48, 0x8B, 0x94, 0x24, 0x60, 0x04, 0x00, 0x00});
    /* 0x1C2: mov r8, [rsp+0x468] */
    emitBytes(code, {0x4C, 0x8B, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00});
    /* 0x1CA: mov r9, [rsp+0x470] */
    emitBytes(code, {0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x04, 0x00, 0x00});
    /* 0x1D2: add rsp, 0x4A8 */
    emitBytes(code, {0x48, 0x81, 0xC4, 0xA8, 0x04, 0x00, 0x00});
    /* 0x1D9: <5 saved prologue bytes> */
    for (int i = 0; i < 5; i++) code.push_back(savedPrologue[i]);
    /* 0x1DE: jmp qword [rip+abs_orig_plus_5]  (slot@0x320, disp=0x320-0x1E4=0x13C) */
    emitBytes(code, {0xFF, 0x25, 0x3C, 0x01, 0x00, 0x00});

    /* === _block at 0x1E4 === */
    /* 0x1E4: add rsp, 0x4A8 */
    emitBytes(code, {0x48, 0x81, 0xC4, 0xA8, 0x04, 0x00, 0x00});
    /* 0x1EB: mov eax, 0xC0000005  (STATUS_ACCESS_DENIED) */
    emitBytes(code, {0xB8, 0x05, 0x00, 0x00, 0xC0});
    /* 0x1F0: ret */
    emitBytes(code, {0xC3});

    if (code.size() > 0x300) {
        FVM_LOG("buildNtCreateUserProcessTrampoline: code too large (%zu bytes)", code.size());
        return {};
    }
    for (size_t i = 0; i < code.size(); i++) buf[i] = code[i];

    writeU64(buf, 0x300, fnCreateFileA);
    writeU64(buf, 0x308, fnWriteFile);
    writeU64(buf, 0x310, fnReadFile);
    writeU64(buf, 0x318, fnCloseHandle);
    writeU64(buf, 0x320, origPlus5);
    writeU64(buf, 0x328, fnWideCharToMultiByte);
    buf[0x330] = static_cast<uint8_t>('P');

    size_t pn = 0;
    if (pipeName != nullptr) {
        while (pipeName[pn] != '\0' && pn < 127) {
            buf[0x340 + pn] = static_cast<uint8_t>(pipeName[pn]);
            pn++;
        }
    }
    buf[0x340 + pn] = 0;

    return buf;
}

static int installNtCreateUserProcessFilter(PatchState& state, const char* pipeName) {
    if (g_target.handle == NULL) {
        setError("no_target_handle");
        return 0;
    }
    if (state.patched) {
        setError("already_patched");
        return 0;
    }
    if (pipeName == nullptr || pipeName[0] == '\0') {
        setError("missing_pipe_name");
        return 0;
    }

    HANDLE proc = g_target.handle;
    uint64_t addr = resolveNtdllExport(proc, "NtCreateUserProcess");
    if (addr == 0) {
        setError("export_not_found");
        return 0;
    }
    FVM_LOG("ban_process_create: ntdll!NtCreateUserProcess @ 0x%llX", (unsigned long long)addr);

    uint8_t saved5[5] = {};
    if (!readRemoteMem(proc, addr, saved5, 5)) {
        setError("read_original_failed");
        return 0;
    }
    FVM_LOG("ban_process_create: original prologue: %02X %02X %02X %02X %02X",
            saved5[0], saved5[1], saved5[2], saved5[3], saved5[4]);

    uint8_t b0 = saved5[0];
    bool dangerous = (b0 == 0xE8) || (b0 == 0xE9) || (b0 == 0xEB) ||
                     (b0 >= 0x70 && b0 <= 0x7F) || (b0 == 0xFF);
    if (dangerous) {
        setError("unsafe_prologue");
        return 0;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        setError("kernel32_not_loaded");
        return 0;
    }
    uint64_t fnCreate = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CreateFileA"));
    uint64_t fnWrite  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "WriteFile"));
    uint64_t fnRead   = reinterpret_cast<uint64_t>(GetProcAddress(k32, "ReadFile"));
    uint64_t fnClose  = reinterpret_cast<uint64_t>(GetProcAddress(k32, "CloseHandle"));
    uint64_t fnWcm    = reinterpret_cast<uint64_t>(GetProcAddress(k32, "WideCharToMultiByte"));
    if (!fnCreate || !fnWrite || !fnRead || !fnClose || !fnWcm) {
        setError("kernel32_resolve_failed");
        return 0;
    }

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
        saved5, addr + 5, fnCreate, fnWrite, fnRead, fnClose, fnWcm, pipeName);
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

    uint8_t patch[5];
    patch[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(delta);
    patch[1] = static_cast<uint8_t>(rel);
    patch[2] = static_cast<uint8_t>(rel >> 8);
    patch[3] = static_cast<uint8_t>(rel >> 16);
    patch[4] = static_cast<uint8_t>(rel >> 24);

    if (!writeRemoteCode(proc, addr, patch, sizeof(patch))) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("write_patch_failed");
        return 0;
    }

    uint8_t verify[5] = {};
    readRemoteMem(proc, addr, verify, sizeof(verify));
    if (memcmp(verify, patch, sizeof(patch)) != 0) {
        VirtualFreeEx(proc, allocated, 0, MEM_RELEASE);
        setError("verify_failed");
        return 0;
    }

    state.targetAddr = addr;
    state.patchSize = 5;
    memcpy(state.original, saved5, 5);
    state.patched = true;
    state.trampolineAddr = trampAddr;
    state.trampolineSize = kPage;
    state.trampolineInstalled = true;

    FVM_LOG("ban_process_create: installed NtCreateUserProcess trampoline + E9 patch (verified)");
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_ban_process_create(const char* pipeName) {
    return installNtCreateUserProcessFilter(g_processCreatePatch, pipeName);
}

extern "C" __declspec(dllexport) int forgevm_unban_process_create() {
    return uninstallFilterTrampoline(g_processCreatePatch, "unban_process_create");
}
