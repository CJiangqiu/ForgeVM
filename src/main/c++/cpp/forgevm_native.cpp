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
bool g_promptApproved = false;
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

bool isAdmin() {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;
    if (!AllocateAndInitializeSid(&ntAuthority, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &adminGroup)) {
        setError("alloc_admin_sid_failed");
        return false;
    }

    BOOL isMember = FALSE;
    if (!CheckTokenMembership(NULL, adminGroup, &isMember)) {
        FreeSid(adminGroup);
        setError("check_admin_membership_failed");
        return false;
    }

    FreeSid(adminGroup);
    return isMember == TRUE;
}

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

int resolveCapabilityByToken() {
    if (isAdmin()) {
        if (enableDebugPrivilege()) return 2;
        return 1;
    }
    if (enableDebugPrivilege()) return 1;
    setError("ok");
    return 1;
}

// ============================================================
// Exported functions
// ============================================================

extern "C" __declspec(dllexport) int forgevm_probe_capability() {
    g_promptApproved = false;
    return resolveCapabilityByToken();
}

extern "C" __declspec(dllexport) int forgevm_probe_capability_prompt() {
    g_promptApproved = false;
    int tokenCapability = resolveCapabilityByToken();
    if (tokenCapability > 0) return tokenCapability;

    HINSTANCE shellResult = ShellExecuteW(NULL, L"runas", L"powershell.exe",
                                          L"-NoProfile -Command exit 0", NULL, SW_HIDE);
    int resultCode = (int)(INT_PTR)shellResult;
    if (resultCode <= 32) {
        setError("elevation_prompt_rejected_or_failed");
        return 0;
    }

    g_promptApproved = true;
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_init() {
    FVM_LOG("forgevm_init() called");
    int capability = resolveCapabilityByToken();
    FVM_LOG("forgevm_init: capability=%d, promptApproved=%d", capability, (int)g_promptApproved);
    if (capability > 0 || g_promptApproved) {
        g_promptApproved = false;
        setError("ok");
        return 1;
    }
    g_promptApproved = false;
    return 0;
}

extern "C" __declspec(dllexport) int forgevm_bootstrap_target(unsigned long long targetPid) {
    FVM_LOG("forgevm_bootstrap_target(pid=%llu)", targetPid);
    if (g_target.handle != NULL) {
        CloseHandle(g_target.handle);
        g_target = TargetProcess{};
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
