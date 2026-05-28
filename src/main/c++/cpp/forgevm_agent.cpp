#include <windows.h>
#include <shellapi.h>
#include <aclapi.h>
/* WMI for relaunch: link ole32.lib oleaut32.lib wbemuuid.lib */
#include <comdef.h>
#include <wbemidl.h>
/* EnumProcessModulesEx / GetModuleBaseNameW for relaunch post-resume watcher. Link Psapi.lib. */
#include <psapi.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <cstdio>
#include <cstdarg>
#include <cwctype>
/* For redirecting stdin/stdout to the handoff command pipe after old JVM dies. */
#include <io.h>
#include <fcntl.h>

// ============================================================
// Agent-level file logging — unified with DLL into one file
// ============================================================

static FILE* g_agentLog = nullptr;
static std::string g_logDir;   // resolved once, passed to DLL for its own log

static void agentLogInit(const std::string& logDir) {
    g_logDir = logDir;
    std::string logPath;
    if (!logDir.empty()) {
        logPath = logDir;
        char last = logPath.back();
        if (last != '\\' && last != '/') logPath += '\\';
        CreateDirectoryA(logPath.c_str(), NULL);
        logPath += "fvm-agent.log";
    } else {
        logPath = "fvm-agent.log";
    }
    g_agentLog = fopen(logPath.c_str(), "w");
    if (g_agentLog) {
        fprintf(g_agentLog, "===== ForgeVM Agent session =====\n");
        fflush(g_agentLog);
    }
}

static void agentLog(const char* fmt, ...) {
    if (!g_agentLog) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_agentLog, "%04d-%02d-%02d %02d:%02d:%02d.%03d | ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_agentLog, fmt, args);
    va_end(args);
    fprintf(g_agentLog, "\n");
    fflush(g_agentLog);
}

#define AGENT_LOG(fmt, ...) agentLog(fmt, ##__VA_ARGS__)

typedef int(__cdecl* ProbeFn)();
typedef int(__cdecl* InitFn)();
typedef const char* (__cdecl* LastErrorFn)();
typedef int(__cdecl* ExitByPidFn)(unsigned long long, int);
typedef int(__cdecl* BootstrapTargetFn)(unsigned long long);
typedef unsigned long long(__cdecl* StructMapCountFn)();
typedef int(__cdecl* PutFieldFn)(unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* PutFieldBatchFn)(const unsigned long long*, unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef void(__cdecl* SetLogDirFn)(const char*);
typedef int(__cdecl* ForceDeoptNowFn)();
typedef int(__cdecl* PurgeAgentsMatchingFn)(int, const char* const*, int);
typedef int(__cdecl* PutFieldPathFn)(const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* PutObjectFieldPathFn)(const char*, const char*, const char*, const char*);
typedef int(__cdecl* BanJavaAgentFn)(const char*);
typedef int(__cdecl* UnbanJavaAgentFn)();
typedef int(__cdecl* BanNativeLoadFn)(const char*);
typedef int(__cdecl* UnbanNativeLoadFn)();
typedef int(__cdecl* BanProcessCreateFn)(const char*);
typedef int(__cdecl* UnbanProcessCreateFn)();
typedef int(__cdecl* ForgeClassPlanFn)(const char*, const char*, int, int, char*, int);
typedef int(__cdecl* ForgeClassUnloadFn)(const char*, int);

namespace {
struct NativeApi {
    HMODULE module = NULL;
    ProbeFn probe = NULL;
    InitFn init = NULL;
    LastErrorFn lastError = NULL;
    ExitByPidFn exitByPid = NULL;
    BootstrapTargetFn bootstrapTarget = NULL;
    StructMapCountFn structMapCount = NULL;
    StructMapCountFn typeMapCount = NULL;
    LastErrorFn compressionInfo = NULL;
    PutFieldFn putField = NULL;
    PutFieldBatchFn putFieldBatch = NULL;
    PutFieldFn putRefField = NULL;
    PutFieldBatchFn putRefFieldBatch = NULL;
    ProbeFn dumpCardStructs = NULL;
    SetLogDirFn setLogDir = NULL;
    ForceDeoptNowFn forceDeoptNow = NULL;
    PurgeAgentsMatchingFn purgeAgentsMatching = NULL;
    PutFieldPathFn putFieldPath = NULL;
    PutObjectFieldPathFn putObjectFieldPath = NULL;
    BanJavaAgentFn banJavaAgent = NULL;
    UnbanJavaAgentFn unbanJavaAgent = NULL;
    BanNativeLoadFn banNativeLoad = NULL;
    UnbanNativeLoadFn unbanNativeLoad = NULL;
    BanProcessCreateFn banProcessCreate = NULL;
    UnbanProcessCreateFn unbanProcessCreate = NULL;
    ForgeClassPlanFn forgeClassPlan = NULL;
    ForgeClassUnloadFn forgeClassUnload = NULL;
};

struct AgentLockState {
    bool locked = false;
    ULONGLONG lockUntilTick = 0;
    unsigned long long ownerPid = 0ULL;
};


// Self-DACL hardening: deny PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
// to Everyone on our own process object. Blocks same-user non-admin kills and injection.
// Admin with TakeOwnership can still override.
static bool hardenSelfProcessDACL() {
    HANDLE hSelf = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                         GetCurrentProcess(), &hSelf,
                         WRITE_DAC | READ_CONTROL, FALSE, 0)) {
        return false;
    }

    PACL pOldDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (GetSecurityInfo(hSelf, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS) {
        CloseHandle(hSelf);
        return false;
    }

    PSID pEveryone = NULL;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &pEveryone)) {
        if (pSD) LocalFree(pSD);
        CloseHandle(hSelf);
        return false;
    }

    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pEveryone);

    PACL pNewDACL = NULL;
    bool ok = false;
    if (SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL) == ERROR_SUCCESS) {
        ok = SetSecurityInfo(hSelf, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                             NULL, NULL, pNewDACL, NULL) == ERROR_SUCCESS;
    }

    if (pNewDACL) LocalFree(pNewDACL);
    if (pEveryone) FreeSid(pEveryone);
    if (pSD) LocalFree(pSD);
    CloseHandle(hSelf);
    return ok;
}

// Parent process watchdog: exits agent when parent JVM dies
static std::atomic<DWORD> g_parentPid{0};

/* Set true by handleRelaunch after a successful CREATE_SUSPENDED + suspended-time
 * hook install. Tells main() to NOT exit when stdin EOFs (old JVM is dead) — the
 * agent must persist to keep serving the filter pipe so the ntdll hook in the new
 * JVM continues to receive allow/block decisions. */
static std::atomic<bool> g_persistAfterEOF{false};

/* SYNCHRONIZE handle to the relaunched JVM, published by handleRelaunch.
 * Lets the post-relaunch handoff wait give up the instant the new JVM exits
 * instead of blocking forever on a client that will never connect — without
 * this the agent leaks one zombie per relaunch whose JVM dies pre-handoff. */
static std::atomic<HANDLE> g_relaunchNewJvm{NULL};

/* Manual-reset event the post-relaunch watcher sets when it concludes the new
 * JVM will never hand off (jvm.dll never loaded, or bootstrap failed). The
 * handoff wait also watches it, so a new JVM that hangs alive — never dying,
 * never connecting — still releases the agent instead of pinning it forever. */
static std::atomic<HANDLE> g_relaunchAbortEvent{NULL};

DWORD WINAPI parentWatchdogThread(LPVOID) {
    /* Short-timeout polling instead of INFINITE wait. The agent's parent pid
     * changes mid-life during relaunch (`g_parentPid.store(0)` to disable,
     * then `.store(new_jvm_pid)` once the new JVM is created). A blocking
     * INFINITE wait on the old handle would never observe these transitions
     * and would force-exit the moment the old JVM is terminated — killing
     * the persistent agent before it can serve the new JVM.
     *
     * The 200ms loop:
     *   - tracks the current g_parentPid value
     *   - re-opens the handle when pid changes
     *   - on parent death, only exits if g_parentPid still points to the
     *     same (now-dead) pid AND g_persistAfterEOF is not set (i.e. we
     *     aren't in the middle of a relaunch handoff). */
    DWORD lastPid = 0;
    HANDLE hParent = NULL;
    while (true) {
        DWORD pid = g_parentPid.load();

        if (pid != lastPid) {
            if (hParent) { CloseHandle(hParent); hParent = NULL; }
            lastPid = pid;
            if (pid != 0) {
                hParent = OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (hParent == NULL) {
                    /* Can't open — could be transient (e.g. process just spawned
                     * and ACLs not stable yet). Retry next tick instead of
                     * exiting; only ExitProcess once we previously had a valid
                     * handle and saw a WAIT_OBJECT_0 signal. */
                    lastPid = 0;
                }
            }
        }

        if (hParent == NULL) {
            Sleep(200);
            continue;
        }

        DWORD r = WaitForSingleObject(hParent, 200);
        if (r != WAIT_OBJECT_0) continue; /* still alive, loop */

        /* Parent process is gone. Decide whether to exit. */
        CloseHandle(hParent);
        hParent = NULL;

        DWORD nowPid = g_parentPid.load();
        if (nowPid != lastPid) {
            /* Pid was switched (relaunch in progress). Loop will re-open. */
            lastPid = 0;
            continue;
        }
        if (g_persistAfterEOF.load()) {
            /* Relaunch armed persistence — old JVM died as expected, new pid
             * not yet stored. Wait for g_parentPid to be updated. */
            lastPid = 0;
            continue;
        }
        /* Truly orphaned — exit. */
        ExitProcess(0);
    }
    return 0;
}

ULONGLONG nowTick() {
    return GetTickCount64();
}

bool lockExpired(const AgentLockState& lockState) {
    return !lockState.locked || nowTick() >= lockState.lockUntilTick;
}

void refreshLockIfExpired(AgentLockState* lockState) {
    if (lockState->locked && lockExpired(*lockState)) {
        lockState->locked = false;
        lockState->lockUntilTick = 0;
        lockState->ownerPid = 0ULL;
    }
}

std::wstring toWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (length <= 0) return std::wstring();
    std::wstring wide(length - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], length);
    return wide;
}

std::string parseArg(const char* prefix, int argc, char** argv) {
    std::string needle(prefix);
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg.rfind(needle, 0) == 0) return arg.substr(needle.size());
    }
    return std::string();
}

bool hasFlag(const char* flag, int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == flag) return true;
    }
    return false;
}

// Wide-char command line parsing (bypasses codepage issues)
std::wstring parseArgW(const wchar_t* prefix, int argc, wchar_t** argv) {
    std::wstring needle(prefix);
    for (int i = 1; i < argc; ++i) {
        std::wstring arg(argv[i]);
        if (arg.rfind(needle, 0) == 0) return arg.substr(needle.size());
    }
    return std::wstring();
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 0) return std::string();
    std::string utf8(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, NULL, NULL);
    return utf8;
}

const char* capFromCode(int code) {
    return code >= 1 ? "FULL" : "UNAVAILABLE";
}

std::string escapeJson(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (size_t i = 0; i < value.size(); ++i) {
        char c = value[i];
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

void printResultWithFields(const char* status,
                           const char* capability,
                           const std::string& dllPath,
                           const char* reason,
                           const std::vector<std::pair<std::string, std::string>>& fields) {
    std::ostringstream oss;
    oss << "{\"status\":\"" << escapeJson(status)
        << "\",\"capability\":\"" << escapeJson(capability)
        << "\",\"dllPath\":\"" << escapeJson(dllPath)
        << "\",\"reason\":\"" << escapeJson(reason) << "\"";
    for (size_t i = 0; i < fields.size(); ++i) {
        oss << ",\"" << escapeJson(fields[i].first)
            << "\":\"" << escapeJson(fields[i].second) << "\"";
    }
    oss << "}";
    std::cout << oss.str() << std::endl;
}

void printResult(const char* status,
                 const char* capability,
                 const std::string& dllPath,
                 const char* reason) {
    std::ostringstream oss;
    oss << "{\"status\":\"" << escapeJson(status)
        << "\",\"capability\":\"" << escapeJson(capability)
        << "\",\"dllPath\":\"" << escapeJson(dllPath)
        << "\",\"reason\":\"" << escapeJson(reason) << "\"}";
    std::cout << oss.str() << std::endl;
}

std::string getJsonStringField(const std::string& line, const std::string& key) {
    std::string pattern = "\"" + key + "\":\"";
    size_t start = line.find(pattern);
    if (start == std::string::npos) return std::string();
    start += pattern.size();

    std::string value;
    bool escaped = false;
    for (size_t i = start; i < line.size(); ++i) {
        char c = line[i];
        if (escaped) {
            switch (c) {
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case '"': value += '"';  break;
                case '\\': value += '\\'; break;
                default:   value += c;   break;
            }
            escaped = false;
            continue;
        }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') return value;
        value += c;
    }
    return std::string();
}

unsigned long long getJsonUnsignedField(const std::string& line,
                                        const std::string& key,
                                        unsigned long long fallback) {
    std::string pattern = "\"" + key + "\":";
    size_t start = line.find(pattern);
    if (start == std::string::npos) return fallback;
    start += pattern.size();

    while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) start++;

    bool quoted = false;
    if (start < line.size() && line[start] == '"') { quoted = true; start++; }

    size_t end = start;
    while (end < line.size() && line[end] >= '0' && line[end] <= '9') end++;
    if (end == start) return fallback;
    if (quoted && (end >= line.size() || line[end] != '"')) return fallback;

    return static_cast<unsigned long long>(
        strtoull(line.substr(start, end - start).c_str(), NULL, 10));
}

std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto hexNibble = [](char c) -> unsigned char {
            if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
            return 0;
        };
        result.push_back(static_cast<unsigned char>((hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1])));
    }
    return result;
}

std::vector<unsigned long long> parseJsonUint64Array(const std::string& line, const std::string& key) {
    std::vector<unsigned long long> result;
    std::string pattern = "\"" + key + "\":[";
    size_t start = line.find(pattern);
    if (start == std::string::npos) return result;
    start += pattern.size();

    size_t end = line.find(']', start);
    if (end == std::string::npos) return result;

    size_t i = start;
    while (i < end) {
        while (i < end && (line[i] == ' ' || line[i] == '\t' || line[i] == ',')) i++;
        if (i >= end) break;
        size_t numStart = i;
        while (i < end && line[i] >= '0' && line[i] <= '9') i++;
        if (i > numStart) {
            result.push_back(strtoull(line.substr(numStart, i - numStart).c_str(), NULL, 10));
        } else {
            break;
        }
    }
    return result;
}

// Returns the index of the matching '}' for the '{' at openIdx, or npos.
// String/escape-aware so quoted braces don't confuse depth counting.
size_t findMatchingBrace(const std::string& s, size_t openIdx) {
    int depth = 0;
    bool inString = false;
    bool escaped = false;
    for (size_t i = openIdx; i < s.size(); ++i) {
        char c = s[i];
        if (escaped) { escaped = false; continue; }
        if (inString) {
            if (c == '\\') escaped = true;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') inString = true;
        else if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) return i;
        }
    }
    return std::string::npos;
}

// Extract the contents of "key":[...] (between [ and ], exclusive). Returns
// empty string if the array is absent or malformed. String/escape-aware.
std::string extractArrayInner(const std::string& s, const std::string& key) {
    std::string pat = "\"" + key + "\":[";
    size_t i = s.find(pat);
    if (i == std::string::npos) return std::string();
    size_t start = i + pat.size();
    int depth = 1;
    bool inString = false;
    bool escaped = false;
    for (size_t j = start; j < s.size(); ++j) {
        char c = s[j];
        if (escaped) { escaped = false; continue; }
        if (inString) {
            if (c == '\\') escaped = true;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') inString = true;
        else if (c == '[') depth++;
        else if (c == ']') {
            depth--;
            if (depth == 0) return s.substr(start, j - start);
        }
    }
    return std::string();
}

// Iterate top-level JSON objects in arrayInner, calling cb with each object's
// substring (including the outer braces). Other characters between objects
// (commas, whitespace) are skipped.
template<typename F>
void forEachJsonObject(const std::string& arrayInner, F cb) {
    size_t i = 0;
    while (i < arrayInner.size()) {
        char c = arrayInner[i];
        if (c == '{') {
            size_t end = findMatchingBrace(arrayInner, i);
            if (end == std::string::npos) return;
            cb(arrayInner.substr(i, end - i + 1));
            i = end + 1;
        } else {
            ++i;
        }
    }
}

// "true" / "false" lookup for "key":<bool>. Returns fallback if not found.
bool getJsonBoolField(const std::string& s, const std::string& key, bool fallback) {
    std::string truePat  = "\"" + key + "\":true";
    std::string falsePat = "\"" + key + "\":false";
    if (s.find(truePat)  != std::string::npos) return true;
    if (s.find(falsePat) != std::string::npos) return false;
    return fallback;
}

bool loadNativeApi(const std::wstring& wideDllPath, const std::string& dllPathUtf8, NativeApi* api, std::string* reason) {
    if (wideDllPath.empty()) { *reason = "dll_path_empty"; return false; }

    HMODULE module = LoadLibraryW(wideDllPath.c_str());
    if (module == NULL) {
        DWORD err = GetLastError();
        *reason = "load_library_failed:err=" + std::to_string(err) + ":path=" + dllPathUtf8;
        return false;
    }

    api->module = module;
    api->probe           = reinterpret_cast<ProbeFn>(GetProcAddress(module, "forgevm_probe_capability"));
    api->init            = reinterpret_cast<InitFn>(GetProcAddress(module, "forgevm_init"));
    api->lastError       = reinterpret_cast<LastErrorFn>(GetProcAddress(module, "forgevm_last_error"));
    api->exitByPid       = reinterpret_cast<ExitByPidFn>(GetProcAddress(module, "forgevm_exit_process"));
    api->bootstrapTarget     = reinterpret_cast<BootstrapTargetFn>(GetProcAddress(module, "forgevm_bootstrap_target"));
    api->structMapCount  = reinterpret_cast<StructMapCountFn>(GetProcAddress(module, "forgevm_structmap_count"));
    api->typeMapCount    = reinterpret_cast<StructMapCountFn>(GetProcAddress(module, "forgevm_typemap_count"));
    api->compressionInfo = reinterpret_cast<LastErrorFn>(GetProcAddress(module, "forgevm_compression_info"));
    api->putField        = reinterpret_cast<PutFieldFn>(GetProcAddress(module, "forgevm_put_field"));
    api->putFieldBatch   = reinterpret_cast<PutFieldBatchFn>(GetProcAddress(module, "forgevm_put_field_batch"));
    api->putRefField     = reinterpret_cast<PutFieldFn>(GetProcAddress(module, "forgevm_put_ref_field"));
    api->putRefFieldBatch = reinterpret_cast<PutFieldBatchFn>(GetProcAddress(module, "forgevm_put_ref_field_batch"));
    api->setLogDir       = reinterpret_cast<SetLogDirFn>(GetProcAddress(module, "forgevm_set_log_dir"));
    api->dumpCardStructs = reinterpret_cast<ProbeFn>(GetProcAddress(module, "forgevm_dump_card_structs"));
    api->forceDeoptNow   = reinterpret_cast<ForceDeoptNowFn>(GetProcAddress(module, "forgevm_force_deopt_now"));
    api->purgeAgentsMatching = reinterpret_cast<PurgeAgentsMatchingFn>(GetProcAddress(module, "forgevm_purge_agents_matching"));
    api->putFieldPath    = reinterpret_cast<PutFieldPathFn>(GetProcAddress(module, "forgevm_put_field_path"));
    api->putObjectFieldPath = reinterpret_cast<PutObjectFieldPathFn>(GetProcAddress(module, "forgevm_put_object_field_path"));
    api->banJavaAgent    = reinterpret_cast<BanJavaAgentFn>(GetProcAddress(module, "forgevm_ban_java_agent"));
    api->unbanJavaAgent  = reinterpret_cast<UnbanJavaAgentFn>(GetProcAddress(module, "forgevm_unban_java_agent"));
    api->banNativeLoad   = reinterpret_cast<BanNativeLoadFn>(GetProcAddress(module, "forgevm_ban_native_load"));
    api->unbanNativeLoad = reinterpret_cast<UnbanNativeLoadFn>(GetProcAddress(module, "forgevm_unban_native_load"));
    api->banProcessCreate   = reinterpret_cast<BanProcessCreateFn>(GetProcAddress(module, "forgevm_ban_process_create"));
    api->unbanProcessCreate = reinterpret_cast<UnbanProcessCreateFn>(GetProcAddress(module, "forgevm_unban_process_create"));
    api->forgeClassPlan   = reinterpret_cast<ForgeClassPlanFn>(GetProcAddress(module, "forgevm_forge_class_plan"));
    api->forgeClassUnload = reinterpret_cast<ForgeClassUnloadFn>(GetProcAddress(module, "forgevm_forge_class_unload"));

    if (api->probe == NULL || api->init == NULL) { *reason = "missing_export"; return false; }
    return true;
}

std::string copyReason(const NativeApi& api, const char* fallback) {
    std::string reason = fallback;
    if (api.lastError != NULL) {
        const char* nativeReason = api.lastError();
        if (nativeReason != NULL && nativeReason[0] != '\0') reason = nativeReason;
    }
    return reason;
}

void handleBootstrap(const NativeApi& api,
                     const std::string& dllPath, const std::string& line) {
    int capability = api.probe ? api.probe() : 0;
    AGENT_LOG("bootstrap: capability=%d (%s)", capability, capFromCode(capability));

    if (capability <= 0) {
        std::string reason = copyReason(api, "permission_probe_failed");
        AGENT_LOG("bootstrap FAILED: %s", reason.c_str());
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
        return;
    }

    int initCode = api.init();
    if (initCode != 1) {
        std::string reason = copyReason(api, "native_init_failed");
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
        return;
    }

    bool structMapReady = false;
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid != 0ULL) {
        g_parentPid.store(static_cast<DWORD>(pid));
    }
    if (pid != 0ULL && api.bootstrapTarget != NULL) {
        AGENT_LOG("bootstrap_target(pid=%llu)...", pid);
        if (api.bootstrapTarget(pid) == 1) {
            structMapReady = true;
            AGENT_LOG("bootstrap_target OK: structMap ready");
        } else {
            std::string reason = copyReason(api, "bootstrap_target_failed");
            AGENT_LOG("bootstrap_target FAILED: %s", reason.c_str());
            printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
            return;
        }
    }

    std::vector<std::pair<std::string, std::string>> fields;
    fields.push_back({"structMapReady", structMapReady ? "true" : "false"});
    if (structMapReady && api.structMapCount != NULL) {
        auto count = api.structMapCount();
        fields.push_back({"structMapEntries", std::to_string(count)});
        AGENT_LOG("structMapEntries=%llu", (unsigned long long)count);
    }
    if (structMapReady && api.typeMapCount != NULL) {
        auto count = api.typeMapCount();
        fields.push_back({"typeMapEntries", std::to_string(count)});
        AGENT_LOG("typeMapEntries=%llu", (unsigned long long)count);
    }
    if (structMapReady && api.compressionInfo != NULL) {
        const char* cinfo = api.compressionInfo();
        if (cinfo != NULL && cinfo[0] != '\0') {
            fields.push_back({"compressionInfo", std::string(cinfo)});
            AGENT_LOG("compressionInfo=%s", cinfo);
        }
    }
    AGENT_LOG("bootstrap complete: %s", capFromCode(capability));
    printResultWithFields("ok", capFromCode(capability), dllPath, "ok", fields);
}

void handleExitJvm(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    unsigned long long pid  = getJsonUnsignedField(line, "pid", 0ULL);
    unsigned long long code = getJsonUnsignedField(line, "code", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_pid");
        return;
    }

    bool ok = false;
    if (api.exitByPid != NULL) {
        ok = api.exitByPid(pid, static_cast<int>(code)) == 1;
    } else {
        HANDLE target = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
        if (target != NULL) {
            ok = TerminateProcess(target, static_cast<UINT>(code)) == TRUE;
            CloseHandle(target);
        }
    }

    if (ok) {
        printResult("ok", "RESTRICTED", dllPath, "exit_sent");
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, "exit_failed");
    }
}

void handleLockAgent(AgentLockState* lockState, const std::string& line, const std::string& dllPath) {
    unsigned long long ttlSec = getJsonUnsignedField(line, "ttlSec", 120ULL);
    if (ttlSec == 0ULL) ttlSec = 1ULL;
    if (ttlSec > 600ULL) ttlSec = 600ULL;
    lockState->locked = true;
    lockState->lockUntilTick = nowTick() + static_cast<ULONGLONG>(ttlSec * 1000ULL);
    printResult("ok", "RESTRICTED", dllPath, "agent_locked");
}

void handleUnlockAgent(AgentLockState* lockState, const std::string& dllPath) {
    lockState->locked = false;
    lockState->lockUntilTick = 0;
    lockState->ownerPid = 0ULL;
    printResult("ok", "RESTRICTED", dllPath, "agent_unlocked");
}

void handleRebindJvm(AgentLockState* lockState, const std::string& line, const std::string& dllPath) {
    refreshLockIfExpired(lockState);
    if (!lockState->locked) {
        printResult("fallback", "UNAVAILABLE", dllPath, "agent_not_locked");
        return;
    }
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_pid");
        return;
    }
    lockState->ownerPid = pid;
    printResult("ok", "RESTRICTED", dllPath, "agent_rebound");
}

void handlePutField(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putField == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_field_not_exported");
        return;
    }
    unsigned long long oop = getJsonUnsignedField(line, "oop", 0ULL);
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_field_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putField(oop, fieldName.c_str(), className.c_str(),
                               valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_field_failed");
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

void handlePutFieldBatch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putFieldBatch == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_field_batch_not_exported");
        return;
    }
    std::vector<unsigned long long> oops = parseJsonUint64Array(line, "oops");
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (oops.empty() || fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_field_batch_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putFieldBatch(oops.data(), static_cast<unsigned long long>(oops.size()),
                                    fieldName.c_str(), className.c_str(),
                                    valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_field_batch_failed");
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

void handlePutRefField(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putRefField == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_ref_field_not_exported");
        return;
    }
    unsigned long long oop = getJsonUnsignedField(line, "oop", 0ULL);
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_ref_field_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putRefField(oop, fieldName.c_str(), className.c_str(),
                                  valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_ref_field_failed");
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

void handlePutRefFieldBatch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putRefFieldBatch == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_ref_field_batch_not_exported");
        return;
    }
    std::vector<unsigned long long> oops = parseJsonUint64Array(line, "oops");
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (oops.empty() || fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_ref_field_batch_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putRefFieldBatch(oops.data(), static_cast<unsigned long long>(oops.size()),
                                       fieldName.c_str(), className.c_str(),
                                       valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_ref_field_batch_failed");
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

// ============================================================
// forge_batch_plan: per-class plan-once-commit-once entry point
// ============================================================

namespace {

struct BatchCandidate {
    std::string methodName;
    std::string paramDesc;
};

struct BatchIngot {
    std::string targetClass;
    bool        includeSubclasses = false;
    std::string injectAt;
    std::string injectTarget;
    std::string hookClass;
    std::string hookMethod;
    std::string hookDesc;
    std::vector<BatchCandidate> candidates;
};

struct PerIngotResult {
    bool        matched = false;
    std::string methodName;
    std::string paramDesc;
    std::string reason;
};

} // namespace

// Parse a forgevm_forge_class_plan results JSON ("[{matched:..,...}, ...]")
// into a vector of PerIngotResult that parallels the input order.
static std::vector<PerIngotResult> parseClassPlanResults(const std::string& json,
                                                        size_t expected) {
    std::vector<PerIngotResult> out;
    out.reserve(expected);
    forEachJsonObject(json, [&out](const std::string& obj) {
        PerIngotResult r;
        r.matched = getJsonBoolField(obj, "matched", false);
        if (r.matched) {
            r.methodName = getJsonStringField(obj, "methodName");
            r.paramDesc  = getJsonStringField(obj, "paramDesc");
        } else {
            r.reason = getJsonStringField(obj, "reason");
            if (r.reason.empty()) r.reason = "match_failed";
        }
        out.push_back(std::move(r));
    });
    return out;
}

void handleForgeBatchPlan(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.forgeClassPlan == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "forge_class_plan_not_exported");
        return;
    }

    std::vector<BatchIngot> ingots;
    {
        std::string ingotsArr = extractArrayInner(line, "ingots");
        forEachJsonObject(ingotsArr, [&ingots](const std::string& obj) {
            BatchIngot spec;
            spec.targetClass        = getJsonStringField(obj, "targetClass");
            spec.includeSubclasses  = getJsonBoolField(obj, "includeSubclasses", false);
            spec.injectAt           = getJsonStringField(obj, "injectAt");
            spec.injectTarget       = getJsonStringField(obj, "injectTarget");
            spec.hookClass          = getJsonStringField(obj, "hookClass");
            spec.hookMethod         = getJsonStringField(obj, "hookMethod");
            spec.hookDesc           = getJsonStringField(obj, "hookDesc");

            std::string candArr = extractArrayInner(obj, "candidates");
            forEachJsonObject(candArr, [&spec](const std::string& cobj) {
                BatchCandidate c;
                c.methodName = getJsonStringField(cobj, "methodName");
                c.paramDesc  = getJsonStringField(cobj, "paramDesc");
                spec.candidates.push_back(std::move(c));
            });
            ingots.push_back(std::move(spec));
        });
    }

    AGENT_LOG("forge_batch_plan: %zu ingot(s)", ingots.size());
    if (ingots.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_ingots");
        return;
    }

    std::vector<PerIngotResult> results(ingots.size());

    if (api.forgeClassPlan != NULL) {
        // §17 Stage 3: group ingots by (targetClass, includeSubclasses) and
        // commit each class as one plan-once-commit-once operation. All
        // commits defer deopt; we run a single global deopt sweep at the end.
        struct GroupKey {
            std::string targetClass;
            bool includeSubclasses;
            bool operator==(const GroupKey& o) const {
                return targetClass == o.targetClass && includeSubclasses == o.includeSubclasses;
            }
        };
        struct GroupKeyHash {
            size_t operator()(const GroupKey& g) const {
                return std::hash<std::string>{}(g.targetClass) ^
                       (g.includeSubclasses ? 0x9E3779B9ULL : 0ULL);
            }
        };
        std::unordered_map<GroupKey, std::vector<size_t>, GroupKeyHash> groups;
        std::vector<GroupKey> groupOrder;
        for (size_t i = 0; i < ingots.size(); ++i) {
            GroupKey k{ ingots[i].targetClass, ingots[i].includeSubclasses };
            auto it = groups.find(k);
            if (it == groups.end()) {
                groups[k] = std::vector<size_t>{ i };
                groupOrder.push_back(k);
            } else {
                it->second.push_back(i);
            }
        }
        AGENT_LOG("forge_batch_plan: %zu group(s) (one DLL call per group)", groupOrder.size());

        for (const GroupKey& gk : groupOrder) {
            const auto& idxs = groups[gk];

            // Build hooksJson for this class.
            std::ostringstream js;
            js << '[';
            for (size_t j = 0; j < idxs.size(); ++j) {
                if (j > 0) js << ',';
                const BatchIngot& sp = ingots[idxs[j]];
                js << '{';
                js << "\"hookClass\":\""  << escapeJson(sp.hookClass)  << "\",";
                js << "\"hookMethod\":\"" << escapeJson(sp.hookMethod) << "\",";
                js << "\"hookDesc\":\""   << escapeJson(sp.hookDesc)   << "\",";
                js << "\"injectAt\":\""   << escapeJson(sp.injectAt)   << "\"";
                if (!sp.injectTarget.empty()) {
                    js << ",\"injectTarget\":\"" << escapeJson(sp.injectTarget) << "\"";
                }
                js << ",\"candidates\":[";
                for (size_t c = 0; c < sp.candidates.size(); ++c) {
                    if (c > 0) js << ',';
                    js << "{\"methodName\":\"" << escapeJson(sp.candidates[c].methodName) << "\","
                       << "\"paramDesc\":\""   << escapeJson(sp.candidates[c].paramDesc)  << "\"}";
                }
                js << "]}";
            }
            js << ']';
            std::string hooksJson = js.str();

            // Generous result buffer: enough for a few hundred per-hook outcomes.
            std::vector<char> resultBuf(64 * 1024, 0);
            int rc = api.forgeClassPlan(gk.targetClass.c_str(),
                                        hooksJson.c_str(),
                                        gk.includeSubclasses ? 1 : 0,
                                        /*deferDeopt=*/1,
                                        resultBuf.data(),
                                        (int)resultBuf.size());

            if (rc != 1) {
                std::string reason = api.lastError ? api.lastError() : "class_plan_failed";
                AGENT_LOG("forge_batch_plan: class %s commit FAILED reason=%s",
                          gk.targetClass.c_str(), reason.c_str());
                for (size_t k : idxs) {
                    PerIngotResult& r = results[k];
                    r.matched = false;
                    r.reason  = reason.empty() ? "class_plan_failed" : reason;
                }
                continue;
            }

            std::vector<PerIngotResult> groupResults =
                parseClassPlanResults(std::string(resultBuf.data()), idxs.size());
            for (size_t j = 0; j < idxs.size() && j < groupResults.size(); ++j) {
                results[idxs[j]] = std::move(groupResults[j]);
            }
            // Defensive: if buffer parse came up short, fill the tail with a generic failure.
            for (size_t j = groupResults.size(); j < idxs.size(); ++j) {
                results[idxs[j]].matched = false;
                results[idxs[j]].reason  = "result_buffer_truncated";
            }
        }

        if (api.forceDeoptNow != NULL) {
            api.forceDeoptNow();
        }
    }

    int matchedCount = 0;
    std::ostringstream oss;
    oss << "{\"status\":\"ok\""
        << ",\"capability\":\"FULL\""
        << ",\"dllPath\":\"" << escapeJson(dllPath) << "\""
        << ",\"reason\":\"batch_plan_done\""
        << ",\"results\":[";
    for (size_t i = 0; i < results.size(); ++i) {
        if (i > 0) oss << ',';
        const auto& r = results[i];
        if (r.matched) ++matchedCount;
        oss << '{';
        oss << "\"matched\":" << (r.matched ? "true" : "false");
        if (r.matched) {
            oss << ",\"methodName\":\"" << escapeJson(r.methodName) << "\"";
            oss << ",\"paramDesc\":\""  << escapeJson(r.paramDesc)  << "\"";
        } else {
            oss << ",\"reason\":\"" << escapeJson(r.reason) << "\"";
        }
        oss << '}';
    }
    oss << "]}";
    std::cout << oss.str() << std::endl;
    AGENT_LOG("forge_batch_plan: %d/%zu matched", matchedCount, (size_t)results.size());
}

void handleForgeClassUnload(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.forgeClassUnload == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unknown_command");
        return;
    }
    std::string targetClass = getJsonStringField(line, "targetClass");
    bool includeSubclasses = getJsonBoolField(line, "includeSubclasses", false);
    if (targetClass.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_target_class");
        return;
    }

    AGENT_LOG("forge_class_unload: %s [subclasses=%d]",
              targetClass.c_str(), (int)includeSubclasses);

    int result = api.forgeClassUnload(targetClass.c_str(), includeSubclasses ? 1 : 0);
    std::string reason = copyReason(api, result == 1 ? "ok" : "forge_class_unload_failed");
    AGENT_LOG("forge_class_unload result=%d reason=%s", result, reason.c_str());

    std::ostringstream oss;
    oss << "{\"status\":\"" << (result == 1 ? "ok" : "fallback") << "\""
        << ",\"capability\":\"" << (result == 1 ? "FULL" : "UNAVAILABLE") << "\""
        << ",\"dllPath\":\"" << escapeJson(dllPath) << "\""
        << ",\"reason\":\"" << escapeJson(reason) << "\"}";
    std::cout << oss.str() << std::endl;
}

void handlePutFieldPath(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putFieldPath == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_field_path_not_exported");
        return;
    }
    std::string className  = getJsonStringField(line, "className");
    std::string fieldChain = getJsonStringField(line, "fieldChain");
    std::string valueHex   = getJsonStringField(line, "valueHex");

    if (className.empty() || fieldChain.empty() || valueHex.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_field_path_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "empty_value_bytes");
        return;
    }

    AGENT_LOG("put_field_path: %s -> %s", className.c_str(), fieldChain.c_str());

    int result = api.putFieldPath(className.c_str(), fieldChain.c_str(),
                                   valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_field_path_failed");
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

std::vector<std::string> parseJsonStringArray(const std::string& line, const std::string& key);

void handlePurgeMatchingAgents(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.purgeAgentsMatching == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "purge_agents_matching_not_exported");
        return;
    }

    /* Parse {mode, patterns} from JSON, same shape as ban_java_agent.
     * Missing/blank mode => filterMode 0 (NONE) = purge ALL loaded agents. */
    std::string mode = getJsonStringField(line, "mode");
    std::vector<std::string> patterns = parseJsonStringArray(line, "patterns");

    std::string modeLower = mode;
    for (char& c : modeLower) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');

    int filterMode = 0;
    if (modeLower == "blacklist" && !patterns.empty()) filterMode = 1;
    else if (modeLower == "whitelist" && !patterns.empty()) filterMode = 2;

    std::vector<const char*> rawPatterns;
    rawPatterns.reserve(patterns.size());
    for (const auto& p : patterns) rawPatterns.push_back(p.c_str());

    AGENT_LOG("purge_matching_agents: mode=%s filterMode=%d patterns=%zu",
              modeLower.c_str(), filterMode, patterns.size());

    int result = api.purgeAgentsMatching(filterMode,
                                          rawPatterns.empty() ? nullptr : rawPatterns.data(),
                                          (int)rawPatterns.size());
    std::string reason = copyReason(api, "ok");
    AGENT_LOG("purge_matching_agents: purged=%d reason=%s", result, reason.c_str());
    /* result is the count of agents purged (may be 0 if filter matched none —
     * not an error condition). */
    printResult("ok", "FULL", dllPath, reason.c_str());
}

void handlePutObjectFieldPath(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putObjectFieldPath == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "put_object_field_path_not_exported");
        return;
    }
    std::string targetClass = getJsonStringField(line, "targetClass");
    std::string targetField = getJsonStringField(line, "targetField");
    std::string sourceClass = getJsonStringField(line, "sourceClass");
    std::string sourceField = getJsonStringField(line, "sourceField");

    if (targetClass.empty() || targetField.empty() || sourceClass.empty() || sourceField.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_put_object_field_path_params");
        return;
    }

    AGENT_LOG("put_object_field_path: %s.%s <- %s.%s",
              targetClass.c_str(), targetField.c_str(),
              sourceClass.c_str(), sourceField.c_str());

    int result = api.putObjectFieldPath(targetClass.c_str(), targetField.c_str(),
                                         sourceClass.c_str(), sourceField.c_str());
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_object_field_path_failed");
    AGENT_LOG("put_object_field_path result=%d reason=%s", result, reason.c_str());
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

// ============================================================
// Load-filter state (Java agent attach + native library load)
//
// Filter storage is Agent-local — enforcement arrives in later steps:
//   step 3: JVM_EnqueueOperation trampoline consults g_javaAgentFilter
//   step 4: ntdll!LdrLoadDll trampoline consults g_nativeLoadFilter
// ============================================================

enum class FilterMode { None, Blacklist, Whitelist };

struct LoadFilter {
    FilterMode mode = FilterMode::None;
    std::vector<std::string> patterns;
    bool active = false;
};

LoadFilter g_javaAgentFilter;
LoadFilter g_nativeLoadFilter;
LoadFilter g_processCreateFilter;
std::mutex g_filterMutex;
std::atomic<bool> g_filterPipeStarted{false};

const char* filterModeName(FilterMode m) {
    switch (m) {
        case FilterMode::None:      return "none";
        case FilterMode::Blacklist: return "blacklist";
        case FilterMode::Whitelist: return "whitelist";
    }
    return "unknown";
}

std::vector<std::string> parseJsonStringArray(const std::string& line, const std::string& key) {
    std::vector<std::string> result;
    std::string header = "\"" + key + "\":[";
    size_t start = line.find(header);
    if (start == std::string::npos) return result;
    size_t i = start + header.size();

    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == ',')) i++;
        if (i >= line.size() || line[i] == ']') break;
        if (line[i] != '"') break;
        i++;

        std::string value;
        bool escaped = false;
        while (i < line.size()) {
            char c = line[i];
            if (escaped) {
                switch (c) {
                    case 'n':  value += '\n'; break;
                    case 'r':  value += '\r'; break;
                    case 't':  value += '\t'; break;
                    case '"':  value += '"';  break;
                    case '\\': value += '\\'; break;
                    default:   value += c;    break;
                }
                escaped = false;
                i++;
                continue;
            }
            if (c == '\\') { escaped = true; i++; continue; }
            if (c == '"') break;
            value += c;
            i++;
        }
        if (i < line.size() && line[i] == '"') {
            result.push_back(value);
            i++;
        } else {
            break;
        }
    }
    return result;
}

void applyFilterFromJson(LoadFilter* filter, const std::string& line) {
    std::string mode = getJsonStringField(line, "mode");
    std::vector<std::string> patterns = parseJsonStringArray(line, "patterns");

    // Normalize to lowercase for comparison
    std::string modeLower = mode;
    for (char& c : modeLower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }

    if (modeLower == "blacklist" && !patterns.empty()) {
        filter->mode = FilterMode::Blacklist;
        filter->patterns = std::move(patterns);
    } else if (modeLower == "whitelist" && !patterns.empty()) {
        filter->mode = FilterMode::Whitelist;
        filter->patterns = std::move(patterns);
    } else {
        filter->mode = FilterMode::None;
        filter->patterns.clear();
    }
    filter->active = true;
}

// Case-insensitive glob match: '*' any run, '?' single char. '\\' and '/' are equivalent.
bool globMatch(const std::string& pattern, const std::string& text) {
    auto norm = [](unsigned char c) -> unsigned char {
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        if (c == '\\') c = '/';
        return c;
    };
    size_t pi = 0, ti = 0;
    size_t starPi = std::string::npos, starTi = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && pattern[pi] == '*') {
            starPi = pi++;
            starTi = ti;
        } else if (pi < pattern.size() &&
                   (pattern[pi] == '?' ||
                    norm((unsigned char)pattern[pi]) == norm((unsigned char)text[ti]))) {
            pi++;
            ti++;
        } else if (starPi != std::string::npos) {
            pi = starPi + 1;
            ti = ++starTi;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') pi++;
    return pi == pattern.size();
}

// true = allow the load, false = block it.
// Semantics:
//   filter inactive           → allow (ForgeVM never installed a filter)
//   active + mode==None       → block everything (global ban, no patterns)
//   active + Blacklist+match  → block; otherwise allow
//   active + Whitelist+match  → allow; otherwise block
bool filterAllows(const LoadFilter& f, const std::string& path) {
    if (!f.active) return true;
    if (f.mode == FilterMode::None) return false;
    bool matched = false;
    for (const auto& pat : f.patterns) {
        if (globMatch(pat, path)) { matched = true; break; }
    }
    return (f.mode == FilterMode::Blacklist) ? !matched : matched;
}

// ============================================================
// Named-pipe server: trampolines in the target JVM connect here
// to ask "is this path allowed?" before calling the real JVM entry.
//
// Protocol (one request per connection, blocking):
//   request : <kind:1 byte 'A'|'N'|'P'> <path:UTF-8 bytes> <0x0A>
//   reply   : <decision:1 byte '1'=allow | '0'=block>
//
// 'A' queries g_javaAgentFilter, 'N' queries g_nativeLoadFilter,
// 'P' queries g_processCreateFilter.
// Pipe name: \\.\pipe\forgevm_<jvm_pid>_filter
// ============================================================

DWORD WINAPI filterPipeHandlerThread(LPVOID param) {
    HANDLE pipe = (HANDLE)param;
    std::string buf;
    buf.reserve(512);

    // Read until newline (or pipe close / limit hit).
    const size_t kMaxRequest = 4 * 1024;
    char chunk[256];
    bool haveLine = false;
    while (buf.size() < kMaxRequest) {
        DWORD got = 0;
        BOOL ok = ReadFile(pipe, chunk, sizeof(chunk), &got, NULL);
        if (!ok || got == 0) break;
        for (DWORD i = 0; i < got; i++) {
            if (chunk[i] == '\n') {
                buf.append(chunk, chunk + i);
                haveLine = true;
                break;
            }
        }
        if (haveLine) break;
        buf.append(chunk, chunk + got);
    }

    char decision = '1'; // default allow on malformed input — fail-open keeps JVM healthy
    if (haveLine && !buf.empty()) {
        char kind = buf[0];
        std::string path = buf.substr(1);
        bool allow = true;
        {
            std::lock_guard<std::mutex> g(g_filterMutex);
            if (kind == 'A') {
                allow = filterAllows(g_javaAgentFilter, path);
            } else if (kind == 'N') {
                allow = filterAllows(g_nativeLoadFilter, path);
            } else if (kind == 'P') {
                allow = filterAllows(g_processCreateFilter, path);
            }
        }
        decision = allow ? '1' : '0';
        AGENT_LOG("filter query kind=%c path=%s -> %s",
                  kind, path.c_str(), allow ? "ALLOW" : "BLOCK");
    } else {
        AGENT_LOG("filter query malformed (len=%zu haveLine=%d)", buf.size(), (int)haveLine);
    }

    DWORD wrote = 0;
    WriteFile(pipe, &decision, 1, &wrote, NULL);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

struct FilterPipeStartup {
    HANDLE firstPipe;
    std::string pipeName;
};

DWORD WINAPI filterPipeAcceptLoopThread(LPVOID param) {
    auto* startup = static_cast<FilterPipeStartup*>(param);
    std::string pipeName = startup->pipeName;
    HANDLE pipe = startup->firstPipe;
    delete startup;
    AGENT_LOG("filter pipe accept loop: %s", pipeName.c_str());

    for (;;) {
        if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
            pipe = CreateNamedPipeA(
                pipeName.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                /*outBuf*/ 512, /*inBuf*/ 4096,
                /*defaultTimeout*/ 0,
                /*sa*/ NULL);
            if (pipe == INVALID_HANDLE_VALUE) {
                AGENT_LOG("CreateNamedPipe failed: %lu", GetLastError());
                pipe = NULL;
                Sleep(200);
                continue;
            }
        }
        BOOL connected = ConnectNamedPipe(pipe, NULL)
                             ? TRUE
                             : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(pipe);
            pipe = NULL;
            continue;
        }
        HANDLE th = CreateThread(NULL, 0, filterPipeHandlerThread, pipe, 0, NULL);
        if (th == NULL) {
            AGENT_LOG("filter handler thread create failed: %lu", GetLastError());
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            pipe = NULL;
            continue;
        }
        CloseHandle(th);
        pipe = NULL;  // handler thread owns it; next iteration creates another instance
    }
    return 0;
}

std::string g_filterPipeName;

/* Handoff command pipe — \\.\pipe\forgevm_cmd_<agent_pid>. Created at agent
 * startup. After old JVM dies (stdin EOF), main() waits on this pipe for the
 * new JVM's ForgeVM.launch() to connect, then redirects stdin/stdout to the
 * pipe and re-enters the command loop. */
static HANDLE g_commandPipeServer = INVALID_HANDLE_VALUE;
static std::string g_commandPipeName;

static std::string buildCommandPipeName() {
    char buf[64];
    sprintf_s(buf, sizeof(buf), "\\\\.\\pipe\\forgevm_cmd_%lu",
              (unsigned long)GetCurrentProcessId());
    return std::string(buf);
}

/* Idempotent: creates the first instance of the command pipe and stashes it
 * in g_commandPipeServer. Returns true on success. Subsequent calls re-use
 * the existing server pipe handle. */
static bool ensureCommandPipeCreated() {
    if (g_commandPipeServer != INVALID_HANDLE_VALUE) return true;
    g_commandPipeName = buildCommandPipeName();
    HANDLE pipe = CreateNamedPipeA(
        g_commandPipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        /*maxInstances*/ 1,
        /*outBuf*/ 4096, /*inBuf*/ 4096,
        /*defaultTimeout*/ 0,
        /*sa*/ NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        AGENT_LOG("ensureCommandPipeCreated: CreateNamedPipe failed: %lu", GetLastError());
        return false;
    }
    g_commandPipeServer = pipe;
    AGENT_LOG("command pipe ready: %s", g_commandPipeName.c_str());
    return true;
}

/* Block until a client connects to the command pipe, OR the given liveness
 * handle signals (the relaunched JVM exited before connecting). Returns the
 * connected pipe handle on success (caller takes ownership; the server pipe
 * instance is consumed for this client and must be recreated for further
 * clients), or NULL on JVM death / connect failure.
 *
 * The blocking ConnectNamedPipe is offloaded to a worker thread so the caller
 * can wait on both its completion and the JVM handle; if the JVM dies first
 * the worker's pending synchronous I/O is cancelled. The pipe stays in
 * synchronous mode throughout so the post-handoff stdio redirection keeps
 * working. hJvmLiveness may be NULL, degrading to an unbounded client wait. */
static HANDLE acceptCommandPipeClient(HANDLE hJvmLiveness) {
    if (!ensureCommandPipeCreated()) return NULL;
    HANDLE pipe = g_commandPipeServer;

    struct ConnCtx {
        HANDLE pipe;
        HANDLE done;
        BOOL   ok;
    } ctx{ pipe, CreateEventA(NULL, TRUE, FALSE, NULL), FALSE };

    if (ctx.done == NULL) {
        /* No event to coordinate on — fall back to a plain blocking connect. */
        BOOL connected = ConnectNamedPipe(pipe, NULL)
                             ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(pipe);
            g_commandPipeServer = INVALID_HANDLE_VALUE;
            return NULL;
        }
        g_commandPipeServer = INVALID_HANDLE_VALUE;
        return pipe;
    }

    HANDLE worker = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
        auto* c = static_cast<ConnCtx*>(p);
        c->ok = ConnectNamedPipe(c->pipe, NULL)
                    ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        SetEvent(c->done);
        return 0;
    }, &ctx, 0, NULL);

    if (worker == NULL) {
        CloseHandle(ctx.done);
        CloseHandle(pipe);
        g_commandPipeServer = INVALID_HANDLE_VALUE;
        return NULL;
    }

    /* Wake on any of: client connected, new JVM exited, watcher gave up. */
    HANDLE abortEvent = g_relaunchAbortEvent.load();
    HANDLE waits[3];
    DWORD  count = 0;
    waits[count++] = ctx.done;
    if (hJvmLiveness != NULL) waits[count++] = hJvmLiveness;
    if (abortEvent != NULL)   waits[count++] = abortEvent;
    DWORD w         = WaitForMultipleObjects(count, waits, FALSE, INFINITE);
    bool  connected = (w == WAIT_OBJECT_0);

    if (connected) {
        WaitForSingleObject(worker, INFINITE);
    } else {
        AGENT_LOG("acceptCommandPipeClient: new JVM exited or watcher signalled failure before handoff — aborting");
        /* CancelSynchronousIo races the worker entering its blocking call: if
         * fired too early it's a no-op and the worker would then block forever.
         * Retry until the worker actually unblocks and exits. */
        while (WaitForSingleObject(worker, 50) == WAIT_TIMEOUT) {
            CancelSynchronousIo(worker);
        }
    }
    /* Worker has exited and no longer references the pipe. */
    CloseHandle(worker);
    CloseHandle(ctx.done);

    HANDLE result = NULL;
    if (connected && ctx.ok) {
        result = pipe;
    } else {
        CloseHandle(pipe);
    }
    g_commandPipeServer = INVALID_HANDLE_VALUE;
    return result;
}

/* Replace the process's stdin/stdout file descriptors with the given pipe
 * handle so that std::cin / std::cout / printResult all transparently use
 * the pipe. Clears EOF/error state on the C++ streams. */
static bool redirectStdioToPipe(HANDLE pipe) {
    int pipeFd = _open_osfhandle(reinterpret_cast<intptr_t>(pipe), _O_BINARY);
    if (pipeFd == -1) {
        AGENT_LOG("redirectStdioToPipe: _open_osfhandle failed");
        return false;
    }
    if (_dup2(pipeFd, _fileno(stdin)) != 0) {
        AGENT_LOG("redirectStdioToPipe: _dup2(stdin) failed");
        _close(pipeFd);
        return false;
    }
    if (_dup2(pipeFd, _fileno(stdout)) != 0) {
        AGENT_LOG("redirectStdioToPipe: _dup2(stdout) failed");
        _close(pipeFd);
        return false;
    }
    /* pipeFd is no longer needed — fd 0 and fd 1 hold their own refs to the
     * underlying handle now. Closing pipeFd does not invalidate them. */
    _close(pipeFd);
    /* Disable C buffering so each response line is flushed immediately. */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    /* Clear stream error/EOF state — the old underlying fd hit EOF when the
     * old JVM died; reset so getline / cout resume working on the new fd. */
    std::cin.clear();
    std::cout.clear();
    return true;
}

// Start the filter pipe server (idempotent). Synchronously creates the
// first pipe instance before spawning the accept thread so that the
// trampoline's CreateFileA can never race the server's first listen.
// Returns the pipe name on success, or an empty string if start failed.
std::string ensureFilterPipeStarted() {
    if (g_filterPipeStarted.load()) {
        return g_filterPipeName;
    }
    bool expected = false;
    if (!g_filterPipeStarted.compare_exchange_strong(expected, true)) {
        return g_filterPipeName;
    }

    DWORD pid = g_parentPid.load();
    if (pid == 0) {
        AGENT_LOG("ensureFilterPipeStarted: parent pid unknown");
        g_filterPipeStarted.store(false);
        return "";
    }

    char buf[64];
    sprintf_s(buf, sizeof(buf), "\\\\.\\pipe\\forgevm_%lu_filter", (unsigned long)pid);
    std::string name(buf);

    HANDLE firstPipe = CreateNamedPipeA(
        name.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        /*outBuf*/ 512, /*inBuf*/ 4096,
        /*defaultTimeout*/ 0,
        /*sa*/ NULL);
    if (firstPipe == INVALID_HANDLE_VALUE) {
        AGENT_LOG("first CreateNamedPipe failed: %lu", GetLastError());
        g_filterPipeStarted.store(false);
        return "";
    }

    auto* startup = new FilterPipeStartup{firstPipe, name};
    HANDLE th = CreateThread(NULL, 0, filterPipeAcceptLoopThread, startup, 0, NULL);
    if (th == NULL) {
        AGENT_LOG("filter accept thread create failed: %lu", GetLastError());
        CloseHandle(firstPipe);
        delete startup;
        g_filterPipeStarted.store(false);
        return "";
    }
    CloseHandle(th);

    g_filterPipeName = name;
    return name;
}

void handleBanJavaAgent(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_javaAgentFilter.active;
        applyFilterFromJson(&g_javaAgentFilter, line);
        AGENT_LOG("ban_java_agent: mode=%s patterns=%zu%s",
                  filterModeName(g_javaAgentFilter.mode),
                  g_javaAgentFilter.patterns.size(),
                  wasActive ? " (updated)" : "");
    }
    std::string pipeName = ensureFilterPipeStarted();
    if (pipeName.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "filter_pipe_start_failed");
        return;
    }
    // Trampoline already installed; new filter takes effect on next attach
    // via the pipe — no need to re-patch jvm.dll.
    if (wasActive) {
        printResult("ok", "FULL", dllPath, "filter_updated");
        return;
    }
    if (api.banJavaAgent == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_java_agent_not_exported");
        return;
    }
    int r = api.banJavaAgent(pipeName.c_str());
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanJavaAgent(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_javaAgentFilter.active;
        g_javaAgentFilter = LoadFilter{};
    }
    AGENT_LOG("unban_java_agent: filter cleared (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanJavaAgent == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_java_agent_not_exported");
        return;
    }
    int r = api.unbanJavaAgent();
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleBanNativeLoad(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_nativeLoadFilter.active;
        applyFilterFromJson(&g_nativeLoadFilter, line);
        AGENT_LOG("ban_native_load: mode=%s patterns=%zu%s",
                  filterModeName(g_nativeLoadFilter.mode),
                  g_nativeLoadFilter.patterns.size(),
                  wasActive ? " (updated)" : "");
    }
    std::string pipeName = ensureFilterPipeStarted();
    if (pipeName.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "filter_pipe_start_failed");
        return;
    }
    if (wasActive) {
        printResult("ok", "FULL", dllPath, "filter_updated");
        return;
    }
    if (api.banNativeLoad == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_native_load_not_exported");
        return;
    }
    int r = api.banNativeLoad(pipeName.c_str());
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanNativeLoad(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_nativeLoadFilter.active;
        g_nativeLoadFilter = LoadFilter{};
    }
    AGENT_LOG("unban_native_load: filter cleared (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanNativeLoad == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_native_load_not_exported");
        return;
    }
    int r = api.unbanNativeLoad();
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleBanProcessCreate(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_processCreateFilter.active;
        applyFilterFromJson(&g_processCreateFilter, line);
        AGENT_LOG("ban_process_create: mode=%s patterns=%zu%s",
                  filterModeName(g_processCreateFilter.mode),
                  g_processCreateFilter.patterns.size(),
                  wasActive ? " (updated)" : "");
    }
    std::string pipeName = ensureFilterPipeStarted();
    if (pipeName.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "filter_pipe_start_failed");
        return;
    }
    if (wasActive) {
        printResult("ok", "FULL", dllPath, "filter_updated");
        return;
    }
    if (api.banProcessCreate == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_process_create_not_exported");
        return;
    }
    int r = api.banProcessCreate(pipeName.c_str());
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanProcessCreate(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_processCreateFilter.active;
        g_processCreateFilter = LoadFilter{};
    }
    AGENT_LOG("unban_process_create: filter cleared (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanProcessCreate == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_process_create_not_exported");
        return;
    }
    int r = api.unbanProcessCreate();
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

// ============================================================
// relaunch: WMI cmdline query → filter → TerminateProcess + CreateProcessW
// ============================================================

static std::wstring queryProcessCommandLine(DWORD pid) {
    std::wstring result;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool needUninit = (hr == S_OK || hr == S_FALSE);

    do {
        IWbemLocator* pLoc = NULL;
        hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
        if (FAILED(hr)) break;

        IWbemServices* pSvc = NULL;
        BSTR ns = SysAllocString(L"ROOT\\CIMV2");
        hr = pLoc->ConnectServer(ns, NULL, NULL, 0, 0, NULL, NULL, &pSvc);
        SysFreeString(ns);
        pLoc->Release();
        if (FAILED(hr)) break;

        hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                               RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL, EOAC_NONE);
        if (FAILED(hr)) { pSvc->Release(); break; }

        wchar_t queryBuf[128];
        swprintf_s(queryBuf, ARRAYSIZE(queryBuf),
                   L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = %u",
                   static_cast<unsigned>(pid));

        BSTR lang  = SysAllocString(L"WQL");
        BSTR query = SysAllocString(queryBuf);
        IEnumWbemClassObject* pEnum = NULL;
        hr = pSvc->ExecQuery(lang, query,
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                             NULL, &pEnum);
        SysFreeString(lang);
        SysFreeString(query);
        pSvc->Release();
        if (FAILED(hr) || pEnum == NULL) break;

        IWbemClassObject* pObj = NULL;
        ULONG got = 0;
        hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &got);
        pEnum->Release();
        if (FAILED(hr) || got == 0 || pObj == NULL) break;

        VARIANT var;
        VariantInit(&var);
        if (SUCCEEDED(pObj->Get(L"CommandLine", 0, &var, NULL, NULL))
                && var.vt == VT_BSTR && var.bstrVal != NULL) {
            result = std::wstring(var.bstrVal);
        }
        VariantClear(&var);
        pObj->Release();
    } while (false);

    if (needUninit) CoUninitialize();
    return result;
}

static std::vector<std::wstring> tokenizeCmdLine(const std::wstring& cmdline) {
    std::vector<std::wstring> tokens;
    size_t i = 0, n = cmdline.size();
    while (i < n) {
        while (i < n && cmdline[i] == L' ') i++;
        if (i >= n) break;
        std::wstring tok;
        bool inQuote = false;
        while (i < n) {
            wchar_t c = cmdline[i];
            if (c == L'"') { inQuote = !inQuote; i++; continue; }
            if (!inQuote && c == L' ') break;
            tok += c;
            i++;
        }
        if (!tok.empty()) tokens.push_back(tok);
    }
    return tokens;
}

static std::wstring quoteIfNeeded(const std::wstring& token) {
    if (token.find(L' ') == std::wstring::npos) return token;
    return L"\"" + token + L"\"";
}

/* True for the -D properties this agent injects into a relaunched JVM. On a
 * chained relaunch the source command line already carries last generation's
 * copies; they must be stripped before fresh ones are prepended, otherwise the
 * stale (later-positioned, hence overriding) tokens would win — e.g. the new
 * JVM would inherit the previous generation's agent.pid and hand off to a dead
 * agent. */
static bool isForgevmRelaunchInjectedToken(const std::wstring& tok) {
    static const wchar_t* const kPrefixes[] = {
        L"-Dforgevm.agent.pid=",
        L"-Dforgevm.relaunch.gen=",
        /* Legacy props from earlier agent revisions — strip on the way through
         * so chained relaunches against an older-built source JVM don't carry
         * forward stale or unrecognised state. */
        L"-Dforgevm.relaunched=",
        L"-Dforgevm.relaunch.remaining=",
    };
    for (const wchar_t* p : kPrefixes) {
        size_t len = wcslen(p);
        if (tok.size() >= len && tok.compare(0, len, p) == 0) return true;
    }
    return false;
}

static bool relaunchShouldKeepToken(const std::wstring& token,
                                     bool hasAgentFilter, const LoadFilter& agentFlt,
                                     bool hasNativeFilter, const LoadFilter& nativeFlt) {
    static const wchar_t kAgentPfx[]  = L"-javaagent:";
    static const wchar_t kNativePfx[] = L"-agentpath:";
    static const size_t  kPfxLen = 11; // both prefixes are 11 chars

    auto extractPath = [](const std::wstring& tok, size_t prefixLen) -> std::string {
        std::wstring pathW = tok.substr(prefixLen);
        size_t eq = pathW.find(L'=');
        if (eq != std::wstring::npos) pathW = pathW.substr(0, eq);
        return wideToUtf8(pathW);
    };

    if (token.size() > kPfxLen && token.compare(0, kPfxLen, kAgentPfx, kPfxLen) == 0) {
        if (!hasAgentFilter) return true;
        return filterAllows(agentFlt, extractPath(token, kPfxLen));
    }
    if (token.size() > kPfxLen && token.compare(0, kPfxLen, kNativePfx, kPfxLen) == 0) {
        if (!hasNativeFilter) return true;
        return filterAllows(nativeFlt, extractPath(token, kPfxLen));
    }
    return true;
}

void handleRelaunch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_pid");
        return;
    }

    bool hasAgentFilter   = getJsonBoolField(line, "hasAgentFilter",   false);
    bool hasNativeFilter  = getJsonBoolField(line, "hasNativeFilter",  false);
    bool hasProcessFilter = getJsonBoolField(line, "hasProcessFilter", false);

    LoadFilter agentFlt, nativeFlt, processFlt;

    auto buildFilter = [&](LoadFilter& f, const char* modeKey, const char* patsKey) {
        std::string mode = getJsonStringField(line, modeKey);
        std::vector<std::string> pats = parseJsonStringArray(line, patsKey);
        for (char& c : mode) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (mode == "blacklist") {
            f.mode = FilterMode::Blacklist;
            f.patterns = std::move(pats);
        } else if (mode == "whitelist") {
            f.mode = FilterMode::Whitelist;
            f.patterns = std::move(pats);
        } else {
            f.mode = FilterMode::None;
        }
        f.active = true;
    };

    if (hasAgentFilter)   buildFilter(agentFlt,   "agentMode",   "agentPatterns");
    if (hasNativeFilter)  buildFilter(nativeFlt,  "nativeMode",  "nativePatterns");
    if (hasProcessFilter) buildFilter(processFlt, "processMode", "processPatterns");

    /* Snapshot pre-relaunch ban state. Trampolines in the old JVM die with it,
     * so the new JVM needs fresh installs whenever a ban was active OR the
     * caller passed a new filter. Without this, relaunch() with no filter
     * args silently drops active protection that was installed before the call. */
    bool wasAgentBanActive, wasNativeBanActive, wasProcessBanActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasAgentBanActive   = g_javaAgentFilter.active;
        wasNativeBanActive  = g_nativeLoadFilter.active;
        wasProcessBanActive = g_processCreateFilter.active;
    }
    bool installNativeBan  = hasNativeFilter  || wasNativeBanActive;
    bool installAgentBan   = hasAgentFilter   || wasAgentBanActive;
    bool installProcessBan = hasProcessFilter || wasProcessBanActive;

    AGENT_LOG("relaunch: pid=%llu hasAgentFilter=%d hasNativeFilter=%d hasProcessFilter=%d "
              "wasAgentActive=%d wasNativeActive=%d wasProcessActive=%d",
              pid, (int)hasAgentFilter, (int)hasNativeFilter, (int)hasProcessFilter,
              (int)wasAgentBanActive, (int)wasNativeBanActive, (int)wasProcessBanActive);

    std::wstring cmdLine = queryProcessCommandLine(static_cast<DWORD>(pid));
    if (cmdLine.empty()) {
        AGENT_LOG("relaunch: WMI cmdline empty");
        printResult("fallback", "UNAVAILABLE", dllPath, "wmi_cmdline_empty");
        return;
    }
    AGENT_LOG("relaunch: cmdline len=%zu", cmdLine.size());

    std::vector<std::wstring> tokens = tokenizeCmdLine(cmdLine);
    if (tokens.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "cmdline_parse_failed");
        return;
    }

    std::vector<std::wstring> newTokens;
    newTokens.push_back(tokens[0]);
    {
        /* Inject handoff token so the new JVM's ForgeVM.launch() connects to
         * the persistent agent via named pipe instead of spawning a new agent. */
        wchar_t buf[64];
        swprintf_s(buf, ARRAYSIZE(buf), L"-Dforgevm.agent.pid=%lu",
                   (unsigned long)GetCurrentProcessId());
        newTokens.push_back(buf);
    }
    {
        /* Carry the monotonic relaunch-generation counter forward; Java side
         * exposes this via ForgeVM.relaunchGeneration() so callers can decide
         * for themselves when to stop relaunching. */
        unsigned long long nextGen = getJsonUnsignedField(line, "nextGen", 1ULL);
        wchar_t gbuf[64];
        swprintf_s(gbuf, ARRAYSIZE(gbuf), L"-Dforgevm.relaunch.gen=%llu", nextGen);
        newTokens.push_back(gbuf);
        AGENT_LOG("relaunch: next-gen relaunch generation=%llu", nextGen);
    }
    for (size_t i = 1; i < tokens.size(); i++) {
        if (isForgevmRelaunchInjectedToken(tokens[i])) {
            /* Drop last generation's self-injected props; fresh ones above win. */
            continue;
        }
        if (relaunchShouldKeepToken(tokens[i], hasAgentFilter, agentFlt, hasNativeFilter, nativeFlt)) {
            newTokens.push_back(tokens[i]);
        } else {
            AGENT_LOG("relaunch: stripped: %s", wideToUtf8(tokens[i]).c_str());
        }
    }

    std::wstring newCmdLine;
    for (size_t i = 0; i < newTokens.size(); i++) {
        if (i > 0) newCmdLine += L' ';
        newCmdLine += quoteIfNeeded(newTokens[i]);
    }

    HANDLE hJvm = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (hJvm == NULL) {
        AGENT_LOG("relaunch: OpenProcess failed: %lu", GetLastError());
        printResult("fallback", "UNAVAILABLE", dllPath, "open_process_failed");
        return;
    }

    /* Disable the parent watchdog so it doesn't ExitProcess on us when we kill the
     * old JVM. We re-arm it on the new JVM after CREATE_SUSPENDED succeeds. */
    g_parentPid.store(0);

    /* Create new JVM SUSPENDED so we can patch ntdll!LdrLoadDll into its memory
     * before any user-mode instruction runs. This gives banNativeLoad protection
     * from the very first instruction of the new JVM's lifetime. banJavaAgent
     * cannot be installed yet (jvm.dll isn't mapped); a watcher thread below
     * polls for jvm.dll and installs it the moment the load completes. */
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdLineBuf(newCmdLine.begin(), newCmdLine.end());
    cmdLineBuf.push_back(L'\0');

    BOOL created = CreateProcessW(NULL, cmdLineBuf.data(), NULL, NULL,
                                  FALSE,
                                  CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                  NULL, NULL, &si, &pi);
    if (!created) {
        AGENT_LOG("relaunch: CreateProcessW failed: %lu", GetLastError());
        CloseHandle(hJvm);
        g_parentPid.store(static_cast<DWORD>(pid));
        printResult("fallback", "UNAVAILABLE", dllPath, "create_process_failed");
        return;
    }
    AGENT_LOG("relaunch: new process created suspended pid=%lu", pi.dwProcessId);

    /* Bump parent pid so the filter pipe name (derived from g_parentPid)
     * corresponds to the new JVM identity. */
    g_parentPid.store(pi.dwProcessId);

    /* Publish a private liveness handle for the handoff wait. The watcher owns
     * and closes pi.hProcess independently, so duplicate rather than share. */
    {
        HANDLE dup = NULL;
        if (DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(),
                            &dup, SYNCHRONIZE, FALSE, 0)) {
            HANDLE prev = g_relaunchNewJvm.exchange(dup);
            if (prev != NULL) CloseHandle(prev);
        }
    }

    /* Stash filters so the trampolines serve the right rules once installed.
     * Only overwrite when the caller passed a new filter — otherwise keep the
     * pre-relaunch state so carried-over bans retain their patterns.
     *
     * The ntdll hooks (LdrLoadDll / NtCreateUserProcess) are deliberately NOT
     * installed on the suspended new JVM. Installing them here makes them fire
     * during the new JVM's own loader bootstrap — under the loader lock, before
     * the core system DLLs are ready — where the trampoline's synchronous filter
     * round-trip hangs or kills the JVM before jvm.dll ever loads. Instead the
     * post-resume watcher installs all three hooks the instant jvm.dll appears:
     * by then the loader is fully functional and only post-bootstrap loads (the
     * actual threat surface) are filtered. The bootstrap window carries no
     * adversary code, so nothing protectable is lost. */
    if (hasNativeFilter) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_nativeLoadFilter = nativeFlt;
    }
    if (hasProcessFilter) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_processCreateFilter = processFlt;
    }
    if (hasAgentFilter) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_javaAgentFilter = agentFlt;
    }

    /* Resume new JVM. ntdll hooks are installed later by the watcher once the
     * loader bootstrap is past (jvm.dll loaded), not here — see the stash note. */
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    AGENT_LOG("relaunch: new JVM resumed pid=%lu (ntdll hooks deferred to post-resume watcher)",
              pi.dwProcessId);

    /* Spawn watcher thread: polls EnumProcessModules until jvm.dll appears in
     * the new JVM, then full-bootstraps and installs all requested hooks. */
    /* (Re)arm the watcher-failure abort event for this handoff. */
    HANDLE abortEvent = g_relaunchAbortEvent.load();
    if (abortEvent == NULL) {
        abortEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        g_relaunchAbortEvent.store(abortEvent);
    } else {
        ResetEvent(abortEvent);
    }

    struct RelaunchPostResumeCtx {
        HANDLE hNewJvm;
        DWORD newPid;
        bool installAgentBan;
        bool installNativeBan;
        bool installProcessBan;
        const NativeApi* api;
        std::string dllPath;
        HANDLE abortEvent;
    };
    auto* ctx = new RelaunchPostResumeCtx{
        pi.hProcess, pi.dwProcessId, installAgentBan, installNativeBan, installProcessBan, &api, dllPath, abortEvent
    };
    HANDLE watcher = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
        auto* c = static_cast<RelaunchPostResumeCtx*>(p);
        HANDLE h = c->hNewJvm;
        DWORD newPid = c->newPid;
        bool installAgentBan = c->installAgentBan;
        bool installNativeBan = c->installNativeBan;
        bool installProcessBan = c->installProcessBan;
        const NativeApi* api = c->api;
        HANDLE abortEvent = c->abortEvent;
        delete c;

        /* Poll for jvm.dll. Cap at 30s — JVM startup completes well within. */
        const int kMaxAttempts = 600;
        bool found = false;
        for (int i = 0; i < kMaxAttempts; i++) {
            HMODULE mods[256];
            DWORD needed = 0;
            if (EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
                size_t count = needed / sizeof(HMODULE);
                if (count > 256) count = 256;
                for (size_t m = 0; m < count; m++) {
                    wchar_t name[MAX_PATH];
                    if (GetModuleBaseNameW(h, mods[m], name, MAX_PATH) > 0) {
                        std::wstring nameLower(name);
                        for (auto& ch : nameLower) ch = (wchar_t)towlower(ch);
                        if (nameLower == L"jvm.dll") { found = true; break; }
                    }
                }
            }
            if (found) break;
            Sleep(50);
        }

        if (!found) {
            AGENT_LOG("post-relaunch watcher: jvm.dll never appeared in new JVM pid=%lu", newPid);
            if (abortEvent != NULL) SetEvent(abortEvent);
            CloseHandle(h);
            return 0;
        }
        AGENT_LOG("post-relaunch watcher: jvm.dll detected in new JVM pid=%lu", newPid);

        if (api->bootstrapTarget != NULL) {
            if (api->bootstrapTarget(static_cast<unsigned long long>(newPid)) == 1) {
                AGENT_LOG("post-relaunch watcher: bootstrap_target(%lu) ok", newPid);
                std::string filterPipeName;
                if (installAgentBan || installNativeBan || installProcessBan) {
                    filterPipeName = ensureFilterPipeStarted();
                    if (filterPipeName.empty()) {
                        AGENT_LOG("post-relaunch watcher: filter pipe unavailable, hooks skipped");
                    }
                }
                if (!filterPipeName.empty()) {
                    if (installAgentBan && api->banJavaAgent != NULL) {
                        int r = api->banJavaAgent(filterPipeName.c_str());
                        AGENT_LOG("post-relaunch watcher: banJavaAgent r=%d reason=%s",
                                  r, api->lastError ? api->lastError() : "");
                    }
                    if (installNativeBan && api->banNativeLoad != NULL) {
                        int r = api->banNativeLoad(filterPipeName.c_str());
                        AGENT_LOG("post-relaunch watcher: banNativeLoad r=%d reason=%s",
                                  r, api->lastError ? api->lastError() : "");
                    }
                    if (installProcessBan && api->banProcessCreate != NULL) {
                        int r = api->banProcessCreate(filterPipeName.c_str());
                        AGENT_LOG("post-relaunch watcher: banProcessCreate r=%d reason=%s",
                                  r, api->lastError ? api->lastError() : "");
                    }
                }
            } else {
                AGENT_LOG("post-relaunch watcher: bootstrap_target(%lu) failed: %s",
                          newPid, api->lastError ? api->lastError() : "unknown");
            }
        }
        CloseHandle(h);
        return 0;
    }, ctx, 0, NULL);
    if (watcher != NULL) CloseHandle(watcher);

    /* Mark agent for post-EOF persistence — once we kill old JVM, our stdin
     * (inherited from old JVM) will EOF and the main read loop will fall out;
     * the persistence flag tells main() to block instead of exiting. */
    g_persistAfterEOF.store(true);

    /* Acknowledge to caller BEFORE killing old JVM. Old JVM's Java thread is
     * blocked on Thread.sleep(Long.MAX_VALUE) after receiving this ok. */
    printResult("ok", "FULL", dllPath, "relaunch_pending");
    std::cout.flush();
    Sleep(50);

    /* Kill old JVM. Agent does NOT exit — it continues serving the filter pipe
     * so the ntdll hook in the new JVM has a live decision endpoint. The new
     * JVM's ForgeVM.launch() will reconnect via a handoff command pipe — Java
     * side support for that arrives in a follow-up change. */
    TerminateProcess(hJvm, 0);
    CloseHandle(hJvm);
    AGENT_LOG("relaunch: old JVM pid=%llu terminated; agent persisting for new JVM pid=%lu",
              pid, pi.dwProcessId);
}

} // namespace

int main(int argc, char** argv) {
    // Harden own process: deny PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
    hardenSelfProcessDACL();

    bool serve = hasFlag("--serve", argc, argv);

    // Parse DLL path from wide command line to handle non-ASCII paths correctly
    int wargc = 0;
    wchar_t** wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    std::wstring dllPathWide;
    std::string dllPath;
    if (wargv != NULL) {
        dllPathWide = parseArgW(L"--dll=", wargc, wargv);
        dllPath = wideToUtf8(dllPathWide);
        LocalFree(wargv);
    } else {
        // fallback to narrow args
        dllPath = parseArg("--dll=", argc, argv);
        dllPathWide = toWide(dllPath);
    }

    if (dllPath.empty()) {
        printResult("fallback", "UNAVAILABLE", "", "missing_dll_path");
        return 2;
    }

    // Parse log directory (passed from Java: --logdir={run}/ForgeVM/logs)
    std::string logDir = parseArg("--logdir=", argc, argv);

    NativeApi api;
    std::string loadReason;
    agentLogInit(logDir);
    AGENT_LOG("agent starting: dll=%s, serve=%d, logdir=%s",
              dllPath.c_str(), (int)serve, logDir.c_str());

    if (!loadNativeApi(dllPathWide, dllPath, &api, &loadReason)) {
        AGENT_LOG("loadNativeApi FAILED: %s", loadReason.c_str());
        if (api.module != NULL) FreeLibrary(api.module);
        printResult("fallback", "UNAVAILABLE", dllPath, loadReason.c_str());
        return 3;
    }
    AGENT_LOG("loadNativeApi OK");

    // Tell DLL to write its logs (fvm-transform.log) to the same directory
    if (api.setLogDir && !g_logDir.empty()) {
        api.setLogDir(g_logDir.c_str());
        AGENT_LOG("DLL log dir set: %s", g_logDir.c_str());
    }

    if (!serve) {
        AGENT_LOG("one-shot mode: bootstrap");
        handleBootstrap(api, dllPath, "");
        if (api.module != NULL) FreeLibrary(api.module);
        return 0;
    }

    // Start parent process watchdog thread
    CreateThread(NULL, 0, parentWatchdogThread, NULL, 0, NULL);
    AGENT_LOG("serve mode: entering command loop");

    /* Create handoff command pipe up-front. After relaunch, the new JVM's
     * ForgeVM.launch() reads -Dforgevm.agent.pid and connects to this pipe;
     * having it ready before relaunch removes any startup race. */
    ensureCommandPipeCreated();

    AgentLockState lockState;
    std::string line;
re_enter_command_loop:
    while (std::getline(std::cin, line)) {
        refreshLockIfExpired(&lockState);
        std::string cmd = getJsonStringField(line, "cmd");
        AGENT_LOG("cmd=%s", cmd.c_str());

        if (cmd == "bootstrap") {
            handleBootstrap(api, dllPath, line);
        } else if (cmd == "exit_jvm") {
            handleExitJvm(api, line, dllPath);
        } else if (cmd == "put_field") {
            handlePutField(api, line, dllPath);
        } else if (cmd == "put_field_batch") {
            handlePutFieldBatch(api, line, dllPath);
        } else if (cmd == "put_ref_field") {
            handlePutRefField(api, line, dllPath);
        } else if (cmd == "put_ref_field_batch") {
            handlePutRefFieldBatch(api, line, dllPath);
        } else if (cmd == "forge_batch_plan") {
            handleForgeBatchPlan(api, line, dllPath);
        } else if (cmd == "force_deopt") {
            if (api.forceDeoptNow != NULL) {
                int r = api.forceDeoptNow();
                std::string reason = copyReason(api, r == 1 ? "ok" : "force_deopt_failed");
                AGENT_LOG("force_deopt result=%d reason=%s", r, reason.c_str());
                if (r == 1) {
                    printResult("ok", "FULL", dllPath, reason.c_str());
                } else {
                    printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
                }
            } else {
                printResult("fallback", "UNAVAILABLE", dllPath, "force_deopt_not_exported");
            }
        } else if (cmd == "forge_class_unload") {
            handleForgeClassUnload(api, line, dllPath);
        } else if (cmd == "purge_matching_agents") {
            handlePurgeMatchingAgents(api, line, dllPath);
        } else if (cmd == "put_field_path") {
            handlePutFieldPath(api, line, dllPath);
        } else if (cmd == "put_object_field_path") {
            handlePutObjectFieldPath(api, line, dllPath);
        } else if (cmd == "dump_card_structs") {
            if (api.dumpCardStructs != NULL) {
                api.dumpCardStructs();
                printResult("ok", "FULL", dllPath, api.lastError ? api.lastError() : "no_data");
            } else {
                printResult("fallback", "UNAVAILABLE", dllPath, "dump_card_structs_not_exported");
            }
        } else if (cmd == "ping") {
            printResult("ok", "RESTRICTED", dllPath, lockState.locked ? "pong_locked" : "pong_unlocked");
        } else if (cmd == "lock_agent") {
            handleLockAgent(&lockState, line, dllPath);
        } else if (cmd == "unlock_agent") {
            handleUnlockAgent(&lockState, dllPath);
        } else if (cmd == "rebind_jvm") {
            handleRebindJvm(&lockState, line, dllPath);
        } else if (cmd == "ban_java_agent") {
            handleBanJavaAgent(api, line, dllPath);
        } else if (cmd == "unban_java_agent") {
            handleUnbanJavaAgent(api, dllPath);
        } else if (cmd == "ban_native_load") {
            handleBanNativeLoad(api, line, dllPath);
        } else if (cmd == "unban_native_load") {
            handleUnbanNativeLoad(api, dllPath);
        } else if (cmd == "ban_process_create") {
            handleBanProcessCreate(api, line, dllPath);
        } else if (cmd == "unban_process_create") {
            handleUnbanProcessCreate(api, dllPath);
        } else if (cmd == "relaunch") {
            handleRelaunch(api, line, dllPath);
        } else if (cmd == "shutdown") {
            printResult("ok", "RESTRICTED", dllPath, "bye");
            break;
        } else {
            printResult("fallback", "UNAVAILABLE", dllPath, "unknown_command");
        }
    }

    while (lockState.locked && !lockExpired(lockState)) {
        Sleep(100);
    }

    /* If a relaunch armed the persistence flag, our stdin (inherited from
     * old JVM) just EOF'd. Don't exit — wait for the new JVM's ForgeVM.launch()
     * to connect to the handoff command pipe, then redirect stdin/stdout to
     * the pipe and re-enter the command loop. The filter pipe (serving the
     * new JVM's ntdll trampoline) stays alive throughout this transition
     * because it's owned by the filter pipe accept thread which is independent
     * of stdio. */
    if (g_persistAfterEOF.load()) {
        AGENT_LOG("main: stdin EOF after relaunch — awaiting handoff on %s",
                  g_commandPipeName.c_str());
        HANDLE hJvm = g_relaunchNewJvm.exchange(NULL);
        HANDLE pipe = acceptCommandPipeClient(hJvm);
        if (hJvm != NULL) CloseHandle(hJvm);
        if (pipe != NULL && pipe != INVALID_HANDLE_VALUE) {
            AGENT_LOG("main: handoff client connected, redirecting stdio");
            if (redirectStdioToPipe(pipe)) {
                /* The persistence flag is one-shot: subsequent stdin EOFs
                 * (e.g., new JVM disconnects) should terminate the agent
                 * normally, since at that point no JVM is left to serve. */
                g_persistAfterEOF.store(false);
                goto re_enter_command_loop;
            }
            CloseHandle(pipe);
        } else {
            AGENT_LOG("main: handoff accept failed — exiting");
        }
    }

    if (api.module != NULL) FreeLibrary(api.module);
    return 0;
}
