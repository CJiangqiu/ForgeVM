#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <cstdio>
#include <cstdarg>

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
typedef int(__cdecl* TransformLoadFn)(const char*, const char*, const char*, const char*, const char*, const char*, const char*);
typedef int(__cdecl* TransformUnloadFn)(const char*, const char*, const char*);
typedef int(__cdecl* PurgeAgentFn)(const char*);
typedef int(__cdecl* PutFieldPathFn)(const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* ForgeSubclassLoadFn)(const char*, const char*, const char*, const char*, const char*, const char*, const char*);
typedef int(__cdecl* ForgeSubclassUnloadFn)(const char*, const char*, const char*);
typedef int(__cdecl* PutObjectFieldPathFn)(const char*, const char*, const char*, const char*);

namespace {
struct NativeApi {
    HMODULE module = NULL;
    ProbeFn probe = NULL;
    ProbeFn probePrompt = NULL;
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
    TransformLoadFn transformLoad = NULL;
    TransformUnloadFn transformUnload = NULL;
    PurgeAgentFn purgeAgent = NULL;
    PutFieldPathFn putFieldPath = NULL;
    ForgeSubclassLoadFn forgeSubLoad = NULL;
    ForgeSubclassUnloadFn forgeSubUnload = NULL;
    PutObjectFieldPathFn putObjectFieldPath = NULL;
};

struct AgentLockState {
    bool locked = false;
    ULONGLONG lockUntilTick = 0;
    unsigned long long ownerPid = 0ULL;
};


// Parent process watchdog: exits agent when parent JVM dies
static std::atomic<DWORD> g_parentPid{0};

DWORD WINAPI parentWatchdogThread(LPVOID) {
    while (true) {
        DWORD pid = g_parentPid.load();
        if (pid == 0) {
            Sleep(500);
            continue;
        }
        HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (hParent == NULL) {
            // Parent already dead — force exit
            ExitProcess(0);
            return 0;
        }
        DWORD waitResult = WaitForSingleObject(hParent, INFINITE);
        CloseHandle(hParent);
        if (waitResult == WAIT_OBJECT_0) {
            // Parent exited — force exit
            ExitProcess(0);
        }
        return 0;
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
    if (code >= 2) return "FULL";
    if (code == 1) return "RESTRICTED";
    return "UNAVAILABLE";
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

// Thread-local socket for the current client connection.
// When set to INVALID_SOCKET, output goes to stdout (bootstrap / one-shot mode).
static thread_local SOCKET tl_clientSocket = INVALID_SOCKET;

static bool sendLine(SOCKET sock, const std::string& line) {
    std::string data = line + "\n";
    int total = static_cast<int>(data.size());
    int sent = 0;
    while (sent < total) {
        int n = ::send(sock, data.c_str() + sent, total - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
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

    if (tl_clientSocket != INVALID_SOCKET) {
        sendLine(tl_clientSocket, oss.str());
    } else {
        std::cout << oss.str() << std::endl;
    }
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

    if (tl_clientSocket != INVALID_SOCKET) {
        sendLine(tl_clientSocket, oss.str());
    } else {
        std::cout << oss.str() << std::endl;
    }
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
    api->probePrompt     = reinterpret_cast<ProbeFn>(GetProcAddress(module, "forgevm_probe_capability_prompt"));
    api->init            = reinterpret_cast<InitFn>(GetProcAddress(module, "forgevm_init"));
    api->lastError       = reinterpret_cast<LastErrorFn>(GetProcAddress(module, "forgevm_last_error"));
    api->exitByPid       = reinterpret_cast<ExitByPidFn>(GetProcAddress(module, "forgevm_exit_process"));
    api->bootstrapTarget = reinterpret_cast<BootstrapTargetFn>(GetProcAddress(module, "forgevm_bootstrap_target"));
    api->structMapCount  = reinterpret_cast<StructMapCountFn>(GetProcAddress(module, "forgevm_structmap_count"));
    api->typeMapCount    = reinterpret_cast<StructMapCountFn>(GetProcAddress(module, "forgevm_typemap_count"));
    api->compressionInfo = reinterpret_cast<LastErrorFn>(GetProcAddress(module, "forgevm_compression_info"));
    api->putField        = reinterpret_cast<PutFieldFn>(GetProcAddress(module, "forgevm_put_field"));
    api->putFieldBatch   = reinterpret_cast<PutFieldBatchFn>(GetProcAddress(module, "forgevm_put_field_batch"));
    api->putRefField     = reinterpret_cast<PutFieldFn>(GetProcAddress(module, "forgevm_put_ref_field"));
    api->putRefFieldBatch = reinterpret_cast<PutFieldBatchFn>(GetProcAddress(module, "forgevm_put_ref_field_batch"));
    api->setLogDir       = reinterpret_cast<SetLogDirFn>(GetProcAddress(module, "forgevm_set_log_dir"));
    api->dumpCardStructs = reinterpret_cast<ProbeFn>(GetProcAddress(module, "forgevm_dump_card_structs"));
    api->transformLoad   = reinterpret_cast<TransformLoadFn>(GetProcAddress(module, "forgevm_transform_load"));
    api->transformUnload = reinterpret_cast<TransformUnloadFn>(GetProcAddress(module, "forgevm_transform_unload"));
    api->purgeAgent      = reinterpret_cast<PurgeAgentFn>(GetProcAddress(module, "forgevm_purge_agent"));
    api->putFieldPath    = reinterpret_cast<PutFieldPathFn>(GetProcAddress(module, "forgevm_put_field_path"));
    api->forgeSubLoad    = reinterpret_cast<ForgeSubclassLoadFn>(GetProcAddress(module, "forgevm_forge_load_subclasses"));
    api->forgeSubUnload  = reinterpret_cast<ForgeSubclassUnloadFn>(GetProcAddress(module, "forgevm_forge_unload_subclasses"));
    api->putObjectFieldPath = reinterpret_cast<PutObjectFieldPathFn>(GetProcAddress(module, "forgevm_put_object_field_path"));

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

void handleBootstrap(const NativeApi& api, const std::string& policy,
                     const std::string& dllPath, const std::string& line) {
    AGENT_LOG("bootstrap: policy=%s", policy.c_str());
    bool prompt = policy == "prompt";
    int capability = 0;
    if (prompt && api.probePrompt != NULL) {
        capability = api.probePrompt();
    } else {
        capability = api.probe();
    }
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

void handleForgeLoad(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.transformLoad == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "forge_load_not_exported");
        return;
    }
    std::string targetClass  = getJsonStringField(line, "targetClass");
    std::string targetMethod = getJsonStringField(line, "targetMethod");
    std::string targetParamDesc = getJsonStringField(line, "targetParamDesc");
    std::string injectAt     = getJsonStringField(line, "injectAt");
    std::string injectTarget = getJsonStringField(line, "injectTarget");
    std::string hookClass    = getJsonStringField(line, "hookClass");
    std::string hookMethod   = getJsonStringField(line, "hookMethod");
    std::string hookDesc     = getJsonStringField(line, "hookDesc");
    bool includeSubclasses   = line.find("\"includeSubclasses\":true") != std::string::npos;

    // Combine injectAt + injectTarget into "TYPE:target" format for DLL
    std::string injectAtFull = injectAt;
    if (!injectTarget.empty()) {
        injectAtFull += ":" + injectTarget;
    }

    AGENT_LOG("forge_load: %s.%s(%s) @ %s -> %s.%s%s [subclasses=%s]",
              targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str(),
              injectAtFull.c_str(), hookClass.c_str(), hookMethod.c_str(), hookDesc.c_str(),
              includeSubclasses ? "true" : "false");

    if (targetClass.empty() || targetMethod.empty() || injectAt.empty() ||
        hookClass.empty() || hookMethod.empty() || hookDesc.empty()) {
        AGENT_LOG("forge_load: missing params");
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_forge_load_params");
        return;
    }

    int result;
    if (includeSubclasses && api.forgeSubLoad != NULL) {
        result = api.forgeSubLoad(
            targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str(),
            injectAtFull.c_str(), hookClass.c_str(), hookMethod.c_str(), hookDesc.c_str());
    } else {
        result = api.transformLoad(
            targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str(),
            injectAtFull.c_str(), hookClass.c_str(), hookMethod.c_str(), hookDesc.c_str());
    }

    std::string reason = copyReason(api, result == 1 ? "ok" : "forge_load_failed");
    AGENT_LOG("forge_load result=%d reason=%s", result, reason.c_str());
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
}

void handleForgeUnload(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.transformUnload == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "forge_unload_not_exported");
        return;
    }
    std::string targetClass  = getJsonStringField(line, "targetClass");
    std::string targetMethod = getJsonStringField(line, "targetMethod");
    std::string targetParamDesc = getJsonStringField(line, "targetParamDesc");
    bool includeSubclasses   = line.find("\"includeSubclasses\":true") != std::string::npos;

    AGENT_LOG("forge_unload: %s.%s(%s) [subclasses=%s]",
              targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str(),
              includeSubclasses ? "true" : "false");

    if (targetClass.empty() || targetMethod.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_forge_unload_params");
        return;
    }

    int result;
    if (includeSubclasses && api.forgeSubUnload != NULL) {
        result = api.forgeSubUnload(targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str());
    } else {
        result = api.transformUnload(targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str());
    }

    std::string reason = copyReason(api, result == 1 ? "ok" : "forge_unload_failed");
    AGENT_LOG("forge_unload result=%d reason=%s", result, reason.c_str());
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
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

void handlePurgeAgent(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.purgeAgent == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "purge_agent_not_exported");
        return;
    }
    std::string agentClass = getJsonStringField(line, "agentClass");
    if (agentClass.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_agent_class");
        return;
    }

    AGENT_LOG("purge_agent: %s", agentClass.c_str());

    int result = api.purgeAgent(agentClass.c_str());
    std::string reason = copyReason(api, result == 1 ? "ok" : "purge_agent_failed");
    AGENT_LOG("purge_agent result=%d reason=%s", result, reason.c_str());
    if (result == 1) {
        printResult("ok", "FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, reason.c_str());
    }
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

// Global lock for DLL calls that modify target process memory.
// Multiple client threads share one DLL instance — serialize writes.
static std::mutex g_dllMutex;

// Read one newline-terminated line from a socket.
// Returns false on disconnect or error.
static bool recvLine(SOCKET sock, std::string* out) {
    out->clear();
    char c;
    while (true) {
        int n = ::recv(sock, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') return true;
        if (c != '\r') out->push_back(c);
    }
}

// Process one command from a client connection.
// Returns false if the connection should be closed.
bool dispatchCommand(const NativeApi& api, const std::string& policy,
                     const std::string& dllPath, AgentLockState* lockState,
                     const std::string& line) {
    refreshLockIfExpired(lockState);
    std::string cmd = getJsonStringField(line, "cmd");
    AGENT_LOG("cmd=%s", cmd.c_str());

    if (cmd == "bootstrap") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handleBootstrap(api, policy, dllPath, line);
    } else if (cmd == "exit_jvm") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handleExitJvm(api, line, dllPath);
    } else if (cmd == "put_field") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutField(api, line, dllPath);
    } else if (cmd == "put_field_batch") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutFieldBatch(api, line, dllPath);
    } else if (cmd == "put_ref_field") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutRefField(api, line, dllPath);
    } else if (cmd == "put_ref_field_batch") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutRefFieldBatch(api, line, dllPath);
    } else if (cmd == "forge_load") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handleForgeLoad(api, line, dllPath);
    } else if (cmd == "forge_unload") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handleForgeUnload(api, line, dllPath);
    } else if (cmd == "purge_agent") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePurgeAgent(api, line, dllPath);
    } else if (cmd == "put_field_path") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutFieldPath(api, line, dllPath);
    } else if (cmd == "put_object_field_path") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        handlePutObjectFieldPath(api, line, dllPath);
    } else if (cmd == "dump_card_structs") {
        std::lock_guard<std::mutex> lock(g_dllMutex);
        if (api.dumpCardStructs != NULL) {
            api.dumpCardStructs();
            printResult("ok", "FULL", dllPath, api.lastError ? api.lastError() : "no_data");
        } else {
            printResult("fallback", "UNAVAILABLE", dllPath, "dump_card_structs_not_exported");
        }
    } else if (cmd == "ping") {
        printResult("ok", "RESTRICTED", dllPath, lockState->locked ? "pong_locked" : "pong_unlocked");
    } else if (cmd == "lock_agent") {
        handleLockAgent(lockState, line, dllPath);
    } else if (cmd == "unlock_agent") {
        handleUnlockAgent(lockState, dllPath);
    } else if (cmd == "rebind_jvm") {
        handleRebindJvm(lockState, line, dllPath);
    } else if (cmd == "shutdown") {
        printResult("ok", "RESTRICTED", dllPath, "bye");
        return false; // close this connection
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, "unknown_command");
    }
    return true;
}

struct ClientThreadArgs {
    SOCKET clientSocket;
    const NativeApi* api;
    std::string policy;
    std::string dllPath;
};

DWORD WINAPI clientThread(LPVOID param) {
    ClientThreadArgs* args = reinterpret_cast<ClientThreadArgs*>(param);
    SOCKET sock = args->clientSocket;
    const NativeApi& api = *args->api;
    std::string policy = args->policy;
    std::string dllPath = args->dllPath;
    delete args;

    tl_clientSocket = sock;
    AGENT_LOG("client connected: socket=%llu", (unsigned long long)sock);

    AgentLockState lockState;
    std::string line;
    while (recvLine(sock, &line)) {
        if (line.empty()) continue;
        if (!dispatchCommand(api, policy, dllPath, &lockState, line)) {
            break;
        }
    }

    AGENT_LOG("client disconnected: socket=%llu", (unsigned long long)sock);
    closesocket(sock);
    tl_clientSocket = INVALID_SOCKET;
    return 0;
}

// Write the port file so Java clients can discover the Agent.
// File: {logDir}/../runtime/agent_{jvmPid}.port  (or ForgeVM/runtime/agent_{pid}.port)
static void writePortFile(int port, const std::string& logDir, unsigned long long jvmPid) {
    // Derive runtime dir from logDir (logDir = .../ForgeVM/logs -> runtime = .../ForgeVM/runtime)
    std::string runtimeDir;
    if (!logDir.empty()) {
        std::string base = logDir;
        // Remove trailing slash
        while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
        // Go up one level (from "logs" to "ForgeVM")
        size_t sep = base.find_last_of("\\/");
        if (sep != std::string::npos) {
            runtimeDir = base.substr(0, sep) + "\\runtime";
        } else {
            runtimeDir = "ForgeVM\\runtime";
        }
    } else {
        runtimeDir = "ForgeVM\\runtime";
    }

    CreateDirectoryA(runtimeDir.c_str(), NULL);
    std::string portFile = runtimeDir + "\\agent_" + std::to_string(jvmPid) + ".port";

    FILE* f = fopen(portFile.c_str(), "w");
    if (f) {
        fprintf(f, "%d", port);
        fclose(f);
        AGENT_LOG("port file written: %s (port=%d)", portFile.c_str(), port);
    } else {
        AGENT_LOG("WARN: failed to write port file: %s", portFile.c_str());
    }
}

static void deletePortFile(const std::string& logDir, unsigned long long jvmPid) {
    std::string runtimeDir;
    if (!logDir.empty()) {
        std::string base = logDir;
        while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
        size_t sep = base.find_last_of("\\/");
        if (sep != std::string::npos) {
            runtimeDir = base.substr(0, sep) + "\\runtime";
        } else {
            runtimeDir = "ForgeVM\\runtime";
        }
    } else {
        runtimeDir = "ForgeVM\\runtime";
    }
    std::string portFile = runtimeDir + "\\agent_" + std::to_string(jvmPid) + ".port";
    DeleteFileA(portFile.c_str());
    AGENT_LOG("port file deleted: %s", portFile.c_str());
}

} // namespace

int main(int argc, char** argv) {
    // Parse policy and serve flag from narrow args (ASCII, safe)
    std::string policy  = parseArg("--policy=", argc, argv);
    bool serve = hasFlag("--serve", argc, argv);
    if (policy.empty()) policy = "silent";

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
    AGENT_LOG("agent starting: dll=%s, policy=%s, serve=%d, logdir=%s",
              dllPath.c_str(), policy.c_str(), (int)serve, logDir.c_str());

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
        handleBootstrap(api, policy, dllPath, "");
        if (api.module != NULL) FreeLibrary(api.module);
        return 0;
    }

    // ---- TCP serve mode ----

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        AGENT_LOG("WSAStartup failed");
        printResult("fallback", "UNAVAILABLE", dllPath, "winsock_init_failed");
        return 4;
    }

    // Create listening socket on localhost, random port
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        AGENT_LOG("socket() failed: %d", WSAGetLastError());
        printResult("fallback", "UNAVAILABLE", dllPath, "socket_create_failed");
        WSACleanup();
        return 4;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only
    addr.sin_port = 0; // random port

    if (bind(listenSock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        AGENT_LOG("bind() failed: %d", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 4;
    }

    // Get assigned port
    struct sockaddr_in boundAddr = {};
    int boundLen = sizeof(boundAddr);
    getsockname(listenSock, reinterpret_cast<struct sockaddr*>(&boundAddr), &boundLen);
    int listenPort = ntohs(boundAddr.sin_port);

    if (listen(listenSock, 8) == SOCKET_ERROR) {
        AGENT_LOG("listen() failed: %d", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 4;
    }

    AGENT_LOG("TCP listening on 127.0.0.1:%d", listenPort);

    // Report port to stdout so the launching Java process can read it.
    // Format: {"port":12345}
    std::cout << "{\"port\":" << listenPort << "}" << std::endl;

    // Start parent process watchdog thread
    CreateThread(NULL, 0, parentWatchdogThread, NULL, 0, NULL);

    // Accept loop — each client gets its own thread
    AGENT_LOG("serve mode: entering accept loop");
    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) {
            AGENT_LOG("accept() failed: %d", WSAGetLastError());
            break;
        }

        ClientThreadArgs* args = new ClientThreadArgs();
        args->clientSocket = clientSock;
        args->api = &api;
        args->policy = policy;
        args->dllPath = dllPath;

        HANDLE hThread = CreateThread(NULL, 0, clientThread, args, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread); // detach
        } else {
            AGENT_LOG("CreateThread failed for client");
            closesocket(clientSock);
            delete args;
        }
    }

    closesocket(listenSock);
    WSACleanup();
    if (api.module != NULL) FreeLibrary(api.module);
    return 0;
}
