#include <windows.h>
#include <shellapi.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>

typedef int(__cdecl* ProbeFn)();
typedef int(__cdecl* InitFn)();
typedef const char* (__cdecl* LastErrorFn)();
typedef int(__cdecl* ExitByPidFn)(unsigned long long, int);
typedef int(__cdecl* BootstrapTargetFn)(unsigned long long);
typedef unsigned long long(__cdecl* StructMapCountFn)();
typedef int(__cdecl* PutFieldFn)(unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* PutFieldBatchFn)(const unsigned long long*, unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* TransformLoadFn)(const char*, const char*, const char*, const char*, const char*, const char*, const char*);
typedef int(__cdecl* TransformUnloadFn)(const char*, const char*, const char*);

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
    TransformLoadFn transformLoad = NULL;
    TransformUnloadFn transformUnload = NULL;
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
    if (code >= 2) return "NATIVE_FULL";
    if (code == 1) return "NATIVE_RESTRICTED";
    return "JVM_FALLBACK";
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
    std::cout << "{\"status\":\"" << escapeJson(status)
              << "\",\"capability\":\"" << escapeJson(capability)
              << "\",\"dllPath\":\"" << escapeJson(dllPath)
              << "\",\"reason\":\"" << escapeJson(reason) << "\"";
    for (size_t i = 0; i < fields.size(); ++i) {
        std::cout << ",\"" << escapeJson(fields[i].first)
                  << "\":\"" << escapeJson(fields[i].second) << "\"";
    }
    std::cout << "}" << std::endl;
}

void printResult(const char* status,
                 const char* capability,
                 const std::string& dllPath,
                 const char* reason) {
    std::cout << "{\"status\":\"" << escapeJson(status)
              << "\",\"capability\":\"" << escapeJson(capability)
              << "\",\"dllPath\":\"" << escapeJson(dllPath)
              << "\",\"reason\":\"" << escapeJson(reason)
              << "\"}" << std::endl;
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
    api->dumpCardStructs = reinterpret_cast<ProbeFn>(GetProcAddress(module, "forgevm_dump_card_structs"));
    api->transformLoad   = reinterpret_cast<TransformLoadFn>(GetProcAddress(module, "forgevm_transform_load"));
    api->transformUnload = reinterpret_cast<TransformUnloadFn>(GetProcAddress(module, "forgevm_transform_unload"));

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
    bool prompt = policy == "prompt";
    int capability = 0;
    if (prompt && api.probePrompt != NULL) {
        capability = api.probePrompt();
    } else {
        capability = api.probe();
    }

    if (capability <= 0) {
        std::string reason = copyReason(api, "permission_probe_failed");
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
        return;
    }

    int initCode = api.init();
    if (initCode != 1) {
        std::string reason = copyReason(api, "native_init_failed");
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
        return;
    }

    bool structMapReady = false;
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid != 0ULL) {
        g_parentPid.store(static_cast<DWORD>(pid));
    }
    if (pid != 0ULL && api.bootstrapTarget != NULL) {
        if (api.bootstrapTarget(pid) == 1) {
            structMapReady = true;
        } else {
            std::string reason = copyReason(api, "bootstrap_target_failed");
            printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
            return;
        }
    }

    std::vector<std::pair<std::string, std::string>> fields;
    fields.push_back({"structMapReady", structMapReady ? "true" : "false"});
    if (structMapReady && api.structMapCount != NULL)
        fields.push_back({"structMapEntries", std::to_string(api.structMapCount())});
    if (structMapReady && api.typeMapCount != NULL)
        fields.push_back({"typeMapEntries", std::to_string(api.typeMapCount())});
    if (structMapReady && api.compressionInfo != NULL) {
        const char* cinfo = api.compressionInfo();
        if (cinfo != NULL && cinfo[0] != '\0')
            fields.push_back({"compressionInfo", std::string(cinfo)});
    }
    printResultWithFields("ok", capFromCode(capability), dllPath, "ok", fields);
}

void handleExitJvm(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    unsigned long long pid  = getJsonUnsignedField(line, "pid", 0ULL);
    unsigned long long code = getJsonUnsignedField(line, "code", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_pid");
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
        printResult("ok", "NATIVE_RESTRICTED", dllPath, "exit_sent");
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, "exit_failed");
    }
}

void handleLockAgent(AgentLockState* lockState, const std::string& line, const std::string& dllPath) {
    unsigned long long ttlSec = getJsonUnsignedField(line, "ttlSec", 120ULL);
    if (ttlSec == 0ULL) ttlSec = 1ULL;
    if (ttlSec > 600ULL) ttlSec = 600ULL;
    lockState->locked = true;
    lockState->lockUntilTick = nowTick() + static_cast<ULONGLONG>(ttlSec * 1000ULL);
    printResult("ok", "NATIVE_RESTRICTED", dllPath, "agent_locked");
}

void handleUnlockAgent(AgentLockState* lockState, const std::string& dllPath) {
    lockState->locked = false;
    lockState->lockUntilTick = 0;
    lockState->ownerPid = 0ULL;
    printResult("ok", "NATIVE_RESTRICTED", dllPath, "agent_unlocked");
}

void handleRebindJvm(AgentLockState* lockState, const std::string& line, const std::string& dllPath) {
    refreshLockIfExpired(lockState);
    if (!lockState->locked) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "agent_not_locked");
        return;
    }
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_pid");
        return;
    }
    lockState->ownerPid = pid;
    printResult("ok", "NATIVE_RESTRICTED", dllPath, "agent_rebound");
}

void handlePutField(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putField == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "put_field_not_exported");
        return;
    }
    unsigned long long oop = getJsonUnsignedField(line, "oop", 0ULL);
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_put_field_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putField(oop, fieldName.c_str(), className.c_str(),
                               valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_field_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
}

void handlePutFieldBatch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putFieldBatch == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "put_field_batch_not_exported");
        return;
    }
    std::vector<unsigned long long> oops = parseJsonUint64Array(line, "oops");
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (oops.empty() || fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_put_field_batch_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putFieldBatch(oops.data(), static_cast<unsigned long long>(oops.size()),
                                    fieldName.c_str(), className.c_str(),
                                    valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_field_batch_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
}

void handlePutRefField(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putRefField == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "put_ref_field_not_exported");
        return;
    }
    unsigned long long oop = getJsonUnsignedField(line, "oop", 0ULL);
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_put_ref_field_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putRefField(oop, fieldName.c_str(), className.c_str(),
                                  valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_ref_field_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
}

void handlePutRefFieldBatch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.putRefFieldBatch == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "put_ref_field_batch_not_exported");
        return;
    }
    std::vector<unsigned long long> oops = parseJsonUint64Array(line, "oops");
    std::string fieldName = getJsonStringField(line, "fieldName");
    std::string className = getJsonStringField(line, "className");
    std::string valueHex  = getJsonStringField(line, "valueHex");

    if (oops.empty() || fieldName.empty() || className.empty() || valueHex.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_put_ref_field_batch_params");
        return;
    }

    std::vector<unsigned char> valueBytes = fromHex(valueHex);
    if (valueBytes.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "empty_value_bytes");
        return;
    }

    int result = api.putRefFieldBatch(oops.data(), static_cast<unsigned long long>(oops.size()),
                                       fieldName.c_str(), className.c_str(),
                                       valueBytes.data(), static_cast<unsigned long long>(valueBytes.size()));
    std::string reason = copyReason(api, result == 1 ? "ok" : "put_ref_field_batch_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
}

void handleTransformLoad(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.transformLoad == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "transform_load_not_exported");
        return;
    }
    std::string targetClass  = getJsonStringField(line, "targetClass");
    std::string targetMethod = getJsonStringField(line, "targetMethod");
    std::string targetParamDesc = getJsonStringField(line, "targetParamDesc");
    std::string injectAt     = getJsonStringField(line, "injectAt");
    std::string hookClass    = getJsonStringField(line, "hookClass");
    std::string hookMethod   = getJsonStringField(line, "hookMethod");
    std::string hookDesc     = getJsonStringField(line, "hookDesc");

    if (targetClass.empty() || targetMethod.empty() || injectAt.empty() ||
        hookClass.empty() || hookMethod.empty() || hookDesc.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_transform_load_params");
        return;
    }

    int result = api.transformLoad(
        targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str(),
        injectAt.c_str(), hookClass.c_str(), hookMethod.c_str(), hookDesc.c_str());

    std::string reason = copyReason(api, result == 1 ? "ok" : "transform_load_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
}

void handleTransformUnload(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    if (api.transformUnload == NULL) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "transform_unload_not_exported");
        return;
    }
    std::string targetClass  = getJsonStringField(line, "targetClass");
    std::string targetMethod = getJsonStringField(line, "targetMethod");
    std::string targetParamDesc = getJsonStringField(line, "targetParamDesc");

    if (targetClass.empty() || targetMethod.empty()) {
        printResult("fallback", "JVM_FALLBACK", dllPath, "missing_transform_unload_params");
        return;
    }

    int result = api.transformUnload(targetClass.c_str(), targetMethod.c_str(), targetParamDesc.c_str());

    std::string reason = copyReason(api, result == 1 ? "ok" : "transform_unload_failed");
    if (result == 1) {
        printResult("ok", "NATIVE_FULL", dllPath, reason.c_str());
    } else {
        printResult("fallback", "JVM_FALLBACK", dllPath, reason.c_str());
    }
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
        printResult("fallback", "JVM_FALLBACK", "", "missing_dll_path");
        return 2;
    }

    NativeApi api;
    std::string loadReason;
    if (!loadNativeApi(dllPathWide, dllPath, &api, &loadReason)) {
        if (api.module != NULL) FreeLibrary(api.module);
        printResult("fallback", "JVM_FALLBACK", dllPath, loadReason.c_str());
        return 3;
    }

    if (!serve) {
        handleBootstrap(api, policy, dllPath, "");
        if (api.module != NULL) FreeLibrary(api.module);
        return 0;
    }

    // Start parent process watchdog thread
    CreateThread(NULL, 0, parentWatchdogThread, NULL, 0, NULL);

    AgentLockState lockState;
    std::string line;
    while (std::getline(std::cin, line)) {
        refreshLockIfExpired(&lockState);
        std::string cmd = getJsonStringField(line, "cmd");

        if (cmd == "bootstrap") {
            handleBootstrap(api, policy, dllPath, line);
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
        } else if (cmd == "transform_load") {
            handleTransformLoad(api, line, dllPath);
        } else if (cmd == "transform_unload") {
            handleTransformUnload(api, line, dllPath);
        } else if (cmd == "dump_card_structs") {
            if (api.dumpCardStructs != NULL) {
                api.dumpCardStructs();
                printResult("ok", "NATIVE_FULL", dllPath, api.lastError ? api.lastError() : "no_data");
            } else {
                printResult("fallback", "JVM_FALLBACK", dllPath, "dump_card_structs_not_exported");
            }
        } else if (cmd == "ping") {
            printResult("ok", "NATIVE_RESTRICTED", dllPath, lockState.locked ? "pong_locked" : "pong_unlocked");
        } else if (cmd == "lock_agent") {
            handleLockAgent(&lockState, line, dllPath);
        } else if (cmd == "unlock_agent") {
            handleUnlockAgent(&lockState, dllPath);
        } else if (cmd == "rebind_jvm") {
            handleRebindJvm(&lockState, line, dllPath);
        } else if (cmd == "shutdown") {
            printResult("ok", "NATIVE_RESTRICTED", dllPath, "bye");
            break;
        } else {
            printResult("fallback", "JVM_FALLBACK", dllPath, "unknown_command");
        }
    }

    while (lockState.locked && !lockExpired(lockState)) {
        Sleep(100);
    }

    if (api.module != NULL) FreeLibrary(api.module);
    return 0;
}
