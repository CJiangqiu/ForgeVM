#include <windows.h>
#include <shellapi.h>
#include <aclapi.h>
/* WMI for relaunch: link ole32.lib oleaut32.lib wbemuuid.lib */
#include <comdef.h>
#include <wbemidl.h>
/* EnumProcessModulesEx / GetModuleBaseNameW for relaunch post-resume watcher. Link Psapi.lib. */
#include <psapi.h>
/* Toolhelp thread enumeration for the optional [JVM] health poller. */
#include <tlhelp32.h>
#include <bcrypt.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <cstdio>
#include <cstdarg>
#include <cwctype>
#include <cctype>
/* For redirecting stdin/stdout to the handoff command pipe after old JVM dies. */
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "bcrypt.lib")

/* ============================================================
 * Agent-level file logging — unified with DLL into one file
 * ============================================================ */

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

/* ============================================================
 * Live status window plumbing (optional, gated at startup)
 *
 * One scrolling feed mixing two prefixed streams in arrival order:
 *   [FVM] — agent activity, teed here from every AGENT_LOG call
 *   [JVM] — target JVM health, sampled cross-process by the poller thread
 * Lines flow through this mutex-guarded queue; the UI thread drains it. Both
 * the poller and the UI live on their own threads and never touch the command
 * loop. windowPublish is a no-op until the window is enabled at startup. */
static std::atomic<bool>        g_windowEnabled{false};
static std::atomic<bool>        g_jvmDiedPostMortem{false};  // target died; window kept for review
static std::atomic<bool>        g_jvmLockRequested{false};
static std::mutex               g_windowQueueMutex;
static std::vector<std::string> g_windowQueue;

static void windowPublish(const std::string& line) {
    if (!g_windowEnabled.load()) return;
    std::lock_guard<std::mutex> g(g_windowQueueMutex);
    g_windowQueue.push_back(line);
}

static void agentLog(const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    char body[2048];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);
    va_end(args);

    if (g_agentLog) {
        fprintf(g_agentLog, "%04d-%02d-%02d %02d:%02d:%02d.%03d | %s\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, body);
        fflush(g_agentLog);
    }
    if (g_windowEnabled.load()) {
        char ts[16];
        sprintf_s(ts, sizeof(ts), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        windowPublish(std::string(ts) + " [FVM] " + body);
    }
}

#define AGENT_LOG(fmt, ...) agentLog(fmt, ##__VA_ARGS__)

typedef int(__cdecl* ProbeFn)();
typedef int(__cdecl* InitFn)();
typedef const char* (__cdecl* LastErrorFn)();
typedef int(__cdecl* ExitByPidFn)(unsigned long long, int);
typedef int(__cdecl* BootstrapTargetFn)(unsigned long long);
typedef int(__cdecl* BootstrapTargetWithHandleFn)(unsigned long long, void*);
typedef unsigned long long(__cdecl* StructMapCountFn)();
typedef int(__cdecl* PutFieldFn)(unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* PutFieldBatchFn)(const unsigned long long*, unsigned long long, const char*, const char*, const unsigned char*, unsigned long long);
typedef void(__cdecl* SetLogDirFn)(const char*);
typedef int(__cdecl* ForceDeoptNowFn)();
typedef int(__cdecl* PurgeAgentsMatchingFn)(int, const char* const*, int);
typedef int(__cdecl* PutFieldPathFn)(const char*, const char*, const unsigned char*, unsigned long long);
typedef int(__cdecl* PutObjectFieldPathFn)(const char*, const char*, const char*, const char*);
typedef int(__cdecl* BanJavaAgentFn)(int, const char*);
typedef int(__cdecl* UnbanJavaAgentFn)();
typedef int(__cdecl* BanNativeLoadFn)(int, const char*);
typedef int(__cdecl* UnbanNativeLoadFn)();
typedef int(__cdecl* BanJvmtiFn)(int, const char*);
typedef int(__cdecl* UnbanJvmtiFn)();
typedef int(__cdecl* BanProcessCreateFn)(int, const char*);
typedef int(__cdecl* UnbanProcessCreateFn)();
typedef unsigned long long(__cdecl* InstallHaltLockFn)();
typedef int(__cdecl* UninstallHaltLockFn)();
typedef int(__cdecl* HaltLockHeartbeatFn)();
typedef int(__cdecl* HaltLockAllowFn)();
typedef unsigned long long(__cdecl* FilterAuditFn)(int);
typedef int(__cdecl* InstallSelfTerminateGuardFn)();
typedef int(__cdecl* VerifyHookIntegrityFn)();
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
    BootstrapTargetWithHandleFn bootstrapTargetWithHandle = NULL;
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
    BanJvmtiFn banJvmti = NULL;
    UnbanJvmtiFn unbanJvmti = NULL;
    BanProcessCreateFn banProcessCreate = NULL;
    UnbanProcessCreateFn unbanProcessCreate = NULL;
    ForgeClassPlanFn forgeClassPlan = NULL;
    ForgeClassUnloadFn forgeClassUnload = NULL;
    InstallHaltLockFn installHaltLock = NULL;
    UninstallHaltLockFn uninstallHaltLock = NULL;
    HaltLockHeartbeatFn haltLockHeartbeat = NULL;
    HaltLockAllowFn haltLockAllow = NULL;
    FilterAuditFn filterAudit = NULL;
    InstallSelfTerminateGuardFn installSelfTerminateGuard = NULL;
    VerifyHookIntegrityFn verifyHookIntegrity = NULL;
};

struct AgentLockState {
    bool locked = false;
    ULONGLONG lockUntilTick = 0;
    unsigned long long ownerPid = 0ULL;
};

/* Pre-authorized target-JVM termination handle. It is acquired before the
 * target's DACL is tightened, so FVM retains its controlled exit path. */
static std::mutex g_jvmControlMutex;
static HANDLE g_jvmControlHandle = NULL;
static DWORD g_jvmControlPid = 0;

/* PID of the target most recently bootstrapped by the post-relaunch or
 * recovery watcher. Lets handleBootstrap skip a redundant OpenProcess
 * call that would fail under the comprehensive DACL. */
static std::atomic<DWORD> g_watchdogBootstrappedPid{0};


/* Self-DACL hardening: deny the full set of dangerous access rights to
 * Everyone on our own process object. This blocks same-user non-admin
 * kills, injection, memory scanning, handle theft, and thread suspension.
 * The agent operates via GetCurrentProcess() (pseudo-handle, bypasses DACL)
 * so its own functionality is unaffected. Admin with TakeOwnership can
 * still override. */
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

    static const DWORD kSelfDeniedRights =
        PROCESS_TERMINATE |
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_SUSPEND_RESUME |
        WRITE_DAC;

    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = kSelfDeniedRights;
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

/* Comprehensive process hardening: deny the full set of dangerous access
 * rights to new handle opens on the target JVM. The agent retains a handle
 * opened before this DACL change, so its own RPM/WPM/VirtualProtectEx
 * operations are unaffected.
 *
 * Denied rights and their rationale:
 *   PROCESS_TERMINATE      — TerminateProcess / NtTerminateProcess from outside
 *   PROCESS_CREATE_THREAD  — CreateRemoteThread (shellcode injection)
 *   PROCESS_VM_OPERATION   — VirtualProtectEx / VirtualAllocEx (memory tampering)
 *   PROCESS_VM_READ        — ReadProcessMemory (hook scanning, handle discovery)
 *   PROCESS_VM_WRITE       — WriteProcessMemory (direct byte patching)
 *   PROCESS_DUP_HANDLE     — DuplicateHandle (stealing the agent's retained handle)
 *   PROCESS_SUSPEND_RESUME — NtSuspendProcess / NtResumeProcess (thread freeze DoS)
 *   WRITE_DAC              — SetSecurityInfo (removing these very protections)
 *
 * Boundary: handles that already existed before the DACL change, an
 * administrator with TakeOwnership/SeDebugPrivilege, and kernel code are
 * outside its protection model. */
static bool lockJvmProcessDACL(HANDLE process, DWORD pid) {
    PACL oldDacl = NULL;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    if (GetSecurityInfo(process, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &oldDacl, NULL, &securityDescriptor) != ERROR_SUCCESS) {
        return false;
    }

    PSID everyone = NULL;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&authority, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &everyone)) {
        if (securityDescriptor) LocalFree(securityDescriptor);
        return false;
    }

    static const DWORD kDeniedRights =
        PROCESS_TERMINATE |
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_SUSPEND_RESUME |
        WRITE_DAC;

    EXPLICIT_ACCESSW denyAll = {};
    denyAll.grfAccessPermissions = kDeniedRights;
    denyAll.grfAccessMode = DENY_ACCESS;
    denyAll.grfInheritance = NO_INHERITANCE;
    denyAll.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAll.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    denyAll.Trustee.ptstrName = reinterpret_cast<LPWSTR>(everyone);

    PACL newDacl = NULL;
    bool ok = false;
    if (SetEntriesInAclW(1, &denyAll, oldDacl, &newDacl) == ERROR_SUCCESS) {
        ok = SetSecurityInfo(process, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                             NULL, NULL, newDacl, NULL) == ERROR_SUCCESS;
    }
    if (newDacl) LocalFree(newDacl);
    if (everyone) FreeSid(everyone);
    if (securityDescriptor) LocalFree(securityDescriptor);
    if (ok) AGENT_LOG("guard: comprehensive DACL applied to JVM pid=%lu (terminate/vm/createthread/suspend/duphandle/writedac denied)", pid);
    return ok;
}

static void clearJvmControlHandle() {
    std::lock_guard<std::mutex> guard(g_jvmControlMutex);
    if (g_jvmControlHandle != NULL) CloseHandle(g_jvmControlHandle);
    g_jvmControlHandle = NULL;
    g_jvmControlPid = 0;
    g_watchdogBootstrappedPid.store(0);
}

static bool retainAndLockJvm(HANDLE process, DWORD pid) {
    HANDLE retained = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &retained,
                         PROCESS_TERMINATE | SYNCHRONIZE, FALSE, 0)) {
        AGENT_LOG("guard: unable to retain JVM control handle for pid=%lu: %lu", pid, GetLastError());
        return false;
    }
    if (!lockJvmProcessDACL(process, pid)) {
        CloseHandle(retained);
        AGENT_LOG("guard: unable to lock JVM DACL for pid=%lu: %lu", pid, GetLastError());
        return false;
    }
    std::lock_guard<std::mutex> guard(g_jvmControlMutex);
    if (g_jvmControlHandle != NULL) CloseHandle(g_jvmControlHandle);
    g_jvmControlHandle = retained;
    g_jvmControlPid = pid;
    return true;
}

static bool restoreJvmControlHandle(HANDLE authorizedHandle, DWORD pid) {
    HANDLE retained = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), authorizedHandle, GetCurrentProcess(), &retained,
                         PROCESS_TERMINATE | SYNCHRONIZE, FALSE, 0)) return false;
    std::lock_guard<std::mutex> guard(g_jvmControlMutex);
    if (g_jvmControlHandle != NULL) CloseHandle(g_jvmControlHandle);
    g_jvmControlHandle = retained;
    g_jvmControlPid = pid;
    return true;
}

static HANDLE duplicateJvmControlHandle(DWORD pid) {
    std::lock_guard<std::mutex> guard(g_jvmControlMutex);
    if (g_jvmControlHandle == NULL || g_jvmControlPid != pid) return NULL;
    HANDLE duplicate = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), g_jvmControlHandle, GetCurrentProcess(), &duplicate,
                         PROCESS_TERMINATE | SYNCHRONIZE, FALSE, 0)) return NULL;
    return duplicate;
}

// Parent process watchdog: exits agent when parent JVM dies
static std::atomic<DWORD> g_parentPid{0};
/* Guard is intentionally opt-in: it is only armed by --lock-jvm, which Java
 * validates as requiring the control window. */
static std::atomic<bool> g_guardMode{false};
static std::atomic<bool> g_guardAuthorizedExit{false};
static std::atomic<bool> g_guardRecoveryRunning{false};
static std::atomic<unsigned long long> g_haltLockTrampolineAddr{0};
static std::atomic<unsigned long long> g_guardGeneration{0};
static std::mutex g_guardMutex;
static std::wstring g_guardCommandLine;
/* Immutable launch source for relaunch v2. Captured once from the first JVM
 * that bootstraps this supervisor and never replaced by handoff/recovery JVMs. */
struct SealedLaunchBaseline {
    std::wstring commandLine;
    std::wstring workingDirectory;
    std::vector<wchar_t> environment;
    bool sealed = false;
};
static SealedLaunchBaseline g_launchBaseline;
static std::atomic<unsigned long long> g_secureRelaunchGeneration{0};
/* True while the original JVM is intentionally parked waiting for the trusted
 * replacement's policy-applied handshake. Zero CPU in this interval is normal,
 * not a deadlock/stall signal. */
static std::atomic<bool> g_secureRelaunchPending{false};
static std::vector<std::wstring> g_secureRecoveryTokens;
static bool g_secureRecoveryEnvironmentSanitized = true;
static std::string g_secureRelaunchPolicyFingerprint;
/* Consecutive unexpected JVM deaths without a stable recovery in between.
 * Reset on successful handoff bootstrap. Agent exits after kGuardMaxDeaths. */
static std::atomic<int> g_guardConsecutiveDeaths{0};
static const int kGuardMaxConsecutiveDeaths = 4;
/* Bootstrap completion is not a stable recovery: hostile startup code can
 * terminate the new JVM a few seconds after its hooks are installed. */
static std::atomic<ULONGLONG> g_guardRecoveryStableSinceTick{0};
static const ULONGLONG kGuardStableRecoveryMs = 30000ULL;

static std::wstring queryProcessCommandLine(DWORD pid);
static std::vector<wchar_t> captureEnvironmentBlock();
static void autoRelaunchAfterCrash(DWORD deadPid);

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
                hParent = duplicateJvmControlHandle(pid);
                if (hParent == NULL) hParent = OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (hParent == NULL) {
                    DWORD error = GetLastError();
                    if (g_guardMode.load() &&
                        (error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND)) {
                        AGENT_LOG("guard: tracked JVM pid=%lu disappeared before watchdog handle: %lu",
                                  pid, error);
                        clearJvmControlHandle();
                        autoRelaunchAfterCrash(pid);
                    }
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
        DWORD observedExitCode = STILL_ACTIVE;
        if (!GetExitCodeProcess(hParent, &observedExitCode)) {
            observedExitCode = 0xFFFFFFFFUL;
        }
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
        if (g_guardMode.load() && !g_guardAuthorizedExit.load()) {
            /* The JVM died without the FVM relaunch handoff. The guard owns
             * recovery (up to kGuardMaxConsecutiveDeaths attempts) and will
             * either publish a new pid or fail closed. */
            AGENT_LOG("guard: JVM pid=%lu exited unexpectedly with code=0x%08lX", lastPid,
                      observedExitCode);
            clearJvmControlHandle();
            autoRelaunchAfterCrash(lastPid);
            lastPid = 0;
            continue;
        }
        /* JVM died without guard or relaunch. In window mode, log and exit
         * cleanly (the operator had the window up for monitoring). Without a
         * window, just exit immediately — no zombie agents. */
        if (g_windowEnabled.load()) {
            AGENT_LOG("watchdog: JVM pid=%lu exited — agent shutting down", lastPid);
            windowPublish("[JVM] target JVM (pid " + std::to_string(lastPid) +
                          ") exited — FVM shutting down");
            g_jvmDiedPostMortem.store(true);
            return 0;   /* stop watching; main() will exit cleanly */
        }
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
    /* `length` includes the trailing NUL because cbMultiByte is -1.  Keep room
     * for it while converting, then remove it from the C++ string. */
    std::wstring wide(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], length);
    wide.resize(length - 1);
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
    /* `len` also includes the terminating NUL when cchWideChar is -1. */
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, NULL, NULL);
    utf8.resize(len - 1);
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

/* When non-null (set per command-pipe connection), a command reply is appended
 * here instead of written to std::cout; the connection thread then sends the
 * captured reply back over its own pipe. This is what lets multiple JVM
 * classloaders each hold an independent command channel to the single agent —
 * the gen0 (parent-stdio) path leaves it null and replies via std::cout. */
thread_local std::string* tls_replySink = nullptr;

static void emitReply(const std::string& json) {
    if (tls_replySink != nullptr) {
        *tls_replySink += json;
        tls_replySink->push_back('\n');
    } else {
        std::cout << json << std::endl;
    }
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
    emitReply(oss.str());
}

void printResult(const char* status,
                 const char* capability,
                 const std::string& dllPath,
                 const char* reason) {
    AGENT_LOG("command result: status=%s capability=%s reason=%s",
              status ? status : "", capability ? capability : "", reason ? reason : "");
    std::ostringstream oss;
    oss << "{\"status\":\"" << escapeJson(status)
        << "\",\"capability\":\"" << escapeJson(capability)
        << "\",\"dllPath\":\"" << escapeJson(dllPath)
        << "\",\"reason\":\"" << escapeJson(reason) << "\"}";
    emitReply(oss.str());
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

/* Returns the index of the matching '}' for the '{' at openIdx, or npos.
 * String/escape-aware so quoted braces don't confuse depth counting. */
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

/* Extract the contents of "key":[...] (between [ and ], exclusive). Returns
 * empty string if the array is absent or malformed. String/escape-aware. */
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

/* Iterate top-level JSON objects in arrayInner, calling cb with each object's
 * substring (including the outer braces). Other characters between objects
 * (commas, whitespace) are skipped. */
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
    api->bootstrapTargetWithHandle = reinterpret_cast<BootstrapTargetWithHandleFn>(GetProcAddress(module, "forgevm_bootstrap_target_with_handle"));
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
    api->banJvmti        = reinterpret_cast<BanJvmtiFn>(GetProcAddress(module, "forgevm_ban_jvmti"));
    api->unbanJvmti      = reinterpret_cast<UnbanJvmtiFn>(GetProcAddress(module, "forgevm_unban_jvmti"));
    api->banProcessCreate   = reinterpret_cast<BanProcessCreateFn>(GetProcAddress(module, "forgevm_ban_process_create"));
    api->unbanProcessCreate = reinterpret_cast<UnbanProcessCreateFn>(GetProcAddress(module, "forgevm_unban_process_create"));
    api->forgeClassPlan   = reinterpret_cast<ForgeClassPlanFn>(GetProcAddress(module, "forgevm_forge_class_plan"));
    api->forgeClassUnload = reinterpret_cast<ForgeClassUnloadFn>(GetProcAddress(module, "forgevm_forge_class_unload"));
    api->installHaltLock    = reinterpret_cast<InstallHaltLockFn>(GetProcAddress(module, "forgevm_install_halt_lock"));
    api->uninstallHaltLock  = reinterpret_cast<UninstallHaltLockFn>(GetProcAddress(module, "forgevm_uninstall_halt_lock"));
    api->haltLockHeartbeat  = reinterpret_cast<HaltLockHeartbeatFn>(GetProcAddress(module, "forgevm_halt_lock_heartbeat"));
    api->haltLockAllow      = reinterpret_cast<HaltLockAllowFn>(GetProcAddress(module, "forgevm_halt_lock_allow"));
    api->filterAudit        = reinterpret_cast<FilterAuditFn>(GetProcAddress(module, "forgevm_filter_audit"));
    api->installSelfTerminateGuard = reinterpret_cast<InstallSelfTerminateGuardFn>(GetProcAddress(module, "forgevm_install_self_terminate_guard"));
    api->verifyHookIntegrity      = reinterpret_cast<VerifyHookIntegrityFn>(GetProcAddress(module, "forgevm_verify_hook_integrity"));

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
        std::wstring observedCommandLine = queryProcessCommandLine(static_cast<DWORD>(pid));
        {
            std::lock_guard<std::mutex> guard(g_guardMutex);
            if (!g_launchBaseline.sealed && !observedCommandLine.empty()) {
                g_launchBaseline.commandLine = observedCommandLine;
                DWORD cwdLength = GetCurrentDirectoryW(0, NULL);
                if (cwdLength > 0) {
                    std::vector<wchar_t> cwd(cwdLength);
                    if (GetCurrentDirectoryW(cwdLength, cwd.data()) > 0) {
                        g_launchBaseline.workingDirectory.assign(cwd.data());
                    }
                }
                g_launchBaseline.environment = captureEnvironmentBlock();
                g_launchBaseline.sealed = true;
                AGENT_LOG("relaunch-v2: sealed first-launch baseline (cmd=%zu, env=%zu)",
                          g_launchBaseline.commandLine.size(), g_launchBaseline.environment.size());
            }
        }
        if (g_guardMode.load()) {
            std::wstring cmd = std::move(observedCommandLine);
            if (!cmd.empty()) {
                std::lock_guard<std::mutex> guard(g_guardMutex);
                g_guardCommandLine = std::move(cmd);
                AGENT_LOG("guard: cached command line for pid=%llu", pid);
            } else {
                AGENT_LOG("guard: failed to cache command line for pid=%llu", pid);
            }
        }
    }
    if (pid != 0ULL && api.bootstrapTarget != NULL) {
        if (g_guardMode.load() && g_watchdogBootstrappedPid.load() == static_cast<DWORD>(pid)) {
            structMapReady = true;
            AGENT_LOG("bootstrap_target skipped: pid=%llu already bootstrapped by recovery watcher", pid);
        } else {
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
    }
    bool jvmLockActive = !g_guardMode.load();
    if (pid != 0ULL && g_guardMode.load()) {
        /* A handoff/recovered JVM was already locked before resume. Do not try
         * to OpenProcess(PROCESS_TERMINATE) again: our own DACL correctly
         * rejects that new handle and used to make this bootstrap falsely
         * report UNAVAILABLE, causing Java to send the agent a shutdown. */
        HANDLE retained = duplicateJvmControlHandle(static_cast<DWORD>(pid));
        if (retained != NULL) {
            CloseHandle(retained);
            jvmLockActive = true;
            AGENT_LOG("guard: reusing retained JVM control handle for pid=%llu", pid);
        } else {
            HANDLE control = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC,
                                         FALSE, static_cast<DWORD>(pid));
            if (control != NULL) {
                jvmLockActive = retainAndLockJvm(control, static_cast<DWORD>(pid));
                CloseHandle(control);
            }
            if (!jvmLockActive) {
                /* Keep the agent and watchdog alive. A protection upgrade
                 * failure must never be converted into an agent shutdown. */
                AGENT_LOG("guard: JVM DACL lock unavailable for pid=%llu; watchdog remains active", pid);
            }
        }
    }

    /* Install JVM_Halt hook so Shutdown.halt() cannot bypass the DACL lock.
     * FVM-authorized termination uses TerminateProcess on the retained handle
     * and never touches JVM_Halt. */
    bool haltLockInstalled = false;
    if (jvmLockActive && api.installHaltLock != NULL) {
        unsigned long long addr = api.installHaltLock();
        if (addr != 0ULL) {
            g_haltLockTrampolineAddr.store(addr);
            haltLockInstalled = true;
            AGENT_LOG("guard: JVM_Halt lock installed @ 0x%llX", addr);
        } else {
            AGENT_LOG("guard: JVM_Halt lock install failed: %s",
                      api.lastError ? api.lastError() : "unknown");
        }
    }

    bool selfTerminateGuardInstalled = false;
    if (jvmLockActive && api.installSelfTerminateGuard != NULL) {
        int result = api.installSelfTerminateGuard();
        selfTerminateGuardInstalled = result == 1;
        AGENT_LOG("guard: NtTerminateProcess in-target guard %s%s",
                  selfTerminateGuardInstalled ? "installed" : "install failed",
                  selfTerminateGuardInstalled ? "" : (api.lastError ? api.lastError() : ""));
    }

    std::vector<std::pair<std::string, std::string>> fields;
    fields.push_back({"structMapReady", structMapReady ? "true" : "false"});
    fields.push_back({"jvmLockActive", jvmLockActive ? "true" : "false"});
    fields.push_back({"haltLockInstalled", haltLockInstalled ? "true" : "false"});
    fields.push_back({"selfTerminateGuardInstalled", selfTerminateGuardInstalled ? "true" : "false"});
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
    /* Unlock JVM_Halt so in-process termination is not blocked. */
    if (api.haltLockAllow != NULL) {
        api.haltLockAllow();
    }
    HANDLE locked = duplicateJvmControlHandle(static_cast<DWORD>(pid));
    if (locked != NULL) {
        ok = TerminateProcess(locked, static_cast<UINT>(code)) == TRUE;
        CloseHandle(locked);
        clearJvmControlHandle();
    } else if (!g_guardMode.load() && api.exitByPid != NULL) {
        ok = api.exitByPid(pid, static_cast<int>(code)) == 1;
    } else if (!g_guardMode.load()) {
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

/* ============================================================
 * forge_batch_plan: per-class plan-once-commit-once entry point
 * ============================================================ */

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

/* Parse a forgevm_forge_class_plan results JSON ("[{matched:..,...}, ...]")
 * into a vector of PerIngotResult that parallels the input order. */
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
        /* §17 Stage 3: group ingots by (targetClass, includeSubclasses) and
         * commit each class as one plan-once-commit-once operation. All
         * commits defer deopt; we run a single global deopt sweep at the end. */
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
    /* Route through emitReply, not std::cout: after handoff this runs on a
     * command-pipe connection thread whose reply must go to that pipe (via the
     * thread-local sink), not the dead inherited stdout. Writing to std::cout
     * here would leave the client's readLine() at EOF → agent_send_failed. */
    emitReply(oss.str());
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
    emitReply(oss.str());
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

/* ============================================================
 * Load-filter state (Java agent attach + native library load)
 *
 * Filter storage is Agent-local — enforcement arrives in later steps:
 *   step 3: JVM_EnqueueOperation trampoline consults g_javaAgentFilter
 *   step 4: ntdll!LdrLoadDll trampoline consults g_nativeLoadFilter
 * ============================================================ */

enum class FilterMode { None, Blacklist, Whitelist };

struct LoadFilter {
    FilterMode mode = FilterMode::None;
    std::vector<std::string> patterns;
    bool active = false;
};

LoadFilter g_javaAgentFilter;
LoadFilter g_nativeLoadFilter;
LoadFilter g_jvmtiFilter;
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

/* Pack a filter's patterns for the in-process-matching DLL exports: mode int
 * (matches FilterMode's underlying 0/1/2) + patterns joined by '\n'. */
std::string joinPatternsLF(const LoadFilter& f) {
    std::string s;
    for (size_t i = 0; i < f.patterns.size(); i++) {
        if (i) s.push_back('\n');
        s += f.patterns[i];
    }
    return s;
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

/* true = allow the load, false = block it.
 * Semantics:
 *   filter inactive           → allow (ForgeVM never installed a filter)
 *   active + mode==None       → block everything (global ban, no patterns)
 *   active + Blacklist+match  → block; otherwise allow
 *   active + Whitelist+match  → allow; otherwise block */
bool filterAllows(const LoadFilter& f, const std::string& path) {
    if (!f.active) return true;
    if (f.mode == FilterMode::None) return false;
    bool matched = false;
    for (const auto& pat : f.patterns) {
        if (globMatch(pat, path)) { matched = true; break; }
    }
    return (f.mode == FilterMode::Blacklist) ? !matched : matched;
}

/* ============================================================
 * Named-pipe server: trampolines in the target JVM connect here
 * to ask "is this path allowed?" before calling the real JVM entry.
 *
 * Protocol (one request per connection, blocking):
 *   request : <kind:1 byte 'A'|'N'|'P'> <path:UTF-8 bytes> <0x0A>
 *   reply   : <decision:1 byte '1'=allow | '0'=block>
 *
 * 'A' queries g_javaAgentFilter, 'N' queries g_nativeLoadFilter,
 * 'P' queries g_processCreateFilter.
 * Pipe name: \\.\pipe\forgevm_<jvm_pid>_filter
 * ============================================================ */

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

/* The command pipe is a control boundary, not a public local RPC endpoint.
 * Every accepted client must be the JVM currently supervised by this agent.
 * This does not attempt to distinguish code already injected into that JVM
 * (which has the target's authority), but it prevents another local process
 * from connecting by name and issuing policy-removal commands. */
static bool isExpectedCommandPipeClient(HANDLE pipe) {
    const DWORD expectedPid = g_parentPid.load();
    DWORD clientPid = 0;
    if (expectedPid == 0 || !GetNamedPipeClientProcessId(pipe, &clientPid)) {
        AGENT_LOG("command pipe: unable to identify client (expected=%lu, err=%lu)",
                  (unsigned long)expectedPid, (unsigned long)GetLastError());
        return false;
    }
    if (clientPid != expectedPid) {
        AGENT_LOG("command pipe: rejected client pid=%lu (expected=%lu)",
                  (unsigned long)clientPid, (unsigned long)expectedPid);
        return false;
    }
    return true;
}

static std::string buildCommandPipeName() {
    char buf[64];
    sprintf_s(buf, sizeof(buf), "\\\\.\\pipe\\forgevm_cmd_%lu",
              (unsigned long)GetCurrentProcessId());
    return std::string(buf);
}

/* Idempotent: creates the first instance of the command pipe and stashes it
 * in g_commandPipeServer. Returns true on success. PIPE_UNLIMITED_INSTANCES so
 * multiple JVM classloaders can each hold an independent command channel — the
 * post-handoff server accepts further instances on demand. */
static bool ensureCommandPipeCreated() {
    if (g_commandPipeServer != INVALID_HANDLE_VALUE) return true;
    g_commandPipeName = buildCommandPipeName();
    HANDLE pipe = CreateNamedPipeA(
        g_commandPipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
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
        if (!isExpectedCommandPipeClient(pipe)) {
            DisconnectNamedPipe(pipe);
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
        if (isExpectedCommandPipeClient(pipe)) {
            result = pipe;
        } else {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
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

/* Start the filter pipe server (idempotent). Synchronously creates the
 * first pipe instance before spawning the accept thread so that the
 * trampoline's CreateFileA can never race the server's first listen.
 * Returns the pipe name on success, or an empty string if start failed. */
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
    LoadFilter desired;
    applyFilterFromJson(&desired, line);
    const int mode = static_cast<int>(desired.mode);
    const std::string joined = joinPatternsLF(desired);
    const size_t patternCount = desired.patterns.size();
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_javaAgentFilter.active;
    }
    if (api.banJavaAgent == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_java_agent_not_exported");
        return;
    }
    /* In-process match: DLL installs the hook on first call, refreshes the
     * resident pattern blob in place on later calls — no filter pipe. */
    int r = api.banJavaAgent(mode, joined.c_str());
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_javaAgentFilter = std::move(desired);
    }
    AGENT_LOG("ban_java_agent: mode=%s patterns=%zu%s result=%d",
              filterModeName(static_cast<FilterMode>(mode)), patternCount,
              wasActive ? " (updated)" : "", r);
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanJavaAgent(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_javaAgentFilter.active;
    }
    AGENT_LOG("unban_java_agent: requested (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanJavaAgent == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_java_agent_not_exported");
        return;
    }
    int r = api.unbanJavaAgent();
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_javaAgentFilter = LoadFilter{};
    }
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleBanNativeLoad(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    LoadFilter desired;
    applyFilterFromJson(&desired, line);
    const int mode = static_cast<int>(desired.mode);
    const std::string joined = joinPatternsLF(desired);
    const size_t patternCount = desired.patterns.size();
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_nativeLoadFilter.active;
    }
    if (api.banNativeLoad == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_native_load_not_exported");
        return;
    }
    /* The DLL installs the trampoline on first call and refreshes the resident
     * pattern blob in place on subsequent calls — both decided in-process, so
     * no filter pipe is involved. */
    int r = api.banNativeLoad(mode, joined.c_str());
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_nativeLoadFilter = std::move(desired);
    }
    AGENT_LOG("ban_native_load: mode=%s patterns=%zu%s result=%d",
              filterModeName(static_cast<FilterMode>(mode)), patternCount,
              wasActive ? " (updated)" : "", r);
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanNativeLoad(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_nativeLoadFilter.active;
    }
    AGENT_LOG("unban_native_load: requested (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanNativeLoad == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_native_load_not_exported");
        return;
    }
    int r = api.unbanNativeLoad();
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_nativeLoadFilter = LoadFilter{};
    }
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleBanJvmti(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    LoadFilter desired;
    applyFilterFromJson(&desired, line);
    const int mode = static_cast<int>(desired.mode);
    const std::string joined = joinPatternsLF(desired);
    if (api.banJvmti == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_jvmti_not_exported");
        return;
    }
    int r = api.banJvmti(mode, joined.c_str());
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_jvmtiFilter = std::move(desired);
    }
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanJvmti(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_jvmtiFilter.active;
    }
    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanJvmti == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_jvmti_not_exported");
        return;
    }
    int r = api.unbanJvmti();
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_jvmtiFilter = LoadFilter{};
    }
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleBanProcessCreate(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    LoadFilter desired;
    applyFilterFromJson(&desired, line);
    const int mode = static_cast<int>(desired.mode);
    const std::string joined = joinPatternsLF(desired);
    const size_t patternCount = desired.patterns.size();
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_processCreateFilter.active;
    }
    if (api.banProcessCreate == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "ban_process_create_not_exported");
        return;
    }
    int r = api.banProcessCreate(mode, joined.c_str());
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_processCreateFilter = std::move(desired);
    }
    AGENT_LOG("ban_process_create: mode=%s patterns=%zu%s result=%d",
              filterModeName(static_cast<FilterMode>(mode)), patternCount,
              wasActive ? " (updated)" : "", r);
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

void handleUnbanProcessCreate(const NativeApi& api, const std::string& dllPath) {
    bool wasActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasActive = g_processCreateFilter.active;
    }
    AGENT_LOG("unban_process_create: requested (wasActive=%d)", (int)wasActive);

    if (!wasActive) {
        printResult("ok", "FULL", dllPath, "already_unbanned");
        return;
    }
    if (api.unbanProcessCreate == NULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "unban_process_create_not_exported");
        return;
    }
    int r = api.unbanProcessCreate();
    if (r) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_processCreateFilter = LoadFilter{};
    }
    printResult(r ? "ok" : "fallback", r ? "FULL" : "UNAVAILABLE", dllPath,
                api.lastError ? api.lastError() : "unknown");
}

/* ============================================================
 * relaunch: WMI cmdline query → filter → TerminateProcess + CreateProcessW
 * ============================================================ */

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

static std::vector<wchar_t> captureEnvironmentBlock() {
    std::vector<wchar_t> out;
    LPWCH block = GetEnvironmentStringsW();
    if (block == NULL) return out;
    const wchar_t* p = block;
    while (*p != L'\0') {
        size_t len = wcslen(p) + 1;
        out.insert(out.end(), p, p + len);
        p += len;
    }
    out.push_back(L'\0');
    FreeEnvironmentStringsW(block);
    return out;
}

static bool blockedJavaEnvironmentEntry(const wchar_t* entry) {
    if (entry == NULL || entry[0] == L'=') return false;
    const wchar_t* eq = wcschr(entry, L'=');
    size_t keyLen = eq == NULL ? wcslen(entry) : static_cast<size_t>(eq - entry);
    static const wchar_t* const blocked[] = {
        L"JAVA_TOOL_OPTIONS", L"JDK_JAVA_OPTIONS", L"_JAVA_OPTIONS", L"CLASSPATH"
    };
    for (const wchar_t* key : blocked) {
        if (keyLen == wcslen(key) && _wcsnicmp(entry, key, keyLen) == 0) return true;
    }
    return false;
}

static std::vector<wchar_t> sanitizeEnvironmentBlock(const std::vector<wchar_t>& source) {
    std::vector<wchar_t> out;
    const wchar_t* p = source.empty() ? NULL : source.data();
    while (p != NULL && *p != L'\0') {
        size_t len = wcslen(p) + 1;
        if (!blockedJavaEnvironmentEntry(p)) out.insert(out.end(), p, p + len);
        p += len;
    }
    out.push_back(L'\0');
    return out;
}

static std::vector<std::wstring> tokenizeCmdLineWindows(const std::wstring& cmdline) {
    std::vector<std::wstring> tokens;
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(cmdline.c_str(), &argc);
    if (argv == NULL) return tokens;
    for (int i = 0; i < argc; ++i) tokens.emplace_back(argv[i]);
    LocalFree(argv);
    return tokens;
}

/* Windows command-line quoting compatible with CommandLineToArgvW and the
 * Microsoft C runtime parser, including backslashes immediately before quotes. */
static std::wstring quoteWindowsArgument(const std::wstring& value) {
    if (!value.empty() && value.find_first_of(L" \t\n\v\"") == std::wstring::npos) return value;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
        } else if (ch == L'\"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'\"');
            slashes = 0;
        } else {
            out.append(slashes, L'\\');
            slashes = 0;
            out.push_back(ch);
        }
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

static std::wstring joinWindowsCommandLine(const std::vector<std::wstring>& tokens) {
    std::wstring result;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i != 0) result.push_back(L' ');
        result += quoteWindowsArgument(tokens[i]);
    }
    return result;
}

static std::string sha256FileHex(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return std::string();
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD objectLength = 0, hashLength = 0, cb = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                                reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &cb, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                                                reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &cb, 0);
    if (status >= 0) {
        object.resize(objectLength);
        digest.resize(hashLength);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength, NULL, 0, 0);
    }
    unsigned char buffer[64 * 1024];
    while (status >= 0) {
        DWORD read = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) { status = -1; break; }
        if (read == 0) break;
        status = BCryptHashData(hash, buffer, read, 0);
    }
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), hashLength, 0);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    if (status < 0 || digest.size() != 32) return std::string();
    static const char hex[] = "0123456789abcdef";
    std::string result(64, '0');
    for (size_t i = 0; i < digest.size(); ++i) {
        result[i * 2] = hex[digest[i] >> 4];
        result[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
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
        L"-Dforgevm.relaunch.readyPipe=",
        L"-Dforgevm.relaunch.readyNonce=",
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

static bool startsWithInsensitive(const std::wstring& value, const wchar_t* prefix) {
    size_t len = wcslen(prefix);
    return value.size() >= len && _wcsnicmp(value.c_str(), prefix, len) == 0;
}

static std::string relaunchPolicyFingerprint(std::string line) {
    const std::string marker = "\"pid\":";
    size_t start = line.find(marker);
    if (start == std::string::npos) return line;
    start += marker.size();
    size_t end = start;
    while (end < line.size() && line[end] >= '0' && line[end] <= '9') ++end;
    line.replace(start, end - start, "0");
    return line;
}

static std::string randomNonceHex() {
    unsigned char bytes[16];
    if (BCryptGenRandom(NULL, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return std::string();
    }
    static const char hex[] = "0123456789abcdef";
    std::string result(sizeof(bytes) * 2, '0');
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        result[i * 2] = hex[bytes[i] >> 4];
        result[i * 2 + 1] = hex[bytes[i] & 15];
    }
    return result;
}

static bool verifyTrustedAgent(const std::string& pathUtf8, const std::string& expectedHash,
                               std::wstring* pathWide, const char** reason) {
    if (pathUtf8.empty() || expectedHash.size() != 64) {
        *reason = "trusted_agent_spec_invalid";
        return false;
    }
    *pathWide = toWide(pathUtf8);
    if (pathWide->empty()) {
        *reason = "trusted_agent_path_invalid";
        return false;
    }
    std::string actual = sha256FileHex(*pathWide);
    if (actual.empty()) {
        *reason = "trusted_agent_unreadable";
        return false;
    }
    std::string expected = expectedHash;
    for (char& c : expected) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    if (actual != expected) {
        *reason = "trusted_agent_hash_mismatch";
        return false;
    }
    return true;
}

static bool waitForReadyPipe(HANDLE pipe, HANDLE process, OVERLAPPED* connect,
                             const std::string& expectedNonce, DWORD timeoutMs) {
    HANDLE waits[2] = { connect->hEvent, process };
    DWORD wait = WaitForMultipleObjects(2, waits, FALSE, timeoutMs);
    if (wait != WAIT_OBJECT_0) return false;
    DWORD transferred = 0;
    if (!GetOverlappedResult(pipe, connect, &transferred, FALSE)
            && GetLastError() != ERROR_PIPE_CONNECTED) return false;
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    char buffer[256];
    while (GetTickCount64() < deadline) {
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return false;
        DWORD available = 0;
        if (PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL) && available > 0) {
            DWORD read = 0;
            if (!ReadFile(pipe, buffer, static_cast<DWORD>(std::min<size_t>(available, sizeof(buffer) - 1)),
                          &read, NULL)) return false;
            buffer[read] = '\0';
            std::string received(buffer, read);
            while (!received.empty() && (received.back() == '\r' || received.back() == '\n')) received.pop_back();
            return received == expectedNonce;
        }
        Sleep(10);
    }
    return false;
}

static bool installRelaunchFilters(const NativeApi& api, HANDLE process, DWORD pid,
                                   bool installAgent, bool installNative,
                                   bool installJvmti, bool installProcess) {
    if (api.bootstrapTargetWithHandle == NULL
            || api.bootstrapTargetWithHandle(static_cast<unsigned long long>(pid), process) != 1) {
        return false;
    }
    g_watchdogBootstrappedPid.store(pid);
    auto apply = [&](bool enabled, const LoadFilter& filter, auto fn) -> bool {
        if (!enabled) return true;
        if (fn == NULL) return false;
        return fn(static_cast<int>(filter.mode), joinPatternsLF(filter).c_str()) == 1;
    };
    std::lock_guard<std::mutex> g(g_filterMutex);
    return apply(installNative, g_nativeLoadFilter, api.banNativeLoad)
        && apply(installAgent, g_javaAgentFilter, api.banJavaAgent)
        && apply(installJvmti, g_jvmtiFilter, api.banJvmti)
        && apply(installProcess, g_processCreateFilter, api.banProcessCreate);
}

static void handleRelaunchV2(const NativeApi& api, const std::string& line,
                             const std::string& dllPath) {
    unsigned long long pid64 = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid64 == 0ULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_pid");
        return;
    }
    DWORD oldPid = static_cast<DWORD>(pid64);
    g_secureRelaunchPending.store(true);
    struct RelaunchPendingReset {
        ~RelaunchPendingReset() { g_secureRelaunchPending.store(false); }
    } pendingReset;
    std::string policyFingerprint = relaunchPolicyFingerprint(line);
    std::wstring baselineCommand;
    std::wstring baselineCwd;
    std::vector<wchar_t> baselineEnvironment;
    {
        std::lock_guard<std::mutex> guard(g_guardMutex);
        if (!g_launchBaseline.sealed) {
            printResult("fallback", "UNAVAILABLE", dllPath, "launch_baseline_not_sealed");
            return;
        }
        baselineCommand = g_launchBaseline.commandLine;
        baselineCwd = g_launchBaseline.workingDirectory;
        baselineEnvironment = g_launchBaseline.environment;
        if (!g_secureRelaunchPolicyFingerprint.empty()
                && g_secureRelaunchPolicyFingerprint != policyFingerprint) {
            printResult("fallback", "UNAVAILABLE", dllPath, "relaunch_policy_already_sealed");
            return;
        }
    }

    std::vector<std::wstring> original = tokenizeCmdLineWindows(baselineCommand);
    if (original.empty()) {
        printResult("fallback", "UNAVAILABLE", dllPath, "baseline_parse_failed");
        return;
    }
    if (getJsonBoolField(line, "rejectArgumentFiles", true)) {
        for (const std::wstring& token : original) {
            if (!token.empty() && token[0] == L'@') {
                printResult("fallback", "UNAVAILABLE", dllPath, "argument_file_rejected");
                return;
            }
        }
    }

    bool hasAgentFilter = getJsonBoolField(line, "hasAgentFilter", false);
    bool hasNativeFilter = getJsonBoolField(line, "hasNativeFilter", false);
    bool hasJvmtiFilter = getJsonBoolField(line, "hasJvmtiFilter", false);
    bool hasProcessFilter = getJsonBoolField(line, "hasProcessFilter", false);
    LoadFilter agentFlt, nativeFlt, jvmtiFlt, processFlt;
    auto parseFilter = [&](LoadFilter& filter, const char* modeKey, const char* patternsKey) {
        std::string mode = getJsonStringField(line, modeKey);
        filter.patterns = parseJsonStringArray(line, patternsKey);
        filter.mode = mode == "whitelist" ? FilterMode::Whitelist : FilterMode::Blacklist;
        filter.active = true;
    };
    if (hasAgentFilter) parseFilter(agentFlt, "agentMode", "agentPatterns");
    if (hasNativeFilter) parseFilter(nativeFlt, "nativeMode", "nativePatterns");
    if (hasJvmtiFilter) parseFilter(jvmtiFlt, "jvmtiMode", "jvmtiPatterns");
    if (hasProcessFilter) parseFilter(processFlt, "processMode", "processPatterns");

    std::string existingPolicy = getJsonStringField(line, "existingAgents");
    bool dropAgents = existingPolicy == "drop_all";
    bool filterAgents = existingPolicy == "filter";
    std::vector<std::wstring> tokens;
    tokens.push_back(original[0]);

    std::wstring trustedNativePath, trustedJavaPath;
    const char* verifyReason = NULL;
    bool hasTrustedNative = getJsonBoolField(line, "hasTrustedNative", false);
    bool hasTrustedJava = getJsonBoolField(line, "hasTrustedJava", false);
    if (hasTrustedNative && !verifyTrustedAgent(getJsonStringField(line, "trustedNativePath"),
            getJsonStringField(line, "trustedNativeSha256"), &trustedNativePath, &verifyReason)) {
        printResult("fallback", "UNAVAILABLE", dllPath, verifyReason);
        return;
    }
    if (hasTrustedJava && !verifyTrustedAgent(getJsonStringField(line, "trustedJavaPath"),
            getJsonStringField(line, "trustedJavaSha256"), &trustedJavaPath, &verifyReason)) {
        printResult("fallback", "UNAVAILABLE", dllPath, verifyReason);
        return;
    }

    unsigned long long generation = g_secureRelaunchGeneration.load() + 1;
    wchar_t property[160];
    swprintf_s(property, ARRAYSIZE(property), L"-Dforgevm.agent.pid=%lu", GetCurrentProcessId());
    tokens.push_back(property);
    swprintf_s(property, ARRAYSIZE(property), L"-Dforgevm.relaunch.gen=%llu", generation);
    tokens.push_back(property);

    std::string handoff = getJsonStringField(line, "handoffPoint");
    bool requireReady = handoff == "policy_applied";
    std::string nonce;
    std::wstring readyPipeName;
    HANDLE readyPipe = INVALID_HANDLE_VALUE;
    OVERLAPPED connect = {};
    if (requireReady) {
        nonce = randomNonceHex();
        if (nonce.empty()) {
            printResult("fallback", "UNAVAILABLE", dllPath, "nonce_generation_failed");
            return;
        }
        readyPipeName = L"\\\\.\\pipe\\forgevm_ready_" + std::to_wstring(GetCurrentProcessId())
                      + L"_" + toWide(nonce);
        /* Java's RandomAccessFile opens a full-duplex handle even though it only
         * writes the nonce. The server must therefore advertise DUPLEX access;
         * INBOUND caused ERROR_ACCESS_DENIED/FileNotFoundException on Windows. */
        readyPipe = CreateNamedPipeW(readyPipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                     1, 256, 256, 0, NULL);
        if (readyPipe == INVALID_HANDLE_VALUE) {
            printResult("fallback", "UNAVAILABLE", dllPath, "ready_pipe_create_failed");
            return;
        }
        connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        BOOL connected = ConnectNamedPipe(readyPipe, &connect);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (connected) SetEvent(connect.hEvent);
        if (!connected && connectError == ERROR_PIPE_CONNECTED) SetEvent(connect.hEvent);
        else if (!connected && connectError != ERROR_IO_PENDING) {
            CloseHandle(connect.hEvent); CloseHandle(readyPipe);
            printResult("fallback", "UNAVAILABLE", dllPath, "ready_pipe_listen_failed");
            return;
        }
        tokens.push_back(L"-Dforgevm.relaunch.readyPipe=" + readyPipeName);
        tokens.push_back(L"-Dforgevm.relaunch.readyNonce=" + toWide(nonce));
    }

    if (hasTrustedNative) {
        std::wstring option = L"-agentpath:" + trustedNativePath;
        std::string args = getJsonStringField(line, "trustedNativeOptions");
        if (!args.empty()) option += L"=" + toWide(args);
        tokens.push_back(std::move(option));
    }
    if (hasTrustedJava) {
        std::wstring option = L"-javaagent:" + trustedJavaPath;
        std::string args = getJsonStringField(line, "trustedJavaOptions");
        if (!args.empty()) option += L"=" + toWide(args);
        tokens.push_back(std::move(option));
    }

    bool skipNextPatchValue = false;
    for (size_t i = 1; i < original.size(); ++i) {
        const std::wstring& token = original[i];
        if (skipNextPatchValue) { skipNextPatchValue = false; continue; }
        if (isForgevmRelaunchInjectedToken(token)) continue;
        bool javaAgent = startsWithInsensitive(token, L"-javaagent:");
        bool nativeAgent = startsWithInsensitive(token, L"-agentpath:");
        bool agentLib = startsWithInsensitive(token, L"-agentlib:");
        if (javaAgent || nativeAgent || agentLib) {
            if (dropAgents) continue;
            if (filterAgents) {
                if (agentLib) continue;
                if (!relaunchShouldKeepToken(token, hasAgentFilter, agentFlt,
                                             hasNativeFilter, nativeFlt)) continue;
            }
        }
        if (startsWithInsensitive(token, L"-Xbootclasspath")
                || startsWithInsensitive(token, L"-Djava.system.class.loader=")
                || startsWithInsensitive(token, L"--patch-module=")) continue;
        if (_wcsicmp(token.c_str(), L"--patch-module") == 0) {
            skipNextPatchValue = true;
            continue;
        }
        tokens.push_back(token);
    }

    std::wstring commandLine = joinWindowsCommandLine(tokens);
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    std::vector<wchar_t> environment = getJsonBoolField(line, "sanitizeEnvironment", true)
            ? sanitizeEnvironmentBlock(baselineEnvironment) : baselineEnvironment;
    LPVOID environmentPtr = environment.empty() ? NULL : environment.data();

    HANDLE oldJvm = duplicateJvmControlHandle(oldPid);
    if (oldJvm == NULL && !g_guardMode.load()) {
        oldJvm = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, oldPid);
    }
    if (oldJvm == NULL) {
        if (connect.hEvent != NULL) CloseHandle(connect.hEvent);
        if (readyPipe != INVALID_HANDLE_VALUE) CloseHandle(readyPipe);
        printResult("fallback", "UNAVAILABLE", dllPath, "open_process_failed");
        return;
    }

    STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child = {};
    BOOL created = CreateProcessW(tokens[0].c_str(), mutableCommand.data(), NULL, NULL, FALSE,
                                  CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
                                      | (environmentPtr != NULL ? CREATE_UNICODE_ENVIRONMENT : 0),
                                  environmentPtr,
                                  baselineCwd.empty() ? NULL : baselineCwd.c_str(),
                                  &startup, &child);
    if (!created) {
        CloseHandle(oldJvm);
        if (connect.hEvent != NULL) CloseHandle(connect.hEvent);
        if (readyPipe != INVALID_HANDLE_VALUE) CloseHandle(readyPipe);
        printResult("fallback", "UNAVAILABLE", dllPath, "create_process_failed");
        return;
    }
    if (g_guardMode.load() && !retainAndLockJvm(child.hProcess, child.dwProcessId)) {
        TerminateProcess(child.hProcess, 0);
        CloseHandle(child.hThread); CloseHandle(child.hProcess); CloseHandle(oldJvm);
        if (connect.hEvent != NULL) CloseHandle(connect.hEvent);
        if (readyPipe != INVALID_HANDLE_VALUE) CloseHandle(readyPipe);
        printResult("fallback", "UNAVAILABLE", dllPath, "replacement_jvm_dacl_lock_failed");
        return;
    }

    ResumeThread(child.hThread);
    CloseHandle(child.hThread);
    bool ready = true;
    if (requireReady) {
        DWORD timeout = static_cast<DWORD>(std::min<unsigned long long>(
                getJsonUnsignedField(line, "handoffTimeoutMs", 30000ULL), 300000ULL));
        ready = waitForReadyPipe(readyPipe, child.hProcess, &connect, nonce, timeout);
    }
    if (connect.hEvent != NULL) CloseHandle(connect.hEvent);
    if (readyPipe != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(readyPipe); CloseHandle(readyPipe); }
    if (!ready) {
        TerminateProcess(child.hProcess, 76);
        if (g_guardMode.load()) restoreJvmControlHandle(oldJvm, oldPid);
        CloseHandle(child.hProcess); CloseHandle(oldJvm);
        printResult("fallback", "UNAVAILABLE", dllPath, "bootstrap_handoff_failed");
        return;
    }

    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        if (hasAgentFilter) g_javaAgentFilter = agentFlt;
        if (hasNativeFilter) g_nativeLoadFilter = nativeFlt;
        if (hasJvmtiFilter) g_jvmtiFilter = jvmtiFlt;
        if (hasProcessFilter) g_processCreateFilter = processFlt;
    }
    if (!installRelaunchFilters(api, child.hProcess, child.dwProcessId,
                                hasAgentFilter, hasNativeFilter, hasJvmtiFilter, hasProcessFilter)) {
        TerminateProcess(child.hProcess, 77);
        if (g_guardMode.load()) restoreJvmControlHandle(oldJvm, oldPid);
        CloseHandle(child.hProcess); CloseHandle(oldJvm);
        printResult("fallback", "UNAVAILABLE", dllPath, "replacement_guard_install_failed");
        return;
    }

    g_secureRelaunchGeneration.store(generation);
    {
        std::lock_guard<std::mutex> guard(g_guardMutex);
        g_secureRecoveryTokens.clear();
        for (const std::wstring& token : tokens) {
            if (!isForgevmRelaunchInjectedToken(token)) g_secureRecoveryTokens.push_back(token);
        }
        g_secureRecoveryEnvironmentSanitized = getJsonBoolField(line, "sanitizeEnvironment", true);
        if (g_secureRelaunchPolicyFingerprint.empty()) {
            g_secureRelaunchPolicyFingerprint = policyFingerprint;
        }
    }
    g_parentPid.store(child.dwProcessId);
    g_persistAfterEOF.store(true);
    HANDLE liveness = NULL;
    if (DuplicateHandle(GetCurrentProcess(), child.hProcess, GetCurrentProcess(), &liveness,
                        SYNCHRONIZE, FALSE, 0)) {
        HANDLE previous = g_relaunchNewJvm.exchange(liveness);
        if (previous != NULL) CloseHandle(previous);
    }
    CloseHandle(child.hProcess);
    printResult("ok", "FULL", dllPath, "relaunch_v2_committed");
    if (g_agentLog != NULL) fflush(g_agentLog);
    Sleep(25);
    TerminateProcess(oldJvm, 0);
    CloseHandle(oldJvm);
    AGENT_LOG("relaunch-v2: committed generation=%llu newPid=%lu", generation, g_parentPid.load());
}

void handleRelaunch(const NativeApi& api, const std::string& line, const std::string& dllPath) {
    unsigned long long pid = getJsonUnsignedField(line, "pid", 0ULL);
    if (pid == 0ULL) {
        printResult("fallback", "UNAVAILABLE", dllPath, "missing_pid");
        return;
    }

    bool hasAgentFilter   = getJsonBoolField(line, "hasAgentFilter",   false);
    bool hasNativeFilter  = getJsonBoolField(line, "hasNativeFilter",  false);
    bool hasJvmtiFilter   = getJsonBoolField(line, "hasJvmtiFilter",   false);
    bool hasProcessFilter = getJsonBoolField(line, "hasProcessFilter", false);

    LoadFilter agentFlt, nativeFlt, jvmtiFlt, processFlt;

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
    if (hasJvmtiFilter)   buildFilter(jvmtiFlt,   "jvmtiMode",   "jvmtiPatterns");
    if (hasProcessFilter) buildFilter(processFlt, "processMode", "processPatterns");

    /* Snapshot pre-relaunch ban state. Trampolines in the old JVM die with it,
     * so the new JVM needs fresh installs whenever a ban was active OR the
     * caller passed a new filter. Without this, relaunch() with no filter
     * args silently drops active protection that was installed before the call. */
    bool wasAgentBanActive, wasNativeBanActive, wasJvmtiBanActive, wasProcessBanActive;
    {
        std::lock_guard<std::mutex> g(g_filterMutex);
        wasAgentBanActive   = g_javaAgentFilter.active;
        wasNativeBanActive  = g_nativeLoadFilter.active;
        wasJvmtiBanActive   = g_jvmtiFilter.active;
        wasProcessBanActive = g_processCreateFilter.active;
    }
    bool installNativeBan  = hasNativeFilter  || wasNativeBanActive;
    bool installAgentBan   = hasAgentFilter   || wasAgentBanActive;
    bool installJvmtiBan   = hasJvmtiFilter || wasJvmtiBanActive;
    bool installProcessBan = hasProcessFilter || wasProcessBanActive;

    AGENT_LOG("relaunch: pid=%llu hasAgentFilter=%d hasNativeFilter=%d hasJvmtiFilter=%d hasProcessFilter=%d "
              "wasAgentActive=%d wasNativeActive=%d wasJvmtiActive=%d wasProcessActive=%d",
              pid, (int)hasAgentFilter, (int)hasNativeFilter, (int)hasJvmtiFilter, (int)hasProcessFilter,
              (int)wasAgentBanActive, (int)wasNativeBanActive,
              (int)wasJvmtiBanActive, (int)wasProcessBanActive);

    std::wstring cmdLine = queryProcessCommandLine(static_cast<DWORD>(pid));
    if (cmdLine.empty()) {
        {
            std::lock_guard<std::mutex> guard(g_guardMutex);
            cmdLine = g_guardCommandLine;
        }
        if (!cmdLine.empty()) {
            AGENT_LOG("relaunch: WMI cmdline empty, using cached command line (len=%zu)", cmdLine.size());
        }
    }
    if (cmdLine.empty()) {
        AGENT_LOG("relaunch: cmdline unavailable (WMI empty, no cache)");
        printResult("fallback", "UNAVAILABLE", dllPath, "cmdline_unavailable");
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

    HANDLE hJvm = duplicateJvmControlHandle(static_cast<DWORD>(pid));
    if (hJvm == NULL && !g_guardMode.load()) {
        hJvm = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    }
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
    if (g_guardMode.load() && !retainAndLockJvm(pi.hProcess, pi.dwProcessId)) {
        AGENT_LOG("relaunch: unable to lock replacement JVM pid=%lu", pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hJvm);
        g_parentPid.store(static_cast<DWORD>(pid));
        printResult("fallback", "UNAVAILABLE", dllPath, "replacement_jvm_dacl_lock_failed");
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
    if (hasJvmtiFilter) {
        std::lock_guard<std::mutex> g(g_filterMutex);
        g_jvmtiFilter = jvmtiFlt;
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
        bool installJvmtiBan;
        bool installProcessBan;
        const NativeApi* api;
        std::string dllPath;
        HANDLE abortEvent;
    };
    auto* ctx = new RelaunchPostResumeCtx{
        pi.hProcess, pi.dwProcessId, installAgentBan, installNativeBan, installJvmtiBan,
        installProcessBan, &api, dllPath, abortEvent
    };
    HANDLE watcher = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
        auto* c = static_cast<RelaunchPostResumeCtx*>(p);
        HANDLE h = c->hNewJvm;
        DWORD newPid = c->newPid;
        bool installAgentBan = c->installAgentBan;
        bool installNativeBan = c->installNativeBan;
        bool installJvmtiBan = c->installJvmtiBan;
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

        if (api->bootstrapTargetWithHandle != NULL) {
            if (api->bootstrapTargetWithHandle(static_cast<unsigned long long>(newPid), h) == 1) {
                AGENT_LOG("post-relaunch watcher: bootstrap_target_with_handle(%lu) ok", newPid);
                g_watchdogBootstrappedPid.store(newPid);
                /* All three bans now match in-process against a resident pattern
                 * blob — no filter pipe. Snapshot each filter's mode + patterns
                 * and hand them to the DLL exports. */
                if (installNativeBan && api->banNativeLoad != NULL) {
                    int m; std::string j;
                    { std::lock_guard<std::mutex> g(g_filterMutex);
                      m = static_cast<int>(g_nativeLoadFilter.mode);
                      j = joinPatternsLF(g_nativeLoadFilter); }
                    int r = api->banNativeLoad(m, j.c_str());
                    AGENT_LOG("post-relaunch watcher: banNativeLoad r=%d reason=%s",
                              r, api->lastError ? api->lastError() : "");
                }
                if (installAgentBan && api->banJavaAgent != NULL) {
                    int m; std::string j;
                    { std::lock_guard<std::mutex> g(g_filterMutex);
                      m = static_cast<int>(g_javaAgentFilter.mode);
                      j = joinPatternsLF(g_javaAgentFilter); }
                    int r = api->banJavaAgent(m, j.c_str());
                    AGENT_LOG("post-relaunch watcher: banJavaAgent r=%d reason=%s",
                              r, api->lastError ? api->lastError() : "");
                }
                if (installJvmtiBan && api->banJvmti != NULL) {
                    int m; std::string j;
                    { std::lock_guard<std::mutex> g(g_filterMutex);
                      m = static_cast<int>(g_jvmtiFilter.mode);
                      j = joinPatternsLF(g_jvmtiFilter); }
                    int r = api->banJvmti(m, j.c_str());
                    AGENT_LOG("post-relaunch watcher: banJvmti r=%d reason=%s",
                              r, api->lastError ? api->lastError() : "");
                }
                if (installProcessBan && api->banProcessCreate != NULL) {
                    int m; std::string j;
                    { std::lock_guard<std::mutex> g(g_filterMutex);
                      m = static_cast<int>(g_processCreateFilter.mode);
                      j = joinPatternsLF(g_processCreateFilter); }
                    int r = api->banProcessCreate(m, j.c_str());
                    AGENT_LOG("post-relaunch watcher: banProcessCreate r=%d reason=%s",
                              r, api->lastError ? api->lastError() : "");
                }
            } else {
                AGENT_LOG("post-relaunch watcher: bootstrap_target_with_handle(%lu) failed: %s",
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

/* ============================================================
 * Command dispatch + multi-client command-pipe server
 *
 * All target-process mutation funnels through the single agent. The Java client
 * side is a thin RPC layer: any classloader's ForgeVM connects to the agent's
 * command pipe (name derived from the JVM-global forgevm.agent.pid property) and
 * sends commands. Because the native DLL keeps shared per-target state, every
 * command executes under g_commandMutex (serialized), but connections are
 * accepted concurrently so multiple classloaders each get a live channel.
 * ============================================================ */

std::mutex g_commandMutex;
AgentLockState g_lockState;          // guarded by g_commandMutex
const NativeApi* g_api = nullptr;    // set in main() before serving
std::string g_cmdDllPath;            // set in main() before serving

struct GuardPostResumeCtx {
    HANDLE process;
    DWORD pid;
    const NativeApi* api;
};

static void guardReapplyActiveFilters(const NativeApi& api) {
    LoadFilter javaAgent, nativeLoad, jvmti, process;
    {
        std::lock_guard<std::mutex> filters(g_filterMutex);
        javaAgent = g_javaAgentFilter;
        nativeLoad = g_nativeLoadFilter;
        jvmti = g_jvmtiFilter;
        process = g_processCreateFilter;
    }
    auto apply = [&](const char* name, const LoadFilter& filter, auto fn) {
        if (!filter.active || fn == NULL) return;
        int result = fn(static_cast<int>(filter.mode), joinPatternsLF(filter).c_str());
        AGENT_LOG("guard: %s reinstalled result=%d reason=%s", name, result,
                  api.lastError ? api.lastError() : "");
    };
    apply("banNativeLoad", nativeLoad, api.banNativeLoad);
    apply("banJavaAgent", javaAgent, api.banJavaAgent);
    apply("banJvmti", jvmti, api.banJvmti);
    apply("banProcessCreate", process, api.banProcessCreate);

    /* Re-install JVM_Halt lock after recovery. */
    if (g_guardMode.load() && api.installHaltLock != NULL) {
        unsigned long long addr = api.installHaltLock();
        if (addr != 0ULL) {
            g_haltLockTrampolineAddr.store(addr);
            AGENT_LOG("guard: JVM_Halt lock re-installed @ 0x%llX", addr);
        } else {
            AGENT_LOG("guard: JVM_Halt lock re-install failed: %s",
                      api.lastError ? api.lastError() : "unknown");
        }
    }
    if (g_guardMode.load() && api.installSelfTerminateGuard != NULL) {
        int result = api.installSelfTerminateGuard();
        AGENT_LOG("guard: NtTerminateProcess in-target guard reinstall result=%d reason=%s", result,
                  api.lastError ? api.lastError() : "");
    }
}

static DWORD WINAPI guardPostResumeWatcher(LPVOID param) {
    GuardPostResumeCtx* ctx = static_cast<GuardPostResumeCtx*>(param);
    HANDLE process = ctx->process;
    DWORD pid = ctx->pid;
    const NativeApi* api = ctx->api;
    delete ctx;

    bool jvmLoaded = false;
    for (int i = 0; i < 600 && !jvmLoaded; ++i) {
        HMODULE modules[256];
        DWORD needed = 0;
        if (EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
            size_t count = (needed / sizeof(HMODULE) < ARRAYSIZE(modules))
                         ? needed / sizeof(HMODULE) : ARRAYSIZE(modules);
            for (size_t m = 0; m < count; ++m) {
                wchar_t name[MAX_PATH] = {};
                if (GetModuleBaseNameW(process, modules[m], name, ARRAYSIZE(name)) > 0) {
                    std::wstring lower(name);
                    for (wchar_t& ch : lower) ch = (wchar_t)towlower(ch);
                    if (lower == L"jvm.dll") { jvmLoaded = true; break; }
                }
            }
        }
        if (!jvmLoaded) Sleep(50);
    }
    if (!jvmLoaded) {
        AGENT_LOG("guard: jvm.dll did not appear in recovered pid=%lu", pid);
        CloseHandle(process);
        return 0;
    }
    if (api->bootstrapTargetWithHandle != NULL) {
        if (api->bootstrapTargetWithHandle(static_cast<unsigned long long>(pid), process) != 1) {
            AGENT_LOG("guard: bootstrap_target_with_handle(%lu) failed: %s", pid,
                      api->lastError ? api->lastError() : "unknown");
            CloseHandle(process);
            return 0;
        }
    } else if (api->bootstrapTarget == NULL || api->bootstrapTarget(pid) != 1) {
        AGENT_LOG("guard: bootstrap_target(%lu) failed: %s", pid,
                  api->lastError ? api->lastError() : "unknown");
        CloseHandle(process);
        return 0;
    }
    guardReapplyActiveFilters(*api);
    /* Hook installation only proves that bootstrap completed. Keep the crash
     * budget until this process survives the stable-recovery grace window. */
    g_guardRecoveryStableSinceTick.store(GetTickCount64());
    g_watchdogBootstrappedPid.store(pid);
    AGENT_LOG("guard: recovery bootstrap completed for pid=%lu; hooks reinstalled, filter decisions pending audit", pid);
    windowPublish("[GUARD] JVM restart bootstrapped; hooks reinstalled (pid " + std::to_string(pid) + ")");
    CloseHandle(process);
    return 0;
}

static void autoRelaunchAfterCrash(DWORD deadPid) {
    if (g_guardRecoveryRunning.exchange(true)) return;

    /* Consecutive-death guard: if the JVM has died repeatedly without a stable
     * recovery, stop after kGuardMaxConsecutiveDeaths attempts. Bootstrap alone
     * does not reset this counter; the health poller requires 30s of lifetime. */
    int deaths = g_guardConsecutiveDeaths.fetch_add(1) + 1;
    if (deaths > kGuardMaxConsecutiveDeaths) {
        AGENT_LOG("guard: %d consecutive JVM deaths — agent exiting", deaths);
        windowPublish("[GUARD] " + std::to_string(deaths) +
                      " consecutive JVM deaths; FVM stopping");
        if (g_api != nullptr && g_api->haltLockAllow != NULL) {
            g_api->haltLockAllow();
        }
        ExitProcess(75);
    }
    AGENT_LOG("guard: consecutive death %d of %d (pid=%lu)",
              deaths, kGuardMaxConsecutiveDeaths, deadPid);

    std::wstring source;
    unsigned long long generation = 0;
    std::vector<std::wstring> secureTokens;
    bool secureEnvironmentSanitized = true;
    {
        std::lock_guard<std::mutex> guard(g_guardMutex);
        source = g_guardCommandLine;
        secureTokens = g_secureRecoveryTokens;
        secureEnvironmentSanitized = g_secureRecoveryEnvironmentSanitized;
        generation = secureTokens.empty()
                ? g_guardGeneration.fetch_add(1) + 1
                : g_secureRelaunchGeneration.fetch_add(1) + 1;
    }
    if ((source.empty() && secureTokens.empty()) || g_api == nullptr) {
        AGENT_LOG("guard: recovery unavailable (no cached command line or API)");
        windowPublish("[GUARD] recovery failed: no cached JVM command line; FVM stopped");
        if (g_api != nullptr && g_api->haltLockAllow != NULL) {
            g_api->haltLockAllow();
        }
        ExitProcess(71);
    }

    std::vector<std::wstring> oldTokens = secureTokens.empty()
            ? tokenizeCmdLineWindows(source) : secureTokens;
    if (oldTokens.empty()) {
        AGENT_LOG("guard: cached command line parse failed");
        ExitProcess(72);
    }
    std::vector<std::wstring> tokens;
    tokens.push_back(oldTokens[0]);
    wchar_t agentPidToken[64];
    swprintf_s(agentPidToken, ARRAYSIZE(agentPidToken), L"-Dforgevm.agent.pid=%lu",
               (unsigned long)GetCurrentProcessId());
    tokens.push_back(agentPidToken);
    wchar_t genToken[64];
    swprintf_s(genToken, ARRAYSIZE(genToken), L"-Dforgevm.relaunch.gen=%llu", generation);
    tokens.push_back(genToken);
    for (size_t i = 1; i < oldTokens.size(); ++i) {
        if (!isForgevmRelaunchInjectedToken(oldTokens[i])) tokens.push_back(oldTokens[i]);
    }
    std::wstring commandLine = joinWindowsCommandLine(tokens);

    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> recoveryEnvironment;
    std::wstring recoveryCwd;
    if (!secureTokens.empty()) {
        std::lock_guard<std::mutex> guard(g_guardMutex);
        recoveryEnvironment = secureEnvironmentSanitized
                ? sanitizeEnvironmentBlock(g_launchBaseline.environment)
                : g_launchBaseline.environment;
        recoveryCwd = g_launchBaseline.workingDirectory;
    }
    LPVOID recoveryEnvironmentPtr = recoveryEnvironment.empty() ? NULL : recoveryEnvironment.data();
    BOOL created = CreateProcessW(secureTokens.empty() ? NULL : tokens[0].c_str(),
                                  mutableCommand.data(), NULL, NULL, FALSE,
                                  CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
                                      | (recoveryEnvironmentPtr != NULL ? CREATE_UNICODE_ENVIRONMENT : 0),
                                  recoveryEnvironmentPtr,
                                  recoveryCwd.empty() ? NULL : recoveryCwd.c_str(), &startup, &pi);
    if (!created) {
        AGENT_LOG("guard: CreateProcessW failed after pid=%lu death: %lu", deadPid, GetLastError());
        windowPublish("[GUARD] recovery CreateProcessW failed; FVM stopped");
        if (g_api != nullptr && g_api->haltLockAllow != NULL) {
            g_api->haltLockAllow();
        }
        ExitProcess(73);
    }
    if (!retainAndLockJvm(pi.hProcess, pi.dwProcessId)) {
        AGENT_LOG("guard: unable to lock recovered JVM pid=%lu", pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        windowPublish("[GUARD] recovery JVM lock failed; FVM stopped");
        if (g_api != nullptr && g_api->haltLockAllow != NULL) {
            g_api->haltLockAllow();
        }
        ExitProcess(74);
    }

    g_parentPid.store(pi.dwProcessId);
    g_guardAuthorizedExit.store(false);
    g_persistAfterEOF.store(true);
    {
        std::lock_guard<std::mutex> guard(g_guardMutex);
        g_guardCommandLine = commandLine;
    }
    HANDLE duplicate = NULL;
    if (DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(), &duplicate,
                        SYNCHRONIZE, FALSE, 0)) {
        HANDLE previous = g_relaunchNewJvm.exchange(duplicate);
        if (previous != NULL) CloseHandle(previous);
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    GuardPostResumeCtx* ctx = new GuardPostResumeCtx{pi.hProcess, pi.dwProcessId, g_api};
    HANDLE watcher = CreateThread(NULL, 0, guardPostResumeWatcher, ctx, 0, NULL);
    if (watcher != NULL) CloseHandle(watcher);
    AGENT_LOG("guard: abnormal pid=%lu restarted as pid=%lu generation=%llu", deadPid,
              pi.dwProcessId, generation);
    windowPublish("[GUARD] abnormal JVM exit; restarting as pid " + std::to_string(pi.dwProcessId));
    g_guardRecoveryRunning.store(false);
}

// Returns true if the command was "shutdown" (caller should stop the channel).
static bool dispatchCommand(const NativeApi& api, const std::string& dllPath,
                            AgentLockState& lockState, const std::string& line) {
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
    } else if (cmd == "ban_jvmti") {
        handleBanJvmti(api, line, dllPath);
    } else if (cmd == "unban_jvmti") {
        handleUnbanJvmti(api, dllPath);
    } else if (cmd == "ban_process_create") {
        handleBanProcessCreate(api, line, dllPath);
    } else if (cmd == "unban_process_create") {
        handleUnbanProcessCreate(api, dllPath);
    } else if (cmd == "relaunch_v2") {
        handleRelaunchV2(api, line, dllPath);
    } else if (cmd == "relaunch") {
        handleRelaunch(api, line, dllPath);
    } else if (cmd == "shutdown") {
        printResult("ok", "RESTRICTED", dllPath, "bye");
        return true;
    } else {
        printResult("fallback", "UNAVAILABLE", dllPath, "unknown_command");
    }
    return false;
}

/* Read one '\n'-terminated request from a byte-mode pipe. Returns false on
 * EOF/error (client disconnected). */
static bool readPipeLine(HANDLE pipe, std::string& out) {
    out.clear();
    char ch;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(pipe, &ch, 1, &got, NULL) || got == 0) {
            return !out.empty();   // partial line at EOF still dispatched
        }
        if (ch == '\n') return true;
        if (ch != '\r') out.push_back(ch);
        if (out.size() > (1u << 20)) return true;   // 1 MiB sanity cap
    }
}

/* Serve one connected command channel until the client disconnects. Each command
 * runs under g_commandMutex with its reply captured to a per-thread sink, then
 * written back over this pipe. */
static DWORD WINAPI commandConnectionThread(LPVOID param) {
    HANDLE pipe = static_cast<HANDLE>(param);
    if (!isExpectedCommandPipeClient(pipe)) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }
    std::string line;
    while (readPipeLine(pipe, line)) {
        if (line.empty()) continue;
        std::string reply;
        bool shutdownReq;
        {
            std::lock_guard<std::mutex> g(g_commandMutex);
            tls_replySink = &reply;
            shutdownReq = dispatchCommand(*g_api, g_cmdDllPath, g_lockState, line);
            tls_replySink = nullptr;
        }
        if (!reply.empty()) {
            DWORD wrote = 0;
            WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &wrote, NULL);
            FlushFileBuffers(pipe);
        }
        if (shutdownReq) {
            AGENT_LOG("command channel: shutdown received — exiting agent");
            /* Release JVM_Halt lock so the JVM can self-terminate after agent exit. */
            if (g_api != nullptr && g_api->haltLockAllow != NULL) {
                g_api->haltLockAllow();
            }
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            ExitProcess(0);
        }
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

/* After the first handoff client connects, keep accepting further clients (other
 * classloaders' ForgeVM instances) on fresh pipe instances, each on its own
 * thread. Never returns; the parent watchdog terminates the agent when the JVM
 * dies. firstPipe is the already-accepted first connection. */
static void runCommandPipeServer(HANDLE firstPipe) {
    if (firstPipe != NULL && firstPipe != INVALID_HANDLE_VALUE) {
        HANDLE th = CreateThread(NULL, 0, commandConnectionThread, firstPipe, 0, NULL);
        if (th != NULL) CloseHandle(th);
    }
    for (;;) {
        HANDLE pipe = CreateNamedPipeA(
            g_commandPipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            /*outBuf*/ 4096, /*inBuf*/ 4096,
            /*defaultTimeout*/ 0, /*sa*/ NULL);
        if (pipe == INVALID_HANDLE_VALUE) {
            AGENT_LOG("command pipe server: CreateNamedPipe failed: %lu", GetLastError());
            Sleep(200);
            continue;
        }
        BOOL connected = ConnectNamedPipe(pipe, NULL)
                             ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }
        if (!isExpectedCommandPipeClient(pipe)) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            continue;
        }
        HANDLE th = CreateThread(NULL, 0, commandConnectionThread, pipe, 0, NULL);
        if (th == NULL) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            continue;
        }
        CloseHandle(th);
    }
}

/* ============================================================
 * Live status window: UI thread + JVM health poller
 * ============================================================ */

static HWND g_statusEdit = NULL;
static HWND g_commandResultEdit = NULL;
static HWND g_commandInput = NULL;
static HWND g_commandSuggestions = NULL;
static const size_t kStatusTextCap = 200000;   // trim the edit buffer past this
static WNDPROC g_commandInputProc = NULL;
static const UINT WM_FVM_STOP_AGENT = WM_APP + 41;

static const wchar_t* const kWindowCommands[] = {
    L"/help", L"/status", L"/clear", L"/stop", L"/stop jvm", L"/stop fvm"
};

static void statusAppend(const std::string& line) {
    if (g_statusEdit == NULL) return;
    int len = GetWindowTextLengthW(g_statusEdit);
    if (len > (int)kStatusTextCap) {
        /* Drop the oldest ~25% so the control never grows unbounded. */
        SendMessageW(g_statusEdit, EM_SETSEL, 0, kStatusTextCap / 4);
        SendMessageW(g_statusEdit, EM_REPLACESEL, FALSE, (LPARAM)L"");
        len = GetWindowTextLengthW(g_statusEdit);
    }
    /* The whole publish pipeline carries UTF-8 (source literals, wideToUtf8'd
     * thread names, ⚠ glyphs). Feed the EDIT control wide chars so a non-Latin
     * system codepage can't mangle it. */
    std::wstring out = toWide(line);
    out += L"\r\n";
    SendMessageW(g_statusEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_statusEdit, EM_REPLACESEL, FALSE, (LPARAM)out.c_str());
    SendMessageW(g_statusEdit, EM_SCROLLCARET, 0, 0);
}

static void commandResultSet(const std::wstring& text) {
    if (g_commandResultEdit == NULL) return;
    SetWindowTextW(g_commandResultEdit, text.c_str());
    SendMessageW(g_commandResultEdit, EM_SETSEL, 0, 0);
}

static std::wstring commandInputText() {
    if (g_commandInput == NULL) return std::wstring();
    int len = GetWindowTextLengthW(g_commandInput);
    std::wstring text((size_t)len + 1, L'\0');
    GetWindowTextW(g_commandInput, &text[0], len + 1);
    text.resize((size_t)len);
    size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return std::wstring();
    size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

static std::wstring lowerWide(std::wstring value) {
    for (wchar_t& ch : value) ch = (wchar_t)towlower(ch);
    return value;
}

static bool stopTargetJvm(std::wstring* detail) {
    DWORD pid = g_parentPid.load();
    if (pid == 0) {
        *detail = L"JVM: not attached";
        return true;
    }
    HANDLE process = duplicateJvmControlHandle(pid);
    if (process == NULL && !g_guardMode.load()) {
        process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    }
    if (process == NULL) {
        *detail = L"JVM: unable to open pid " + std::to_wstring(pid) +
                  L" (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    /* Unlock JVM_Halt before terminating so a subsequent in-process halt
     * (e.g. during shutdown hooks) is not blocked. */
    if (g_api != nullptr && g_api->haltLockAllow != NULL) {
        g_api->haltLockAllow();
    }

    bool ok = TerminateProcess(process, 0) != FALSE;
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(process);
    if (!ok) {
        *detail = L"JVM: terminate failed (error " + std::to_wstring(err) + L")";
        return false;
    }
    /* This is an operator-authorized exit: disable watchdog tracking before it
     * observes the process signal, so a future lock/guard cannot revive it. */
    g_guardAuthorizedExit.store(true);
    clearJvmControlHandle();
    g_guardMode.store(false);
    g_jvmLockRequested.store(false);
    g_parentPid.store(0);
    g_jvmDiedPostMortem.store(true);
    *detail = L"JVM: stopped (pid " + std::to_wstring(pid) + L")";
    return true;
}

static void updateCommandSuggestions() {
    if (g_commandSuggestions == NULL) return;
    std::wstring prefix = lowerWide(commandInputText());
    SendMessageW(g_commandSuggestions, LB_RESETCONTENT, 0, 0);
    if (prefix.empty() || prefix[0] != L'/') {
        ShowWindow(g_commandSuggestions, SW_HIDE);
        return;
    }
    int matches = 0;
    for (const wchar_t* command : kWindowCommands) {
        std::wstring candidate(command);
        if (candidate.compare(0, prefix.size(), prefix) == 0) {
            SendMessageW(g_commandSuggestions, LB_ADDSTRING, 0, (LPARAM)command);
            ++matches;
        }
    }
    ShowWindow(g_commandSuggestions, matches ? SW_SHOWNOACTIVATE : SW_HIDE);
}

static void completeSelectedCommand() {
    if (g_commandSuggestions == NULL || g_commandInput == NULL) return;
    LRESULT index = SendMessageW(g_commandSuggestions, LB_GETCURSEL, 0, 0);
    if (index == LB_ERR) index = 0;
    wchar_t command[64] = {};
    if (SendMessageW(g_commandSuggestions, LB_GETTEXT, index, (LPARAM)command) != LB_ERR) {
        SetWindowTextW(g_commandInput, command);
        SendMessageW(g_commandInput, EM_SETSEL, wcslen(command), wcslen(command));
        ShowWindow(g_commandSuggestions, SW_HIDE);
    }
}

static void executeWindowCommand(HWND hwnd) {
    std::wstring command = lowerWide(commandInputText());
    if (command.empty()) return;
    SetWindowTextW(g_commandInput, L"");
    ShowWindow(g_commandSuggestions, SW_HIDE);

    if (command == L"/help") {
        commandResultSet(
            L"ForgeVM commands\r\n\r\n"
            L"/help\r\n"
            L"  Show this command reference.\r\n\r\n"
            L"/status\r\n"
            L"  Show the tracked JVM PID, lifecycle mode, and guard state.\r\n\r\n"
            L"/clear\r\n"
            L"  Clear the left-side status stream.\r\n\r\n"
            L"/stop jvm\r\n"
            L"  Stop only the JVM. This is an authorized exit and disables guard.\r\n\r\n"
            L"/stop fvm\r\n"
            L"  Stop only the ForgeVM agent; the JVM continues without protection.\r\n\r\n"
            L"/stop\r\n"
            L"  Stop both the JVM and the ForgeVM agent.");
        windowPublish("[CMD] /help -> OK");
    } else if (command == L"/status") {
        DWORD pid = g_parentPid.load();
        std::wstring jvm = pid ? (std::wstring(L"running (pid ") + std::to_wstring(pid) + L")")
                               : std::wstring(L"not attached");
        std::wstring result = std::wstring(L"command: /status\r\nresult: OK\r\njvm: ") + jvm +
            L"\r\njvm lock: " + (g_guardMode.load() ? L"enabled" : L"disabled") +
            L"\r\nwindow: enabled";
        commandResultSet(result);
        windowPublish("[CMD] /status -> OK");
    } else if (command == L"/clear") {
        if (g_statusEdit) SetWindowTextW(g_statusEdit, L"");
        commandResultSet(L"command: /clear\r\nresult: OK\r\nstatus output cleared");
        windowPublish("[CMD] /clear -> OK");
    } else if (command == L"/stop jvm") {
        std::wstring detail;
        bool ok = stopTargetJvm(&detail);
        commandResultSet(L"command: /stop jvm\r\nresult: " + std::wstring(ok ? L"OK" : L"FAILED") +
                         L"\r\n" + detail + L"\r\nfvm agent: " +
                         (g_guardMode.load() ? L"running" : L"stopping"));
        windowPublish(std::string("[CMD] /stop jvm -> ") + (ok ? "OK" : "FAILED"));
        /* In lockJvm mode the agent persists with its window after an authorized
         * JVM stop. Without lockJvm, stopping the JVM also stops the agent. */
        if (!g_guardMode.load()) PostMessageW(hwnd, WM_FVM_STOP_AGENT, 0, 0);
    } else if (command == L"/stop fvm") {
        commandResultSet(L"command: /stop fvm\r\nresult: OK\r\njvm: unchanged\r\nfvm agent: stopping");
        windowPublish("[CMD] /stop fvm -> OK");
        PostMessageW(hwnd, WM_FVM_STOP_AGENT, 0, 0);
    } else if (command == L"/stop") {
        std::wstring detail;
        bool ok = stopTargetJvm(&detail);
        commandResultSet(L"command: /stop\r\nresult: " + std::wstring(ok ? L"OK" : L"PARTIAL") +
                         L"\r\n" + detail + L"\r\nfvm agent: stopping");
        windowPublish(std::string("[CMD] /stop -> ") + (ok ? "OK" : "PARTIAL"));
        PostMessageW(hwnd, WM_FVM_STOP_AGENT, 0, 0);
    } else {
        commandResultSet(L"command: " + command + L"\r\nresult: UNKNOWN_COMMAND\r\nUse /help.");
        windowPublish("[CMD] unknown command");
    }
}

static LRESULT CALLBACK commandInputWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_KEYDOWN) {
        if (wp == VK_RETURN) {
            executeWindowCommand(GetParent(hwnd));
            return 0;
        }
        if (wp == VK_TAB) {
            completeSelectedCommand();
            return 0;
        }
        if (wp == VK_DOWN && IsWindowVisible(g_commandSuggestions)) {
            SendMessageW(g_commandSuggestions, LB_SETCURSEL, 0, 0);
            SetFocus(g_commandSuggestions);
            return 0;
        }
    }
    return CallWindowProcW(g_commandInputProc, hwnd, msg, wp, lp);
}

static LRESULT CALLBACK statusWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_SIZE:
            {
                int width = LOWORD(lp), height = HIWORD(lp);
                int margin = 8, inputHeight = 25, suggestionHeight = 96;
                int outputHeight = height - margin * 3 - inputHeight;
                int leftWidth = (width - margin * 3) * 3 / 5;
                int rightWidth = width - margin * 3 - leftWidth;
                if (g_statusEdit) MoveWindow(g_statusEdit, margin, margin, leftWidth, outputHeight, TRUE);
                if (g_commandResultEdit) MoveWindow(g_commandResultEdit, margin * 2 + leftWidth, margin,
                                                    rightWidth, outputHeight, TRUE);
                if (g_commandInput) MoveWindow(g_commandInput, margin, margin * 2 + outputHeight,
                                                width - margin * 2, inputHeight, TRUE);
                if (g_commandSuggestions) MoveWindow(g_commandSuggestions, margin,
                    margin * 2 + outputHeight - suggestionHeight, leftWidth, suggestionHeight, TRUE);
            }
            return 0;
        case WM_TIMER: {
            std::vector<std::string> batch;
            {
                std::lock_guard<std::mutex> g(g_windowQueueMutex);
                batch.swap(g_windowQueue);
            }
            for (const auto& l : batch) statusAppend(l);
            return 0;
        }
        case WM_CLOSE:
            /* While the JVM is alive the agent is still serving it — closing the
             * X must NOT kill the agent, so just hide. But once the JVM has died
             * and we're only keeping the window for post-mortem review, closing
             * it is the operator's "I'm done" → quit the agent. */
            if (g_jvmDiedPostMortem.load()) ExitProcess(0);
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_COMMAND:
            if ((HWND)lp == g_commandInput && HIWORD(wp) == EN_CHANGE) {
                updateCommandSuggestions();
                return 0;
            }
            if ((HWND)lp == g_commandSuggestions && HIWORD(wp) == LBN_DBLCLK) {
                completeSelectedCommand();
                SetFocus(g_commandInput);
                return 0;
            }
            return 0;
        case WM_FVM_STOP_AGENT:
            ExitProcess(0);
            return 0;
        case WM_DESTROY:
            g_statusEdit = NULL;
            g_commandResultEdit = NULL;
            g_commandInput = NULL;
            g_commandSuggestions = NULL;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static DWORD WINAPI statusWindowThread(LPVOID) {
    HINSTANCE inst = GetModuleHandleW(NULL);
    WNDCLASSW wc = {};
    wc.lpfnWndProc   = statusWndProc;
    wc.hInstance     = inst;
    wc.lpszClassName = L"ForgeVMStatusWnd";
    wc.hCursor       = LoadCursorW(NULL, MAKEINTRESOURCEW(32512)); // IDC_ARROW
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (!RegisterClassW(&wc)) return 0;

    HWND hwnd = CreateWindowExW(
        0, L"ForgeVMStatusWnd", L"ForgeVM — live status",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 980, 600,
        NULL, NULL, inst, NULL);
    if (hwnd == NULL) return 0;

    g_statusEdit = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 1, 1, hwnd, NULL, inst, NULL);
    g_commandResultEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"Run /help for ForgeVM commands.",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 1, 1, hwnd, NULL, inst, NULL);
    g_commandInput = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, 0, 1, 1, hwnd, NULL, inst, NULL);
    g_commandSuggestions = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | LBS_NOTIFY | WS_VSCROLL,
        0, 0, 1, 1, hwnd, NULL, inst, NULL);
    if (g_statusEdit) {
        /* A TrueType monospace face (not the ANSI_FIXED_FONT raster font) so GDI
         * font-linking can fall back to CJK glyphs for non-Latin content;
         * DEFAULT_CHARSET keeps that fallback path open. */
        HFONT mono = CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        if (mono == NULL) mono = (HFONT)GetStockObject(ANSI_FIXED_FONT);
        SendMessageW(g_statusEdit, WM_SETFONT, (WPARAM)mono, TRUE);
        if (g_commandResultEdit) SendMessageW(g_commandResultEdit, WM_SETFONT, (WPARAM)mono, TRUE);
        if (g_commandInput) SendMessageW(g_commandInput, WM_SETFONT, (WPARAM)mono, TRUE);
        if (g_commandSuggestions) SendMessageW(g_commandSuggestions, WM_SETFONT, (WPARAM)mono, TRUE);
    }
    if (g_commandInput) {
        g_commandInputProc = (WNDPROC)SetWindowLongPtrW(g_commandInput, GWLP_WNDPROC,
                                                          (LONG_PTR)commandInputWndProc);
    }
    SendMessageW(hwnd, WM_SIZE, 0, MAKELPARAM(980, 600));
    SetFocus(g_commandInput);

    /* Drain the queue ~10x/sec — cheap, keeps the feed live without busy-wait. */
    SetTimer(hwnd, 1, 100, NULL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

/* Sum a thread's kernel+user CPU as 100ns ticks; 0 if unreadable. */
static ULONGLONG threadCpu100ns(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (h == NULL) return 0;
    FILETIME c{}, e{}, k{}, u{};
    ULONGLONG total = 0;
    if (GetThreadTimes(h, &c, &e, &k, &u)) {
        ULARGE_INTEGER ku{}, uu{};
        ku.LowPart = k.dwLowDateTime; ku.HighPart = k.dwHighDateTime;
        uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
        total = ku.QuadPart + uu.QuadPart;
    }
    CloseHandle(h);
    return total;
}

/* Best-effort OS thread name (JDK 17 sets these via SetThreadDescription on
 * Windows, so the busiest thread often shows as e.g. "Render thread"). */
static std::string threadName(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (h == NULL) return std::string();
    PWSTR desc = NULL;
    std::string name;
    if (SUCCEEDED(GetThreadDescription(h, &desc)) && desc != NULL) {
        if (desc[0] != L'\0') name = wideToUtf8(desc);
        LocalFree(desc);
    }
    CloseHandle(h);
    return name;
}

/* Anti-suspend defense: when the health poller detects a CPU stall, this
 * function enumerates all JVM threads and resumes any that are externally
 * suspended. An adversary's guardian process can bypass the process-level
 * PROCESS_SUSPEND_RESUME DACL by calling SuspendThread on individual threads
 * (thread DACLs are independent of the process DACL). This reactive defense
 * detects the resulting stall and reverses the suspension.
 *
 * JVM-internal suspensions (GC stack scanning, etc.) are brief (milliseconds);
 * a 6-second stall is always external. ResumeThread is a no-op on threads
 * that are not suspended, so calling it on all threads is safe. */
static int resumeSuspendedJvmThreads(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = {}; te.dwSize = sizeof(te);
    int resumedCount = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (ht == NULL) continue;
            DWORD prev = ResumeThread(ht);
            if (prev != 0) {
                ++resumedCount;
                DWORD loops = 0;
                while (prev > 1 && loops < 20) {
                    prev = ResumeThread(ht);
                    ++loops;
                }
            }
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return resumedCount;
}

static DWORD WINAPI jvmHealthPollerThread(LPVOID) {
    const DWORD intervalMs = 1500;
    std::unordered_map<DWORD, ULONGLONG> prevCpu;
    DWORD trackedPid = 0;
    int spinTicks = 0, stallTicks = 0;
    int deadlockTicks = 0;
    bool spinWarned = false, stallWarned = false, deadlockWarned = false;
    bool protectedTerminationSeen = false;
    unsigned long long lastNativeAllow = 0, lastNativeBlock = 0;
    unsigned long long lastProcessAllow = 0, lastProcessBlock = 0;
    unsigned long long lastHaltBlock = 0;
    unsigned long long lastTerminateBlock = 0;

    for (;;) {
        Sleep(intervalMs);
        /* Once the target has died and we're only keeping the window for review,
         * stop sampling — no point, and it would spam "not found" each tick. */
        if (g_jvmDiedPostMortem.load()) continue;
        DWORD pid = g_parentPid.load();
        if (pid == 0) { prevCpu.clear(); trackedPid = 0; continue; }
        if (pid != trackedPid) {
            prevCpu.clear();
            trackedPid = pid;
            spinTicks = stallTicks = deadlockTicks = 0;
            spinWarned = stallWarned = deadlockWarned = false;
            protectedTerminationSeen = false;
            lastNativeAllow = lastNativeBlock = 0;
            lastProcessAllow = lastProcessBlock = 0;
            lastHaltBlock = 0;
            lastTerminateBlock = 0;
            windowPublish("[JVM] tracking target pid=" + std::to_string(pid));
        }

        /* Write JVM_Halt lock heartbeat so the trampoline knows the agent is alive. */
        if (g_guardMode.load() && g_api != nullptr && g_api->haltLockHeartbeat != NULL) {
            g_api->haltLockHeartbeat();
        }

        /* Verify all inline hooks are still in place. An in-process adversary
         * may attempt to restore original bytes at hook sites (unhooking).
         * This detects tampering and re-applies the patch automatically. */
        if (g_guardMode.load() && g_api != nullptr && g_api->verifyHookIntegrity != NULL) {
            int repaired = g_api->verifyHookIntegrity();
            if (repaired > 0) {
                AGENT_LOG("guard: hook integrity check re-applied %d tampered hook(s)", repaired);
                windowPublish("[FVM] hook integrity: " + std::to_string(repaired) +
                              " hook(s) re-applied after tamper detection");
            }
        }

        /* The filter trampolines cannot log or use IPC safely (they may execute
         * under the Windows loader lock). Sample their private counters here so
         * a test trace distinguishes an allowed child/DLL from a blocked one. */
        if (g_api != nullptr && g_api->filterAudit != NULL) {
            unsigned long long nativeAllow = g_api->filterAudit(0);
            unsigned long long nativeBlock = g_api->filterAudit(1);
            unsigned long long processAllow = g_api->filterAudit(2);
            unsigned long long processBlock = g_api->filterAudit(3);
            unsigned long long haltBlock = g_api->filterAudit(4);
            unsigned long long terminateBlock = g_api->filterAudit(5);
            if (haltBlock > lastHaltBlock || terminateBlock > lastTerminateBlock) {
                protectedTerminationSeen = true;
                AGENT_LOG("guard: protected in-process termination attempt observed "
                          "(halt +%llu, terminate +%llu); automatic stall kill is suppressed",
                          haltBlock - lastHaltBlock, terminateBlock - lastTerminateBlock);
                windowPublish("[FVM] protected JVM termination attempt blocked; automatic stall kill suppressed");
            }
            if (nativeAllow != lastNativeAllow || nativeBlock != lastNativeBlock ||
                processAllow != lastProcessAllow || processBlock != lastProcessBlock ||
                haltBlock != lastHaltBlock || terminateBlock != lastTerminateBlock) {
                AGENT_LOG("filter-audit: native allow=%llu block=%llu; process allow=%llu block=%llu; halt block=%llu; terminate block=%llu",
                          nativeAllow, nativeBlock, processAllow, processBlock, haltBlock, terminateBlock);
                windowPublish("[FVM] filter audit | dll A/B " + std::to_string(nativeAllow) + "/" +
                              std::to_string(nativeBlock) + " | process A/B " +
                              std::to_string(processAllow) + "/" + std::to_string(processBlock) +
                              " | halt B " + std::to_string(haltBlock) +
                              " | terminate B " + std::to_string(terminateBlock));
                lastNativeAllow = nativeAllow;
                lastNativeBlock = nativeBlock;
                lastProcessAllow = processAllow;
                lastProcessBlock = processBlock;
                lastHaltBlock = haltBlock;
                lastTerminateBlock = terminateBlock;
            }
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        THREADENTRY32 te = {}; te.dwSize = sizeof(te);
        int threadCount = 0;
        ULONGLONG totalDelta = 0;
        DWORD hotTid = 0;
        ULONGLONG hotDelta = 0;
        std::unordered_map<DWORD, ULONGLONG> curCpu;

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                threadCount++;
                ULONGLONG cpu = threadCpu100ns(te.th32ThreadID);
                curCpu[te.th32ThreadID] = cpu;
                auto it = prevCpu.find(te.th32ThreadID);
                if (it != prevCpu.end() && cpu >= it->second) {
                    ULONGLONG d = cpu - it->second;
                    totalDelta += d;
                    if (d > hotDelta) { hotDelta = d; hotTid = te.th32ThreadID; }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        prevCpu.swap(curCpu);

        /* Only continuous process lifetime constitutes a stable recovery.
         * Rapid startup deaths therefore share one retry budget. */
        ULONGLONG stableSince = g_guardRecoveryStableSinceTick.load();
        if (stableSince != 0 && GetTickCount64() - stableSince >= kGuardStableRecoveryMs) {
            int priorDeaths = g_guardConsecutiveDeaths.exchange(0);
            g_guardRecoveryStableSinceTick.store(0);
            if (priorDeaths > 0) {
                AGENT_LOG("guard: recovered JVM pid=%lu stable for %llums; consecutive-death counter reset from %d",
                          pid, kGuardStableRecoveryMs, priorDeaths);
            }
        }

        if (threadCount == 0) {
            windowPublish("[JVM] target pid=" + std::to_string(pid) + " not found (exited?)");
            continue;
        }

        /* 100ns ticks → ms; one core fully busy over the interval = intervalMs ms. */
        ULONGLONG totalMs = totalDelta / 10000ULL;
        ULONGLONG hotMs   = hotDelta / 10000ULL;
        int hotPctOfCore  = (int)((hotMs * 100) / intervalMs);
        int totalPctOfCore = (int)((totalMs * 100) / intervalMs);

        std::string hot;
        if (hotTid != 0 && hotMs > 0) {
            std::string nm = threadName(hotTid);
            hot = " | hot:" + (nm.empty() ? ("tid" + std::to_string(hotTid)) : ("\"" + nm + "\""))
                + " " + std::to_string(hotPctOfCore) + "%core";
        }

        std::string line = "[JVM] alive | " + std::to_string(threadCount) + " thr | cpu "
                         + std::to_string(totalPctOfCore) + "%core" + hot;

        /* Spin: one thread pinned near a full core for several intervals. */
        if (hotPctOfCore >= 80) {
            if (++spinTicks >= 3 && !spinWarned) {
                std::string nm = threadName(hotTid);
                windowPublish("[JVM] ⚠ spin: " +
                    (nm.empty() ? ("tid" + std::to_string(hotTid)) : ("\"" + nm + "\"")) +
                    " pinned ~1 core for " + std::to_string(spinTicks * intervalMs / 1000) + "s");
                spinWarned = true;
            }
        } else { spinTicks = 0; spinWarned = false; }

        /* Stall: process alive but essentially no CPU anywhere — possible deadlock
         * or external thread suspension. After the first stall warning, attempt
         * to resume any externally suspended threads. */
        if (g_secureRelaunchPending.load()) {
            stallTicks = 0;
            stallWarned = false;
            deadlockTicks = 0;
            deadlockWarned = false;
        } else if (totalPctOfCore <= 1) {
            if (++stallTicks >= 4 && !stallWarned) {
                windowPublish("[JVM] ⚠ stall: no CPU activity for " +
                    std::to_string(stallTicks * intervalMs / 1000) + "s — possible deadlock");
                stallWarned = true;
                AGENT_LOG("guard: stall detected (pid=%lu, %d threads, 0%% CPU for %ds)",
                          pid, threadCount, stallTicks * intervalMs / 1000);
            }
            /* After the stall warning, try to resume suspended threads every tick.
             * If threads were externally suspended, this reverses it. If it's a
             * genuine Java-level deadlock, ResumeThread is a no-op (returns 0). */
            if (stallWarned && g_guardMode.load()) {
                int resumed = resumeSuspendedJvmThreads(pid);
                if (resumed > 0) {
                    AGENT_LOG("guard: anti-suspend: resumed %d externally suspended thread(s) in pid=%lu",
                              resumed, pid);
                    windowPublish("[FVM] anti-suspend: resumed " + std::to_string(resumed) +
                                  " thread(s) — external SuspendThread attack detected");
                    stallTicks = 0;
                    stallWarned = false;
                    deadlockTicks = 0;
                    deadlockWarned = false;
                } else {
                    /* No threads were suspended, so this is not an external suspend.
                     * CPU inactivity alone cannot distinguish a Java park from
                     * a deadlock. Report the condition, but never translate this
                     * heuristic into an FVM-authorized process termination. */
                    if (++deadlockTicks >= 3 && !deadlockWarned) {
                        AGENT_LOG("guard: prolonged zero-CPU stall observed (pid=%lu, %d ticks) — "
                                  "automatic kill suppressed (protectedTermination=%d)",
                                  pid, deadlockTicks, protectedTerminationSeen ? 1 : 0);
                        windowPublish("[FVM] prolonged JVM stall observed; automatic kill suppressed");
                        deadlockWarned = true;
                    } else if (deadlockTicks == 1) {
                        AGENT_LOG("guard: stall persists (pid=%lu, %d ticks) — no suspended threads found; "
                                  "possible Java park/deadlock; observation only", pid, stallTicks);
                    }
                }
            }
        } else {
            stallTicks = 0;
            stallWarned = false;
            deadlockTicks = 0;
            deadlockWarned = false;
        }

        windowPublish(line);
    }
    return 0;
}

static void startStatusWindow() {
    g_windowEnabled.store(true);
    CreateThread(NULL, 0, statusWindowThread, NULL, 0, NULL);
    CreateThread(NULL, 0, jvmHealthPollerThread, NULL, 0, NULL);
    AGENT_LOG("status window enabled");
}

} // namespace

int main(int argc, char** argv) {
    // Harden own process: deny terminate/vm/createthread/suspend/duphandle/writedac
    hardenSelfProcessDACL();

    bool serve = hasFlag("--serve", argc, argv);
    g_jvmLockRequested.store(hasFlag("--lock-jvm", argc, argv));
    g_guardMode.store(g_jvmLockRequested.load());

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

    /* Optional live status window: enabled by the --window flag (passed by Java
     * when the forgevm.window system property is set), the FORGEVM_WINDOW
     * environment variable, or forced on when --lock-jvm is active. */
    bool wantWindow = hasFlag("--window", argc, argv)
                   || hasFlag("--lock-jvm", argc, argv)
                   || GetEnvironmentVariableA("FORGEVM_WINDOW", NULL, 0) > 0;
    if (wantWindow) startStatusWindow();

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

    /* Publish dispatch context for the post-handoff command channels. */
    g_api = &api;
    g_cmdDllPath = dllPath;

    /* Gen0 (parent-spawned) phase: commands arrive on inherited stdin, replies
     * go to stdout (tls_replySink stays null). Serialized via g_commandMutex for
     * symmetry with the post-handoff channels. */
    std::string line;
    while (std::getline(std::cin, line)) {
        std::lock_guard<std::mutex> g(g_commandMutex);
        if (dispatchCommand(api, dllPath, g_lockState, line)) break;
    }

    while (g_lockState.locked && !lockExpired(g_lockState)) {
        Sleep(100);
    }

    /* If a relaunch or guard recovery armed persistence, our inherited stdin
     * (from the old JVM) just EOF'd. Don't exit — wait for the new JVM's
     * ForgeVM.launch() to connect to the handoff command pipe. Once the first
     * client connects (or the new JVM dies / never maps jvm.dll, handled by
     * acceptCommandPipeClient), serve it AND keep accepting further clients. */
    /* A guard recovery is initiated by the watchdog, which may observe the
     * process signal a few milliseconds after this inherited stdin reaches
     * EOF. Wait for it so the recovered JVM can use the same handoff pipe. */
    while (g_guardMode.load() && !g_persistAfterEOF.load()) {
        Sleep(25);
    }

    if (g_persistAfterEOF.load()) {
        AGENT_LOG("main: stdin EOF after relaunch — awaiting handoff on %s",
                  g_commandPipeName.c_str());
        HANDLE hJvm = g_relaunchNewJvm.exchange(NULL);
        HANDLE firstPipe = acceptCommandPipeClient(hJvm);
        if (hJvm != NULL) CloseHandle(hJvm);
        if (firstPipe != NULL && firstPipe != INVALID_HANDLE_VALUE) {
            AGENT_LOG("main: handoff client connected — serving multi-client command channels");
            g_persistAfterEOF.store(false);
            runCommandPipeServer(firstPipe);   // never returns; watchdog reaps on JVM death
        } else {
            AGENT_LOG("main: handoff accept failed — exiting");
        }
    }

    /* JVM is gone without a relaunch handoff. In lockJvm mode the agent keeps
     * its window open for post-mortem review (the operator closes the window to
     * quit). Without lockJvm, the agent exits cleanly — no zombie agents. */
    if (g_windowEnabled.load() && g_guardMode.load()) {
        g_jvmDiedPostMortem.store(true);
        windowPublish("[JVM] command stream ended — window kept open for review, close window to quit");
        for (;;) Sleep(1000);
    }

    if (g_windowEnabled.load()) {
        AGENT_LOG("main: JVM command stream ended — agent shutting down");
    }

    if (api.module != NULL) FreeLibrary(api.module);
    return 0;
}
