#include "forgevm_internal.h"

#include <tlhelp32.h>
#include <algorithm>
#include <mutex>

/* ============================================================
 * Global transform state
 * ============================================================ */

std::unordered_map<uint64_t, ClassTransformPlan> g_plans;

/* ── Deferred-transform state ─────────────────────────────────────────────────
 * A class that is loaded but not yet linked has no ConstantPoolCache: HotSpot
 * runs its rewriter (which allocates the cache and rewrites every method's
 * bytecode) only at link time. Committing a transform on such a class is
 * unsafe — HotSpot's link pipeline must run on a real, fully-formed metaspace
 * ConstantPool, not on the synthetic newCP we hand-build. So an unlinked target
 * is parked here and re-committed by the retry thread once the target links it
 * naturally (detected via oldCP._cache becoming non-NULL). */
struct PendingTransform {
    uint64_t                      klassAddr;
    std::vector<HookSpecExtended> specs;
};
static std::vector<PendingTransform> g_pendingTransforms;
/* Serializes ALL transform activity: commitClassPlan, unloadClassPlan, and the
 * retry thread. Held for the whole duration of each so they never interleave. */
static std::mutex                    g_transformLock;
static bool                          g_retryThreadStarted = false;

/* ============================================================
 * Klass / Method address cache
 *
 * findInstanceKlassByName traverses the entire ClassLoaderDataGraph (every
 * loaded class, every Symbol read via RPM) on each call. In a batch transform
 * (hundreds of transforms × 3-4 lookups each = many full scans) this dominates
 * wall time: each scan is O(class count) RPM reads, and a mature JVM may have
 * tens of thousands of loaded classes.
 *
 * Cached entries are stable for the lifetime of the target JVM as long as the
 * class isn't unloaded — the classes we cache (callback class, boxed primitives,
 * Object, hook classes, ingot target classes) are typically strong-referenced.
 *
 * Caches are cleared on Agent restart (process boundary), not within a session. */
static std::unordered_map<std::string, uint64_t> g_klassNameCache;

/* Method cache key: "klassAddr#methodName#paramDesc". paramDesc may be empty
 * (matches any descriptor — first-overload-wins, same as findMethodInKlass). */
static std::unordered_map<std::string, uint64_t> g_methodCache;

/* Set of klass addresses whose entire _methods array has been scanned and
 * fully populated into g_methodCache. Once a klass is here, any cache miss
 * on that klass means the method genuinely doesn't exist (only the methods
 * the klass declares itself live in _methods — inherited methods are not
 * in the array). Avoids redundant rescans when the same subclass is queried
 * for different methods by N ingots in batch. */
static std::unordered_set<uint64_t> g_klassMethodsScanned;

// Hit-rate counters (logged in forgevm_force_deopt_now).
static uint64_t g_klassCacheHits = 0;
static uint64_t g_klassCacheMisses = 0;
static uint64_t g_methodCacheHits = 0;
static uint64_t g_methodCacheMisses = 0;

static std::string methodCacheKey(uint64_t klassAddr, const char* methodName, const char* paramDesc) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llX#", (unsigned long long)klassAddr);
    return std::string(buf) + methodName + "#" + (paramDesc ? paramDesc : "");
}

static std::string makeTransformKey(const char* className, const char* methodName, const char* paramDesc) {
    return std::string(className) + "#" + methodName + "#" + paramDesc;
}

/* ============================================================
 * Parameter type parsing for argument capture
 * ============================================================ */

struct ParamSlotInfo {
    int slot;    // local variable slot index
    bool isRef;  // true if reference type (L...; or [...), false if primitive
};

/* Parse JVM method signature to extract parameter slot info.
 * fullSig format: "(Ljava/lang/String;I)V"
 * isStatic: if true, params start at slot 0; otherwise slot 0 = this, params start at slot 1. */
static std::vector<ParamSlotInfo> parseParamSlots(const std::string& fullSig, bool isStatic) {
    std::vector<ParamSlotInfo> params;
    if (fullSig.empty() || fullSig[0] != '(') return params;

    int slot = isStatic ? 0 : 1;
    size_t i = 1; // skip '('
    while (i < fullSig.size() && fullSig[i] != ')') {
        ParamSlotInfo p;
        p.slot = slot;
        char c = fullSig[i];

        if (c == 'L') {
            p.isRef = true;
            while (i < fullSig.size() && fullSig[i] != ';') i++;
            i++; // skip ';'
            slot++;
        } else if (c == '[') {
            p.isRef = true;
            while (i < fullSig.size() && fullSig[i] == '[') i++;
            if (i < fullSig.size() && fullSig[i] == 'L') {
                while (i < fullSig.size() && fullSig[i] != ';') i++;
                i++; // skip ';'
            } else {
                i++; // skip primitive component type
            }
            slot++;
        } else if (c == 'J' || c == 'D') {
            p.isRef = false;
            i++;
            slot += 2; // long/double occupy 2 slots
        } else {
            // B, C, F, I, S, Z
            p.isRef = false;
            i++;
            slot++;
        }
        params.push_back(p);
    }
    return params;
}

// suspendTargetThreads / resumeTargetThreads — defined in forgevm_memory.cpp, declared in forgevm_internal.h

/* ============================================================
 * Locate Java Method* in target process
 *
 * Path: SystemDictionary -> ClassLoaderData -> Klass chain
 *       -> InstanceKlass -> methods array -> Method*
 *
 * All done via ReadProcessMemory, no JVMTI.
 * ============================================================ */

/* Read a Symbol body from a HotSpot Symbol* (length at offset 0, body at offset 8 for 64-bit).
 * Already declared in forgevm_internal.h. */

// Convert "com.example.Foo" or "com/example/Foo" to internal form "com/example/Foo"
static std::string toInternalName(const char* name) {
    std::string result(name);
    for (char& c : result) {
        if (c == '.') c = '/';
    }
    return result;
}

// Read the name of a Klass by reading _name Symbol*
static bool readKlassName(HANDLE proc, uint64_t klassAddr, std::string* out) {
    int64_t nameOff = structOffset("Klass", "_name");
    if (nameOff < 0) nameOff = 32; // common default

    uint64_t symbolAddr = 0;
    if (!readRemotePointer(proc, klassAddr + (uint64_t)nameOff, &symbolAddr)) return false;
    if (symbolAddr == 0) return false;

    return readSymbolBody(proc, symbolAddr, out);
}

// Walk ClassLoaderData chain to find an InstanceKlass by name
bool findInstanceKlassByName(const std::string& internalName, uint64_t* outKlassAddr) {
    HANDLE proc = g_target.handle;

    // Cache hit: skip the full ClassLoaderDataGraph scan.
    auto cacheIt = g_klassNameCache.find(internalName);
    if (cacheIt != g_klassNameCache.end()) {
        *outKlassAddr = cacheIt->second;
        g_klassCacheHits++;
        return true;
    }
    g_klassCacheMisses++;

    /* Get SystemDictionary via gHotSpotVMStructs.
     * SystemDictionary::_loader_data is the head of ClassLoaderData linked list.
     * The actual path depends on JDK version — try multiple approaches. */

    // Approach: scan all loaded classes via ClassLoaderDataGraph::_head
    uint64_t cldgHeadAddr = structStaticAddr("ClassLoaderDataGraph", "_head");
    if (cldgHeadAddr == 0) {
        // Older JDK: try ClassLoaderData::_head
        cldgHeadAddr = structStaticAddr("ClassLoaderData", "_head");
    }

    if (cldgHeadAddr == 0) {
        setError("cannot_find_ClassLoaderDataGraph_head");
        return false;
    }

    uint64_t cldAddr = 0;
    if (!readRemotePointer(proc, cldgHeadAddr, &cldAddr) || cldAddr == 0) {
        setError("ClassLoaderDataGraph_head_is_null");
        return false;
    }

    int64_t cldNextOff = structOffset("ClassLoaderData", "_next");
    if (cldNextOff < 0) cldNextOff = 8; // fallback

    int64_t cldKlassesOff = structOffset("ClassLoaderData", "_klasses");
    if (cldKlassesOff < 0) cldKlassesOff = 16; // fallback

    int64_t klassNextOff = structOffset("Klass", "_next_link");
    if (klassNextOff < 0) {
        // Try InstanceKlass specific
        klassNextOff = structOffset("InstanceKlass", "_next_link");
    }
    if (klassNextOff < 0) klassNextOff = -1; // will skip klass chain walk

    // Walk ClassLoaderData linked list
    for (int cldCount = 0; cldAddr != 0 && cldCount < 10000; cldCount++) {
        // Read first klass in this CLD
        uint64_t klassAddr = 0;
        readRemotePointer(proc, cldAddr + (uint64_t)cldKlassesOff, &klassAddr);

        // Walk klass linked list within this CLD
        for (int klassCount = 0; klassAddr != 0 && klassCount < 100000; klassCount++) {
            std::string name;
            if (readKlassName(proc, klassAddr, &name)) {
                if (name == internalName) {
                    *outKlassAddr = klassAddr;
                    g_klassNameCache[internalName] = klassAddr;
                    return true;
                }
            }

            // Next klass in chain
            if (klassNextOff < 0) break;
            uint64_t nextKlass = 0;
            if (!readRemotePointer(proc, klassAddr + (uint64_t)klassNextOff, &nextKlass)) break;
            klassAddr = nextKlass;
        }

        // Next ClassLoaderData
        uint64_t nextCld = 0;
        if (!readRemotePointer(proc, cldAddr + (uint64_t)cldNextOff, &nextCld)) break;
        cldAddr = nextCld;
    }

    setError("class_not_found:" + internalName);
    return false;
}

// Find a Method* within an InstanceKlass by method name and parameter descriptor
static bool findMethodInKlass(uint64_t klassAddr, const char* methodName, const char* paramDesc,
                               uint64_t* outMethodAddr) {
    HANDLE proc = g_target.handle;

    /* Cache hit: skip Method array scan and Symbol reads. The combination of
     * (klassAddr, methodName, paramDesc) uniquely identifies a Method* until
     * the class is unloaded — which we don't expect during a transform batch. */
    std::string mcKey = methodCacheKey(klassAddr, methodName, paramDesc);
    auto mcIt = g_methodCache.find(mcKey);
    if (mcIt != g_methodCache.end()) {
        g_methodCacheHits++;
        if (mcIt->second == 0) {
            // Negative entry: previously confirmed this method does not exist.
            setError(std::string("method_not_found:") + methodName);
            return false;
        }
        *outMethodAddr = mcIt->second;
        return true;
    }
    /* Cache miss but the klass's full _methods array has already been scanned
     * — the method genuinely is not declared on this klass (might exist on
     * an ancestor, but findMethodInKlass intentionally only inspects the
     * klass's own _methods, not inherited ones). Skip the rescan. */
    if (g_klassMethodsScanned.count(klassAddr) > 0) {
        g_methodCacheHits++;
        g_methodCache[mcKey] = 0;  // memoize this exact tuple too
        setError(std::string("method_not_found:") + methodName);
        return false;
    }
    g_methodCacheMisses++;

    // InstanceKlass::_methods is an Array<Method*>*
    int64_t methodsOff = structOffset("InstanceKlass", "_methods");
    if (methodsOff < 0) {
        setError("cannot_find_InstanceKlass_methods_offset");
        return false;
    }

    uint64_t methodsArrayAddr = 0;
    if (!readRemotePointer(proc, klassAddr + (uint64_t)methodsOff, &methodsArrayAddr) || methodsArrayAddr == 0) {
        setError("methods_array_is_null");
        return false;
    }

    /* Array<Method*> layout: _length (int32 at offset 0, or after metadata pointer).
     * In HotSpot, Array<T> has: int _length at a known offset, then T _data[]. */
    int64_t arrayLengthOff = structOffset("Array<int>", "_length");
    if (arrayLengthOff < 0) arrayLengthOff = 0; // common for older JDKs

    int64_t arrayDataOff = structOffset("Array<int>", "_data");
    if (arrayDataOff < 0) arrayDataOff = arrayLengthOff + 4; // length is int32, data follows
    // For pointer arrays, data is typically aligned to 8
    if (arrayDataOff < 8) arrayDataOff = 8;

    int32_t methodCount = 0;
    if (!readRemoteI32(proc, methodsArrayAddr + (uint64_t)arrayLengthOff, &methodCount)) {
        setError("cannot_read_methods_count");
        return false;
    }
    if (methodCount <= 0 || methodCount > 100000) {
        setError("invalid_methods_count:" + std::to_string(methodCount));
        return false;
    }

    // Read Method* pointers
    std::vector<uint64_t> methodPtrs(methodCount);
    if (!readRemoteMem(proc, methodsArrayAddr + (uint64_t)arrayDataOff,
                       methodPtrs.data(), methodCount * 8)) {
        setError("cannot_read_method_pointers");
        return false;
    }

    // For each Method*, read its name via ConstMethod -> _name Symbol*
    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    int64_t cmNameOff = structOffset("ConstMethod", "_name");
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;
    int64_t nameIdxOff = structOffset("ConstMethod", "_name_index");
    int64_t sigIdxOff = structOffset("ConstMethod", "_signature_index");
    int64_t cpHeaderSize = typeSize("ConstantPool");
    if (cpHeaderSize < 0) cpHeaderSize = 0x138;

    std::string targetName(methodName);
    bool found = false;
    uint64_t foundAddr = 0;

    /*
     * Scan the entire methods array exactly once and populate the method cache
     * for every entry, so subsequent queries on this klass hit the cache rather
     * than rescanning. Dominant in batch loads with includeSubclasses, where a
     * deep class hierarchy multiplied by the ingot count would otherwise turn
     * every miss into a full O(methods) scan.
     */
    for (int i = 0; i < methodCount; i++) {
        uint64_t methodAddr = methodPtrs[i];
        if (methodAddr == 0) continue;

        // Method -> ConstMethod
        uint64_t constMethodAddr = 0;
        if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &constMethodAddr) || constMethodAddr == 0) {
            continue;
        }

        std::string mName, mSig;
        bool nameFound = false;

        // Try direct Symbol* approach (ConstMethod::_name in some JDK builds)
        if (cmNameOff >= 0) {
            uint64_t nameSymbolAddr = 0;
            if (readRemotePointer(proc, constMethodAddr + (uint64_t)cmNameOff, &nameSymbolAddr) && nameSymbolAddr != 0) {
                if (readSymbolBody(proc, nameSymbolAddr, &mName)) {
                    nameFound = true;
                }
            }
        }

        /* Read name and signature via ConstantPool indices (for caching the
         * signature key — we want every method individually addressable by
         * (klass, name, paramDesc) for future lookups). */
        uint64_t constPoolAddr = 0;
        if (!nameFound && nameIdxOff >= 0) {
            if (!readRemotePointer(proc, constMethodAddr + (uint64_t)cmConstsOff, &constPoolAddr) || constPoolAddr == 0) {
                continue;
            }
            uint16_t nameIndex = 0;
            if (!readRemoteU16(proc, constMethodAddr + (uint64_t)nameIdxOff, &nameIndex)) continue;

            uint64_t nameEntryAddr = constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)nameIndex * 8;
            uint64_t nameSymbol = 0;
            if (!readRemotePointer(proc, nameEntryAddr, &nameSymbol) || nameSymbol == 0) continue;
            if (!readSymbolBody(proc, nameSymbol, &mName)) continue;
            nameFound = true;
        }

        if (!nameFound) continue;

        // Read signature for caching and (when given) match against paramDesc.
        if (sigIdxOff >= 0) {
            if (constPoolAddr == 0) {
                if (!readRemotePointer(proc, constMethodAddr + (uint64_t)cmConstsOff, &constPoolAddr) || constPoolAddr == 0) {
                    constPoolAddr = 0;
                }
            }
            if (constPoolAddr != 0) {
                uint16_t sigIndex = 0;
                if (readRemoteU16(proc, constMethodAddr + (uint64_t)sigIdxOff, &sigIndex)) {
                    uint64_t sigEntryAddr = constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)sigIndex * 8;
                    uint64_t sigSymbol = 0;
                    if (readRemotePointer(proc, sigEntryAddr, &sigSymbol) && sigSymbol != 0) {
                        readSymbolBody(proc, sigSymbol, &mSig);
                    }
                }
            }
        }

        /* Cache by signature (full match) and by empty desc (any-overload-wins,
         * first method with this name in the array). Both forms used by
         * findMethodInKlass / findJavaMethod call sites. */
        if (!mSig.empty()) {
            std::string sigKey = methodCacheKey(klassAddr, mName.c_str(), mSig.c_str());
            if (g_methodCache.find(sigKey) == g_methodCache.end()) {
                g_methodCache[sigKey] = methodAddr;
            }
            /* Also cache "params" prefix form (e.g. "(F)") — the paramDesc
             * arg in our API is typically the parameter list portion, not full sig. */
            size_t closeParen = mSig.find(')');
            if (closeParen != std::string::npos) {
                std::string paramsOnly = mSig.substr(0, closeParen + 1);
                std::string paramKey = methodCacheKey(klassAddr, mName.c_str(), paramsOnly.c_str());
                if (g_methodCache.find(paramKey) == g_methodCache.end()) {
                    g_methodCache[paramKey] = methodAddr;
                }
            }
        }
        std::string anyKey = methodCacheKey(klassAddr, mName.c_str(), "");
        if (g_methodCache.find(anyKey) == g_methodCache.end()) {
            g_methodCache[anyKey] = methodAddr;
        }

        // Match against caller's request.
        if (!found && mName == targetName) {
            bool descMatches = true;
            if (paramDesc != nullptr && paramDesc[0] != '\0' && !mSig.empty()) {
                if (mSig.find(paramDesc) != 0 && mSig != paramDesc) {
                    descMatches = false;
                }
            }
            if (descMatches) {
                found = true;
                foundAddr = methodAddr;
            }
        }
    }

    /* Mark this klass as fully scanned so any subsequent miss on it can
     * short-circuit to "not found" without rescanning the methods array. */
    g_klassMethodsScanned.insert(klassAddr);

    if (found) {
        *outMethodAddr = foundAddr;
        return true;
    }

    // Negative cache for this specific tuple too.
    g_methodCache[mcKey] = 0;
    setError("method_not_found:" + targetName);
    return false;
}

bool findJavaMethod(const char* className, const char* methodName,
                    const char* paramDesc, uint64_t* outMethodAddr) {
    std::string internalName = toInternalName(className);

    uint64_t klassAddr = 0;
    if (!findInstanceKlassByName(internalName, &klassAddr)) {
        return false;
    }

    return findMethodInKlass(klassAddr, methodName, paramDesc, outMethodAddr);
}

/* ============================================================
 * Force deoptimization of all compiled methods
 *
 * JIT may inline the target method into callers. Modifying the
 * target Method*'s ConstMethod does NOT affect inlined copies.
 * We must mark all nmethods as "not_entrant" so the JVM
 * deoptimizes them at the next safepoint and re-interprets
 * (picking up our new bytecodes on re-compilation).
 * ============================================================ */

/* forceDeoptimizeAll — §17.11: only clear Method::_code, no c2i adapter probing.
 * Callers use the normal interpreted entry after JIT deopt; the JVM re-adapts via
 * the interpreter stub. c2i redirect is not needed for same-user, same-session targets. */
static void forceDeoptimizeAll() {
    HANDLE proc = g_target.handle;

    int64_t codeOff = structOffset("Method", "_code");
    if (codeOff < 0) {
        FVM_LOG("WARN: Method::_code not in VMStructs, cannot deoptimize");
        return;
    }

    int64_t nmethodStateOff = structOffset("nmethod", "_state");
    if (nmethodStateOff < 0) nmethodStateOff = structOffset("CompiledMethod", "_state");

    uint64_t cldgHeadAddr = structStaticAddr("ClassLoaderDataGraph", "_head");
    if (cldgHeadAddr == 0) cldgHeadAddr = structStaticAddr("ClassLoaderData", "_head");
    if (cldgHeadAddr == 0) {
        FVM_LOG("WARN: CLDG not found, cannot deoptimize");
        return;
    }

    uint64_t cldAddr = 0;
    if (!readRemotePointer(proc, cldgHeadAddr, &cldAddr) || cldAddr == 0) return;

    int64_t cldNextOff = structOffset("ClassLoaderData", "_next");
    if (cldNextOff < 0) cldNextOff = 8;
    int64_t cldKlassesOff = structOffset("ClassLoaderData", "_klasses");
    if (cldKlassesOff < 0) cldKlassesOff = 16;
    int64_t klassNextOff = structOffset("Klass", "_next_link");
    if (klassNextOff < 0) klassNextOff = structOffset("InstanceKlass", "_next_link");

    int64_t methodsOff = structOffset("InstanceKlass", "_methods");
    if (methodsOff < 0) { FVM_LOG("WARN: _methods not found"); return; }

    int64_t arrayLengthOff = structOffset("Array<int>", "_length");
    if (arrayLengthOff < 0) arrayLengthOff = 0;
    int64_t arrayDataOff = structOffset("Array<int>", "_data");
    if (arrayDataOff < 0) arrayDataOff = arrayLengthOff + 4;
    if (arrayDataOff < 8) arrayDataOff = 8;

    int deoptCount = 0, klassCount = 0;

    for (int cldC = 0; cldAddr != 0 && cldC < 10000; cldC++) {
        uint64_t kAddr = 0;
        readRemotePointer(proc, cldAddr + (uint64_t)cldKlassesOff, &kAddr);

        for (int kc = 0; kAddr != 0 && kc < 100000; kc++) {
            klassCount++;
            uint64_t mArr = 0;
            if (readRemotePointer(proc, kAddr + (uint64_t)methodsOff, &mArr) && mArr != 0) {
                int32_t mc = 0;
                if (readRemoteI32(proc, mArr + (uint64_t)arrayLengthOff, &mc)
                    && mc > 0 && mc < 100000) {
                    std::vector<uint64_t> mps((size_t)mc);
                    if (readRemoteMem(proc, mArr + (uint64_t)arrayDataOff,
                                      mps.data(), (size_t)mc * 8)) {
                        for (int m = 0; m < mc; m++) {
                            if (mps[m] == 0) continue;
                            uint64_t nm = 0;
                            if (!readRemotePointer(proc, mps[m] + (uint64_t)codeOff, &nm) || nm == 0)
                                continue;
                            if (nmethodStateOff >= 0) {
                                uint8_t notEntrant = 1;
                                writeRemoteMem(proc, nm + (uint64_t)nmethodStateOff, &notEntrant, 1);
                            }
                            uint64_t zero = 0;
                            writeRemoteMem(proc, mps[m] + (uint64_t)codeOff, &zero, 8);
                            deoptCount++;
                        }
                    }
                }
            }
            if (klassNextOff < 0) break;
            uint64_t nk = 0;
            if (!readRemotePointer(proc, kAddr + (uint64_t)klassNextOff, &nk)) break;
            kAddr = nk;
        }

        uint64_t nextCld = 0;
        if (!readRemotePointer(proc, cldAddr + (uint64_t)cldNextOff, &nextCld)) break;
        cldAddr = nextCld;
    }

    FVM_LOG("deopt sweep: visited %d classes, deopt %d methods", klassCount, deoptCount);
}

/* ============================================================
 * Read ConstMethod bytecode
 * ============================================================ */

bool readConstMethodBytecode(uint64_t constMethodAddr, std::vector<uint8_t>* bytecodeOut,
                             uint64_t* bytecodeStartAddr, uint32_t* codeSizeOut) {
    HANDLE proc = g_target.handle;

    // ConstMethod::_code_size is a u2 field
    int64_t codeSizeOff = structOffset("ConstMethod", "_code_size");
    if (codeSizeOff < 0) {
        setError("cannot_find_ConstMethod_code_size_offset");
        return false;
    }

    uint16_t codeSize = 0;
    if (!readRemoteU16(proc, constMethodAddr + (uint64_t)codeSizeOff, &codeSize) || codeSize == 0) {
        setError("cannot_read_code_size");
        return false;
    }

    // Bytecode starts right after the ConstMethod fixed header
    int64_t constMethodSize = typeSize("ConstMethod");
    if (constMethodSize < 0) {
        setError("cannot_find_ConstMethod_type_size");
        return false;
    }

    uint64_t bcStart = constMethodAddr + (uint64_t)constMethodSize;

    bytecodeOut->resize(codeSize);
    if (!readRemoteMem(proc, bcStart, bytecodeOut->data(), codeSize)) {
        setError("cannot_read_bytecode");
        return false;
    }

    *bytecodeStartAddr = bcStart;
    *codeSizeOut = codeSize;
    return true;
}

/* ============================================================
 * Read ConstantPool
 * ============================================================ */

bool readConstantPool(uint64_t constPoolAddr, std::vector<uint8_t>* poolBytesOut,
                      uint32_t* poolLengthOut, size_t* poolByteSizeOut) {
    HANDLE proc = g_target.handle;

    // ConstantPool::_length is an int (number of entries)
    int64_t lengthOff = structOffset("ConstantPool", "_length");
    if (lengthOff < 0) {
        setError("cannot_find_ConstantPool_length_offset");
        return false;
    }

    int32_t length = 0;
    if (!readRemoteI32(proc, constPoolAddr + (uint64_t)lengthOff, &length) || length <= 0) {
        setError("cannot_read_constpool_length");
        return false;
    }

    int64_t headerSize = typeSize("ConstantPool");
    if (headerSize < 0) {
        setError("cannot_find_ConstantPool_type_size");
        return false;
    }

    // Total size = header + length * sizeof(intptr_t)
    size_t totalSize = (size_t)headerSize + (size_t)length * 8;

    poolBytesOut->resize(totalSize);
    if (!readRemoteMem(proc, constPoolAddr, poolBytesOut->data(), totalSize)) {
        setError("cannot_read_constpool_bytes");
        return false;
    }

    *poolLengthOut = (uint32_t)length;
    *poolByteSizeOut = totalSize;
    return true;
}

/* ============================================================
 * Build expanded ConstantPool with hook MethodRef
 *
 * We append new entries to the constant pool:
 *   [origLength]     = CONSTANT_Class(hookClass)  -> name_index = origLength+2
 *   [origLength+1]   = CONSTANT_NameAndType(hookMethod, hookDesc) -> name = origLength+3, desc = origLength+4
 *   [origLength+2]   = CONSTANT_Utf8(hookClass internal name)
 *   [origLength+3]   = CONSTANT_Utf8(hookMethod name)
 *   [origLength+4]   = CONSTANT_Utf8(hookDesc)
 *   [origLength+5]   = CONSTANT_Methodref -> class = origLength, nat = origLength+1
 *
 * HotSpot ConstantPool entries are pointer-sized slots with tag array separate.
 * The "entries" in HotSpot's ConstantPool are NOT the same as classfile cp_info;
 * they are resolved at load time into raw pointers/values. For an unresolved
 * Methodref, HotSpot stores it as indices packed into a single slot. We need
 * entries that the interpreter can resolve.
 *
 * CRITICAL: HotSpot resolves methods by comparing Symbol* POINTERS, not string
 * content. We MUST use the JVM's existing interned Symbol* pointers, not freshly
 * allocated ones. Read them from the Klass/Method metadata that already exists
 * in the target process.
 * ============================================================ */

// Read the interned name Symbol* pointer from an InstanceKlass
static uint64_t readKlassNameSymbol(uint64_t klassAddr) {
    HANDLE proc = g_target.handle;
    int64_t nameOff = structOffset("Klass", "_name");
    if (nameOff < 0) nameOff = structOffset("InstanceKlass", "_name");
    if (nameOff < 0) {
        FVM_LOG("WARN: cannot find Klass::_name offset");
        return 0;
    }
    uint64_t sym = 0;
    if (!readRemotePointer(proc, klassAddr + (uint64_t)nameOff, &sym)) return 0;
    return sym;
}

// Read the interned name and signature Symbol* pointers from a Method*
static bool readMethodSymbols(uint64_t methodAddr, uint64_t* nameSymOut, uint64_t* sigSymOut) {
    HANDLE proc = g_target.handle;

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t constMethodAddr = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &constMethodAddr) || constMethodAddr == 0)
        return false;

    // Try direct Symbol* approach (ConstMethod::_name / _signature in some JDK builds)
    int64_t cmNameOff = structOffset("ConstMethod", "_name");
    int64_t cmSigOff  = structOffset("ConstMethod", "_signature");

    if (cmNameOff >= 0 && cmSigOff >= 0) {
        uint64_t nameSym = 0, sigSym = 0;
        if (readRemotePointer(proc, constMethodAddr + (uint64_t)cmNameOff, &nameSym) && nameSym != 0 &&
            readRemotePointer(proc, constMethodAddr + (uint64_t)cmSigOff, &sigSym) && sigSym != 0) {
            // Validate: check that these look like Symbol pointers (body offset check)
            std::string test;
            if (readSymbolBody(proc, nameSym, &test) && !test.empty()) {
                *nameSymOut = nameSym;
                *sigSymOut = sigSym;
                return true;
            }
        }
    }

    // Fallback: read via ConstantPool + name_index/signature_index
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;
    int64_t nameIdxOff = structOffset("ConstMethod", "_name_index");
    int64_t sigIdxOff  = structOffset("ConstMethod", "_signature_index");
    if (nameIdxOff < 0 || sigIdxOff < 0) return false;

    uint64_t constPoolAddr = 0;
    if (!readRemotePointer(proc, constMethodAddr + (uint64_t)cmConstsOff, &constPoolAddr) || constPoolAddr == 0)
        return false;

    uint16_t nameIndex = 0, sigIndex = 0;
    if (!readRemoteU16(proc, constMethodAddr + (uint64_t)nameIdxOff, &nameIndex)) return false;
    if (!readRemoteU16(proc, constMethodAddr + (uint64_t)sigIdxOff, &sigIndex)) return false;

    int64_t cpHeaderSize = typeSize("ConstantPool");
    if (cpHeaderSize < 0) cpHeaderSize = 0x138;

    uint64_t nameSym = 0, sigSym = 0;
    if (!readRemotePointer(proc, constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)nameIndex * 8, &nameSym) || nameSym == 0)
        return false;
    if (!readRemotePointer(proc, constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)sigIndex * 8, &sigSym) || sigSym == 0)
        return false;

    *nameSymOut = nameSym;
    *sigSymOut = sigSym;
    return true;
}

/* ============================================================
 * Phase 1 invalidation: clear stale profiling state on Method*
 *
 * After replacing ConstMethod, the existing MDO is keyed against the
 * OLD bytecode's BCIs. If C1/C2 reads it during recompile, ciMethodData
 * hits ShouldNotReachHere(). Counters likewise reflect the old shape.
 *
 *   _method_data     = NULL  -> fresh MDO allocated on next compile
 *   _method_counters = NULL  -> invocation count restarts
 *   _flags |= 0x4 (_dont_inline) -> blocks stale inlines until callers
 *                                   are deopted (Phase 2)
 *
 * _flags is not always in VMStructs; skip silently if absent.
 * ============================================================ */
static void clearMethodProfilingState(uint64_t methodAddr, bool setDontInline,
                                      const char* logPrefix) {
    HANDLE proc = g_target.handle;

    int64_t mdoOff = structOffset("Method", "_method_data");
    if (mdoOff >= 0) {
        uint64_t zero = 0;
        if (writeRemoteMem(proc, methodAddr + (uint64_t)mdoOff, &zero, 8)) {
            FVM_LOG("%s: cleared Method::_method_data (offset %lld)",
                    logPrefix, (long long)mdoOff);
        } else {
            FVM_LOG("%s: WARN failed to clear Method::_method_data", logPrefix);
        }
    } else {
        FVM_LOG("%s: WARN Method::_method_data not in VMStructs, skipped", logPrefix);
    }

    int64_t mcOff = structOffset("Method", "_method_counters");
    if (mcOff >= 0) {
        uint64_t zero = 0;
        if (writeRemoteMem(proc, methodAddr + (uint64_t)mcOff, &zero, 8)) {
            FVM_LOG("%s: cleared Method::_method_counters (offset %lld)",
                    logPrefix, (long long)mcOff);
        } else {
            FVM_LOG("%s: WARN failed to clear Method::_method_counters", logPrefix);
        }
    } else {
        FVM_LOG("%s: WARN Method::_method_counters not in VMStructs, skipped", logPrefix);
    }

    if (setDontInline) {
        int64_t flagsOff = structOffset("Method", "_flags");
        if (flagsOff >= 0) {
            uint16_t flags = 0;
            if (readRemoteMem(proc, methodAddr + (uint64_t)flagsOff, &flags, 2)) {
                uint16_t newFlags = (uint16_t)(flags | 0x4); // _dont_inline
                if (newFlags == flags) {
                    FVM_LOG("%s: _dont_inline already set (Method::_flags = 0x%X)",
                            logPrefix, (unsigned)flags);
                } else if (writeRemoteMem(proc, methodAddr + (uint64_t)flagsOff, &newFlags, 2)) {
                    FVM_LOG("%s: set _dont_inline (Method::_flags 0x%X -> 0x%X, offset %lld)",
                            logPrefix, (unsigned)flags, (unsigned)newFlags, (long long)flagsOff);
                } else {
                    FVM_LOG("%s: WARN failed to write Method::_flags", logPrefix);
                }
            } else {
                FVM_LOG("%s: WARN failed to read Method::_flags", logPrefix);
            }
        } else {
            FVM_LOG("%s: NOTE Method::_flags not in VMStructs, _dont_inline skipped",
                    logPrefix);
        }

        /* Also mark as not-compilable by C1/C2/C2-OSR so the JIT never reads our
           CPCache-indexed trampoline bytecodes (which are unreadable to C2's parser).
           JVM_ACC_NOT_C1_COMPILABLE = 0x80000, NOT_C2 = 0x100000, NOT_C2_OSR = 0x200000 */
        int64_t afOff = structOffset("Method", "_access_flags");
        if (afOff >= 0) {
            uint32_t af = 0;
            if (readRemoteU32(proc, methodAddr + (uint64_t)afOff, &af)) {
                uint32_t newAF = af | 0x80000u | 0x100000u | 0x200000u;
                if (newAF != af) {
                    if (writeRemoteMem(proc, methodAddr + (uint64_t)afOff, &newAF, 4)) {
                        FVM_LOG("%s: set NOT_C1/C2_COMPILABLE (_access_flags 0x%X->0x%X)",
                                logPrefix, (unsigned)af, (unsigned)newAF);
                    } else {
                        FVM_LOG("%s: WARN failed to write _access_flags", logPrefix);
                    }
                }
            }
        } else {
            FVM_LOG("%s: NOTE Method::_access_flags not in VMStructs, not-compilable not set",
                    logPrefix);
        }
    }
}

/* ============================================================
 * Exported DLL functions
 * ============================================================ */

/* ============================================================
 * Purge Agent — disable a loaded Java agent entirely.
 *
 * Strategy:
 *   1. Enumerate ClassLoaderDataGraph; an "agent main class" is any
 *      InstanceKlass with a static field whose declared type is
 *      sun/instrument/InstrumentationImpl or java/lang/instrument/Instrumentation.
 *   2. For each candidate, resolve its source jar via
 *      Klass._java_mirror -> Class.protection_domain ->
 *      CodeSource.location -> URL.path (and protocol). This is the same
 *      jar identity the JVM_EnqueueOperation trampoline observes for
 *      future attach attempts, so a single jar-path glob filter covers
 *      both arms of the ban.
 *   3. Apply the filter; for each match, null the agent's static
 *      Instrumentation reference + its mTransformerManager + overwrite
 *      premain/agentmain bytecode with a bare return.
 *
 * No class-name input from the caller — purge is byproduct of ban.
 * ============================================================ */

static bool clearMethodBody(uint64_t klassAddr, const char* methodName) {
    HANDLE proc = g_target.handle;
    uint64_t methodAddr = 0;
    if (!findMethodInKlass(klassAddr, methodName, "", &methodAddr) || methodAddr == 0) {
        FVM_LOG("purge_agent: method '%s' not found (may not exist)", methodName);
        return false;
    }

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t constMethodAddr = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &constMethodAddr) || constMethodAddr == 0) {
        return false;
    }

    uint32_t codeSize = 0;
    std::vector<uint8_t> bytecode;
    uint64_t bytecodeStart = 0;
    if (!readConstMethodBytecode(constMethodAddr, &bytecode, &bytecodeStart, &codeSize)) {
        return false;
    }
    if (codeSize == 0 || bytecodeStart == 0) return false;

    std::vector<uint8_t> cleared(codeSize, 0x00);
    cleared[0] = 0xB1; // return void

    if (!writeRemoteMem(proc, bytecodeStart, cleared.data(), codeSize)) return false;

    FVM_LOG("purge_agent: cleared method '%s' bytecode (%u bytes) at 0x%llX",
            methodName, codeSize, bytecodeStart);
    return true;
}

/* Glob match: '*' any run, '?' single char. Case-insensitive, '\\' == '/'.
 * Mirrors the agent-side trampoline filter so future-attach and purge
 * semantics stay identical. */
static bool agentGlobMatch(const std::string& pattern, const std::string& text) {
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

/* Read a java.lang.String oop into a UTF-8 std::string.
 * Handles JDK 9+ byte[]+coder layout (Latin1 / UTF-16) and JDK 8 char[].
 * Returns true on success with `out` populated. */
static bool readJavaString(uint64_t stringOop, std::string& out) {
    out.clear();
    if (stringOop == 0) return false;
    HANDLE proc = g_target.handle;

    /* Oop layout: markWord(8) + klass(4 compressed | 8 uncompressed) at offset 8. */
    uint64_t strKlass = readKlass(proc, stringOop + 8, g_target.useCompressedClassPointers);
    if (strKlass == 0) return false;

    ResolvedField valueField = {};
    if (!resolveFieldInKlass(strKlass, "value", "", &valueField)) return false;
    if (valueField.isStatic) return false;

    uint64_t arrOop = readOop(proc, stringOop + (uint64_t)valueField.offset,
                              g_target.useCompressedOops);
    if (arrOop == 0) return false;

    /* JDK 9+ has String.coder (byte); JDK 8 does not. */
    bool hasCoder = false;
    uint8_t coder = 0;
    ResolvedField coderField = {};
    if (resolveFieldInKlass(strKlass, "coder", "", &coderField) && !coderField.isStatic) {
        if (readRemoteMem(proc, stringOop + (uint64_t)coderField.offset, &coder, 1)) {
            hasCoder = true;
        }
    }

    /* arrayOop layout: markWord(8) + klass(4|8) + length(int32) + padding + data.
     * With compressed klass: length@12, data@16.
     * Without: length@16, data@20. */
    int arrLengthOff = g_target.useCompressedClassPointers ? 12 : 16;
    int arrDataOff   = g_target.useCompressedClassPointers ? 16 : 20;

    int32_t arrLen = 0;
    if (!readRemoteI32(proc, arrOop + (uint64_t)arrLengthOff, &arrLen)) return false;
    if (arrLen < 0 || arrLen > (1 << 20)) return false;
    if (arrLen == 0) return true;

    auto pushUtf8 = [&out](uint32_t c) {
        if (c < 0x80) {
            out.push_back((char)c);
        } else if (c < 0x800) {
            out.push_back((char)(0xC0 | (c >> 6)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else {
            out.push_back((char)(0xE0 | (c >> 12)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        }
    };

    if (hasCoder) {
        /* byte[]: coder=0 Latin1 (1 byte/char), coder=1 UTF-16LE (2 bytes/char).
         * arrLen is the byte count of the underlying array. */
        std::vector<uint8_t> bytes(arrLen);
        if (!readRemoteMem(proc, arrOop + (uint64_t)arrDataOff, bytes.data(), arrLen)) return false;
        if (coder == 0) {
            for (uint8_t b : bytes) pushUtf8(b);
        } else {
            for (int32_t i = 0; i + 1 < arrLen; i += 2) {
                uint16_t c = (uint16_t)bytes[i] | ((uint16_t)bytes[i + 1] << 8);
                pushUtf8(c);
            }
        }
    } else {
        /* JDK 8 char[]: 2 bytes per element, arrLen is char count. */
        std::vector<uint8_t> bytes((size_t)arrLen * 2);
        if (!readRemoteMem(proc, arrOop + (uint64_t)arrDataOff, bytes.data(), bytes.size())) return false;
        for (int32_t i = 0; i < arrLen; i++) {
            uint16_t c = (uint16_t)bytes[i * 2] | ((uint16_t)bytes[i * 2 + 1] << 8);
            pushUtf8(c);
        }
    }
    return true;
}

/* Read an int constant stored at a VMStructs static field address. */
static int32_t readStaticInt32(const std::string& typeName, const std::string& fieldName, int32_t fallback) {
    uint64_t addr = structStaticAddr(typeName, fieldName);
    if (addr == 0) return fallback;
    int32_t value = 0;
    if (!readRemoteI32(g_target.handle, addr, &value)) return fallback;
    return value;
}

/* Walk Klass._java_mirror -> Class.protection_domain -> CodeSource.location
 * -> URL.{protocol,path}, returning a normalized filesystem path to the agent
 * jar. Returns false when any link in the chain is null (boot loader agents,
 * dynamically-generated classes — these have no jar identity). */
static bool resolveAgentJarPath(uint64_t klassAddr, std::string& outPath) {
    HANDLE proc = g_target.handle;
    outPath.clear();

    int64_t mirrorOff = structOffset("Klass", "_java_mirror");
    if (mirrorOff < 0) return false;
    uint64_t classOop = readOop(proc, klassAddr + (uint64_t)mirrorOff, g_target.useCompressedOops);
    if (classOop == 0) return false;

    /* Modern JDK: injected field offset exposed as static_field
     * java_lang_Class::_protection_domain_offset (int). */
    uint64_t pdOop = 0;
    int32_t pdOff = readStaticInt32("java_lang_Class", "_protection_domain_offset", -1);
    if (pdOff > 0) {
        pdOop = readOop(proc, classOop + (uint64_t)pdOff, g_target.useCompressedOops);
    }
    if (pdOop == 0) {
        /* JDK 8 fallback: stored on InstanceKlass directly. */
        int64_t ikPdOff = structOffset("InstanceKlass", "_protection_domain");
        if (ikPdOff >= 0) {
            pdOop = readOop(proc, klassAddr + (uint64_t)ikPdOff, g_target.useCompressedOops);
        }
    }
    if (pdOop == 0) return false;

    uint64_t pdKlass = readKlass(proc, pdOop + 8, g_target.useCompressedClassPointers);
    if (pdKlass == 0) return false;

    ResolvedField csField = {};
    if (!resolveFieldInKlass(pdKlass, "codesource", "", &csField)) return false;
    if (csField.isStatic) return false;
    uint64_t csOop = readOop(proc, pdOop + (uint64_t)csField.offset, g_target.useCompressedOops);
    if (csOop == 0) return false;

    uint64_t csKlass = readKlass(proc, csOop + 8, g_target.useCompressedClassPointers);
    if (csKlass == 0) return false;

    ResolvedField locField = {};
    if (!resolveFieldInKlass(csKlass, "location", "", &locField)) return false;
    if (locField.isStatic) return false;
    uint64_t urlOop = readOop(proc, csOop + (uint64_t)locField.offset, g_target.useCompressedOops);
    if (urlOop == 0) return false;

    uint64_t urlKlass = readKlass(proc, urlOop + 8, g_target.useCompressedClassPointers);
    if (urlKlass == 0) return false;

    ResolvedField pathField = {};
    if (!resolveFieldInKlass(urlKlass, "path", "", &pathField)) return false;
    if (pathField.isStatic) return false;
    uint64_t pathStrOop = readOop(proc, urlOop + (uint64_t)pathField.offset, g_target.useCompressedOops);
    if (pathStrOop == 0) return false;

    std::string path;
    if (!readJavaString(pathStrOop, path) || path.empty()) return false;

    /* Read protocol to identify jar:file:..!/ wrapping vs plain file: URL. */
    std::string protocol;
    ResolvedField protoField = {};
    if (resolveFieldInKlass(urlKlass, "protocol", "", &protoField) && !protoField.isStatic) {
        uint64_t protoStrOop = readOop(proc, urlOop + (uint64_t)protoField.offset,
                                       g_target.useCompressedOops);
        if (protoStrOop != 0) readJavaString(protoStrOop, protocol);
    }

    /* Normalize:
     *   protocol=jar,  path=file:/D:/foo/agent.jar!/  → D:/foo/agent.jar
     *   protocol=file, path=/D:/foo/agent.jar         → D:/foo/agent.jar */
    if (protocol == "jar") {
        if (path.compare(0, 5, "file:") == 0) path = path.substr(5);
        size_t bang = path.find('!');
        if (bang != std::string::npos) path = path.substr(0, bang);
    }
    /* Strip the leading '/' on Windows-style URL paths like "/D:/foo/x.jar". */
    if (path.size() >= 3 && path[0] == '/' && path[2] == ':') {
        path = path.substr(1);
    }

    outPath = std::move(path);
    return !outPath.empty();
}

/* Scan an InstanceKlass's static fields. If any has declared type
 * Lsun/instrument/InstrumentationImpl; or Ljava/lang/instrument/Instrumentation;,
 * write its field name to outFieldName and return true. */
static bool findInstrumentationStaticField(uint64_t klassAddr, std::string* outFieldName) {
    HANDLE proc = g_target.handle;
    outFieldName->clear();

    int64_t ik_fields_off = structOffset("InstanceKlass", "_fields");
    int64_t ik_constants_off = structOffset("InstanceKlass", "_constants");
    if (ik_fields_off < 0 || ik_constants_off < 0) return false;

    uint64_t cpAddr = 0;
    readRemotePointer(proc, klassAddr + ik_constants_off, &cpAddr);
    if (cpAddr == 0) return false;

    uint64_t fieldsArrayAddr = 0;
    readRemotePointer(proc, klassAddr + ik_fields_off, &fieldsArrayAddr);
    if (fieldsArrayAddr == 0) return false;

    /* Array<u2> length: try common header offsets. */
    int32_t fieldsLen = 0;
    readRemoteI32(proc, fieldsArrayAddr + 8, &fieldsLen);
    if (fieldsLen <= 0 || fieldsLen > 100000) {
        readRemoteI32(proc, fieldsArrayAddr + 12, &fieldsLen);
    }
    if (fieldsLen <= 0 || fieldsLen > 100000) return false;

    int64_t cp_header_size = typeSize("ConstantPool");
    if (cp_header_size <= 0) cp_header_size = 72;

    int64_t cp_length_off = structOffset("ConstantPool", "_length");
    int32_t cpLength = 0;
    if (cp_length_off >= 0) readRemoteI32(proc, cpAddr + cp_length_off, &cpLength);
    if (cpLength <= 0) cpLength = 32767;

    std::vector<uint16_t> fieldData(fieldsLen);
    bool readOk = false;
    for (int hdrTry = 16; hdrTry >= 8; hdrTry -= 4) {
        if (readRemoteMem(proc, fieldsArrayAddr + hdrTry, fieldData.data(),
                          (size_t)fieldsLen * 2)) {
            readOk = true;
            break;
        }
    }
    if (!readOk) return false;

    int32_t javaFieldsCount = fieldsLen / 6;
    int64_t jfc_off = structOffset("InstanceKlass", "_java_fields_count");
    if (jfc_off >= 0) {
        uint16_t jfc = 0;
        readRemoteU16(proc, klassAddr + jfc_off, &jfc);
        if (jfc > 0) javaFieldsCount = jfc;
    }

    for (int fi = 0; fi < javaFieldsCount && (fi * 6 + 2) < fieldsLen; fi++) {
        int base = fi * 6;
        uint16_t accessFlags = fieldData[base + 0];
        uint16_t nameIndex   = fieldData[base + 1];
        uint16_t sigIndex    = fieldData[base + 2];

        if ((accessFlags & 0x0008) == 0) continue; /* not static */
        if (sigIndex == 0 || sigIndex >= (uint16_t)cpLength) continue;

        uint64_t sigSymAddr = 0;
        readRemotePointer(proc, cpAddr + (uint64_t)cp_header_size + (uint64_t)sigIndex * 8,
                          &sigSymAddr);
        if (sigSymAddr == 0) continue;

        std::string descriptor;
        if (!readSymbolBody(proc, sigSymAddr, &descriptor)) continue;

        if (descriptor != "Lsun/instrument/InstrumentationImpl;" &&
            descriptor != "Ljava/lang/instrument/Instrumentation;") {
            continue;
        }

        if (nameIndex == 0 || nameIndex >= (uint16_t)cpLength) continue;
        uint64_t nameSymAddr = 0;
        readRemotePointer(proc, cpAddr + (uint64_t)cp_header_size + (uint64_t)nameIndex * 8,
                          &nameSymAddr);
        if (nameSymAddr == 0) continue;

        std::string fieldName;
        if (!readSymbolBody(proc, nameSymAddr, &fieldName)) continue;

        *outFieldName = std::move(fieldName);
        return true;
    }
    return false;
}

/* Walk ClassLoaderDataGraph -> ClassLoaderData -> Klass chain. For each
 * InstanceKlass, check if it holds a static Instrumentation reference;
 * if yes, record (klassAddr, fieldName). */
static void enumerateAgentMainKlasses(std::vector<std::pair<uint64_t, std::string>>& out) {
    HANDLE proc = g_target.handle;
    out.clear();

    uint64_t cldgHeadAddr = structStaticAddr("ClassLoaderDataGraph", "_head");
    if (cldgHeadAddr == 0) cldgHeadAddr = structStaticAddr("ClassLoaderData", "_head");
    if (cldgHeadAddr == 0) {
        FVM_LOG("enumerateAgentMainKlasses: ClassLoaderDataGraph::_head not in VMStructs");
        return;
    }

    uint64_t cldAddr = 0;
    if (!readRemotePointer(proc, cldgHeadAddr, &cldAddr) || cldAddr == 0) {
        FVM_LOG("enumerateAgentMainKlasses: CLD head is null");
        return;
    }

    int64_t cldNextOff = structOffset("ClassLoaderData", "_next");
    if (cldNextOff < 0) cldNextOff = 8;
    int64_t cldKlassesOff = structOffset("ClassLoaderData", "_klasses");
    if (cldKlassesOff < 0) cldKlassesOff = 16;
    int64_t klassNextOff = structOffset("Klass", "_next_link");
    if (klassNextOff < 0) klassNextOff = structOffset("InstanceKlass", "_next_link");
    if (klassNextOff < 0) {
        FVM_LOG("enumerateAgentMainKlasses: Klass::_next_link not in VMStructs");
        return;
    }

    int scanned = 0;
    for (int cldCount = 0; cldAddr != 0 && cldCount < 10000; cldCount++) {
        uint64_t klassAddr = 0;
        readRemotePointer(proc, cldAddr + (uint64_t)cldKlassesOff, &klassAddr);

        for (int klassCount = 0; klassAddr != 0 && klassCount < 100000; klassCount++) {
            scanned++;
            std::string fieldName;
            if (findInstrumentationStaticField(klassAddr, &fieldName)) {
                std::string klassName;
                readKlassName(proc, klassAddr, &klassName);
                FVM_LOG("enumerateAgentMainKlasses: agent main '%s' @ 0x%llX field='%s'",
                        klassName.c_str(), (unsigned long long)klassAddr, fieldName.c_str());
                out.emplace_back(klassAddr, std::move(fieldName));
            }

            uint64_t nextKlass = 0;
            if (!readRemotePointer(proc, klassAddr + (uint64_t)klassNextOff, &nextKlass)) break;
            klassAddr = nextKlass;
        }

        uint64_t nextCld = 0;
        if (!readRemotePointer(proc, cldAddr + (uint64_t)cldNextOff, &nextCld)) break;
        cldAddr = nextCld;
    }
    FVM_LOG("enumerateAgentMainKlasses: scanned %d klasses, found %zu agent main(s)",
            scanned, out.size());
}

/* Purge a single agent given its main InstanceKlass and the field name that
 * holds its Instrumentation reference. Steps mirror the original implementation
 * but skip the class-name lookup (caller already located the klass) and use
 * the correct oop+8 offset for klass reads on InstrumentationImpl instances. */
static int purgeAgentByKlass(uint64_t agentKlass, const std::string& instFieldName) {
    HANDLE proc = g_target.handle;
    if (proc == NULL) return 0;

    std::string klassName;
    readKlassName(proc, agentKlass, &klassName);
    FVM_LOG("=== PURGE AGENT: %s (field=%s) ===", klassName.c_str(), instFieldName.c_str());

    std::vector<DWORD> threads;
    suspendTargetThreads(g_target.pid, threads);

    int steps = 0;
    size_t writeSize = g_target.useCompressedOops ? 4 : 8;
    uint64_t zero = 0;

    ResolvedField rf = {};
    if (resolveFieldInKlass(agentKlass, instFieldName, "", &rf) && rf.isStatic && rf.staticAddress != 0) {
        uint64_t instOop = readOop(proc, rf.staticAddress, g_target.useCompressedOops);

        if (instOop != 0) {
            uint64_t instKlass = readKlass(proc, instOop + 8, g_target.useCompressedClassPointers);
            if (instKlass != 0) {
                ResolvedField tmField = {};
                if (resolveFieldInKlass(instKlass, "mTransformerManager", "", &tmField) &&
                    !tmField.isStatic && tmField.offset > 0) {
                    if (writeRemoteMem(proc, instOop + tmField.offset, &zero, writeSize)) {
                        FVM_LOG("purge_agent: nullified mTransformerManager at OOP+%d", tmField.offset);
                        steps++;
                    }
                }
                ResolvedField rtmField = {};
                if (resolveFieldInKlass(instKlass, "mRetransfomerManager", "", &rtmField) &&
                    !rtmField.isStatic && rtmField.offset > 0) {
                    if (writeRemoteMem(proc, instOop + rtmField.offset, &zero, writeSize)) {
                        FVM_LOG("purge_agent: nullified mRetransfomerManager at OOP+%d", rtmField.offset);
                        steps++;
                    }
                }
            }

            if (writeRemoteMem(proc, rf.staticAddress, &zero, writeSize)) {
                FVM_LOG("purge_agent: nullified static '%s' at 0x%llX",
                        instFieldName.c_str(), (unsigned long long)rf.staticAddress);
                steps++;
            }
        }
    }

    if (clearMethodBody(agentKlass, "agentmain")) steps++;
    if (clearMethodBody(agentKlass, "premain")) steps++;

    resumeTargetThreads(threads);

    FVM_LOG("purge_agent: deopt sweep");
    forceDeoptimizeAll();

    FVM_LOG("=== PURGE AGENT DONE: %s (%d steps) ===", klassName.c_str(), steps);
    return steps > 0 ? 1 : 0;
}

/* Public export: scan every loaded Java agent, apply the jar-path filter,
 * purge each match. The same filter mode/patterns are used by the
 * JVM_EnqueueOperation trampoline for future-attach blocking, so a single
 * AgentFilter on the Java side gives symmetric "already loaded + future"
 * behavior.
 *
 *   filterMode = 0 (NONE) : purge ALL loaded agents (including unknown-jar)
 *   filterMode = 1 (BLACKLIST) : purge agents whose jar matches any pattern
 *   filterMode = 2 (WHITELIST) : purge agents whose jar does NOT match
 *
 * Returns the number of agents purged. */
extern "C" __declspec(dllexport) int forgevm_purge_agents_matching(
        int filterMode,
        const char* const* patterns,
        int patternsCount) {

    if (g_target.handle == NULL || !g_target.structMapReady) {
        setError("not_bootstrapped");
        return 0;
    }

    FVM_LOG("forgevm_purge_agents_matching: mode=%d patternsCount=%d",
            filterMode, patternsCount);

    std::vector<std::pair<uint64_t, std::string>> agents;
    enumerateAgentMainKlasses(agents);
    if (agents.empty()) {
        setError("ok");
        return 0;
    }

    int purged = 0;
    for (auto& entry : agents) {
        uint64_t klassAddr = entry.first;
        const std::string& fieldName = entry.second;

        std::string jarPath;
        bool gotJar = resolveAgentJarPath(klassAddr, jarPath);

        bool shouldPurge;
        if (filterMode == 0) {
            shouldPurge = true;
        } else if (!gotJar) {
            /* Strict: filter is set, jar identity unknown → don't purge.
             * If user wants these too, they call banJavaAgent() with no filter. */
            FVM_LOG("forgevm_purge_agents_matching: skip 0x%llX (no jar identity)",
                    (unsigned long long)klassAddr);
            shouldPurge = false;
        } else {
            bool matched = false;
            for (int i = 0; i < patternsCount; i++) {
                if (patterns[i] != nullptr &&
                    agentGlobMatch(std::string(patterns[i]), jarPath)) {
                    matched = true;
                    break;
                }
            }
            shouldPurge = (filterMode == 1) ? matched : !matched;
        }

        FVM_LOG("forgevm_purge_agents_matching: klass=0x%llX jar='%s' %s",
                (unsigned long long)klassAddr, jarPath.c_str(),
                shouldPurge ? "PURGE" : "keep");

        if (shouldPurge && purgeAgentByKlass(klassAddr, fieldName) == 1) {
            purged++;
        }
    }

    FVM_LOG("forgevm_purge_agents_matching: purged %d of %zu loaded agents",
            purged, agents.size());
    setError("ok");
    return purged;
}

// Trigger a single global deoptimization sweep — used after a batch of deferred transforms.
extern "C" __declspec(dllexport) int forgevm_force_deopt_now() {
    if (g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    FVM_LOG("=== FORCE DEOPT (manual) ===");
    uint64_t kh = g_klassCacheHits, km = g_klassCacheMisses;
    uint64_t mh = g_methodCacheHits, mm = g_methodCacheMisses;
    FVM_LOG("klass cache: %llu hits / %llu misses (hit rate %.1f%%, %zu entries)",
            (unsigned long long)kh, (unsigned long long)km,
            (kh + km) ? (100.0 * kh / (kh + km)) : 0.0,
            g_klassNameCache.size());
    FVM_LOG("method cache: %llu hits / %llu misses (hit rate %.1f%%, %zu entries, %zu klasses fully scanned)",
            (unsigned long long)mh, (unsigned long long)mm,
            (mh + mm) ? (100.0 * mh / (mh + mm)) : 0.0,
            g_methodCache.size(), g_klassMethodsScanned.size());
    forceDeoptimizeAll();
    return 1;
}

/* ============================================================
 * Subclass traversal helpers (used by commitClassPlan / unloadClassPlan)
 * ============================================================ */

static bool isSubclassOf(uint64_t klassAddr, uint64_t targetKlassAddr) {
    HANDLE proc = g_target.handle;
    int64_t superOff = structOffset("Klass", "_super");
    if (superOff < 0) return false;

    uint64_t current = klassAddr;
    for (int depth = 0; current != 0 && depth < 100; depth++) {
        uint64_t superKlass = 0;
        if (!readRemotePointer(proc, current + (uint64_t)superOff, &superKlass)) break;
        if (superKlass == targetKlassAddr) return true;
        current = superKlass;
    }
    return false;
}

static std::vector<uint64_t> findAllSubclasses(uint64_t targetKlassAddr) {
    HANDLE proc = g_target.handle;
    std::vector<uint64_t> result;

    uint64_t cldgHeadAddr = structStaticAddr("ClassLoaderDataGraph", "_head");
    if (cldgHeadAddr == 0) cldgHeadAddr = structStaticAddr("ClassLoaderData", "_head");
    if (cldgHeadAddr == 0) return result;

    uint64_t cldAddr = 0;
    if (!readRemotePointer(proc, cldgHeadAddr, &cldAddr) || cldAddr == 0) return result;

    int64_t cldNextOff   = structOffset("ClassLoaderData", "_next");
    if (cldNextOff < 0) cldNextOff = 8;
    int64_t cldKlassesOff = structOffset("ClassLoaderData", "_klasses");
    if (cldKlassesOff < 0) cldKlassesOff = 16;
    int64_t klassNextOff  = structOffset("Klass", "_next_link");
    if (klassNextOff < 0) klassNextOff = structOffset("InstanceKlass", "_next_link");

    for (int cldCount = 0; cldAddr != 0 && cldCount < 10000; cldCount++) {
        uint64_t klassAddr = 0;
        readRemotePointer(proc, cldAddr + (uint64_t)cldKlassesOff, &klassAddr);

        for (int kc = 0; klassAddr != 0 && kc < 100000; kc++) {
            if (klassAddr != targetKlassAddr && isSubclassOf(klassAddr, targetKlassAddr)) {
                result.push_back(klassAddr);
            }
            if (klassNextOff < 0) break;
            uint64_t next = 0;
            if (!readRemotePointer(proc, klassAddr + (uint64_t)klassNextOff, &next)) break;
            klassAddr = next;
        }

        uint64_t nextCld = 0;
        if (!readRemotePointer(proc, cldAddr + (uint64_t)cldNextOff, &nextCld)) break;
        cldAddr = nextCld;
    }

    return result;
}

/* ============================================================
 * Per-class bytecode transform — core implementation
 * ============================================================ */

/* Per-hook resolved data collected during Phase A (no suspend needed). */
struct HookData {
    /* Hook identity */
    std::string methodName, paramDesc;
    std::string injectAt, hookClass, hookMethod, hookDesc;

    /* Internal name ("a/b/C") of the class that declares the patched method —
       the class actually being committed (a subclass when reached via
       includeSubclasses). Used as the verification type of local 0 (`this`) in
       the rebuilt trampoline StackMapTable. */
    std::string targetClassInternalName;

    /* Method addresses */
    uint64_t methodAddr           = 0;
    uint64_t origConstMethodAddr  = 0;

    /* Original bytecode */
    std::vector<uint8_t> origBytecode;

    /* Method properties */
    bool     targetIsStatic = false;
    bool     hasArgCapture  = false;
    std::vector<ParamSlotInfo> targetParams;
    std::string targetReturnDesc;

    /* True when a CP entry for java/lang/Object must be allocated even without
       arg capture (e.g., HEAD with `this` or any reference parameter — the
       rebuilt StackMapTable types those locals as ITEM_Object(Object)). */
    bool     needObjectCp = false;

    /* Return / unbox */
    bool     needsUnbox       = false;
    uint8_t  unboxReturnOp    = 0xB1;
    std::string unboxWrapperClass, unboxMethodName, unboxMethodDesc;

    /* Resolved Klass / Method addresses */
    uint64_t hookKlassAddr = 0, cbKlassAddr = 0;
    uint64_t objectKlassAddr = 0, unboxKlassAddr = 0;
    uint64_t hookMethodAddr = 0, cbInitAddr = 0;
    uint64_t cbIsCancelledAddr = 0, cbGetReturnAddr = 0;
    uint64_t unboxMethodAddr = 0;

    /* Interned symbols */
    uint64_t symHookClass = 0, symHookMethod = 0, symHookDesc = 0;
    uint64_t symCbClass = 0, symInit = 0, symInitDesc = 0;
    uint64_t symIsCancelled = 0, symIsCancelledD = 0;
    uint64_t symGetRetVal = 0, symGetRetValD = 0;
    uint64_t symObjectClass = 0;
    uint64_t symUnboxClass = 0, symUnboxMethod = 0, symUnboxDesc = 0;

    /* Assigned layout (filled by assignPoolLayout) */
    uint32_t cpBase           = 0;
    int      hookCacheIdx     = 0, initCacheIdx   = 0;
    int      cancelCacheIdx   = 0, retValCacheIdx = 0, unboxCacheIdx = 0;
    int      hookClassRKIdx   = 0, cbClassRKIdx   = 0;
    int      objectClassRKIdx = 0, unboxClassRKIdx = 0;
    uint16_t cbClassCpIdx     = 0, objClassCpIdx  = 0;
    uint16_t unboxClassCpIdx  = 0;
    uint32_t unboxMethodrefCpOff = 0;  /* offset from cpBase */

    /* Extra Class CP entries for INVOKE/FIELD_PUT reference parameter types
       whose declared class is not already addressable via an existing
       Methodref/Fieldref class component. Deduped by internal name. */
    struct ExtraClassEntry {
        std::string internalName;
        uint64_t    klassAddr   = 0;
        uint64_t    symbolAddr  = 0;
        uint16_t    nameCpIdx   = 0;
        uint16_t    classCpIdx  = 0;
        int         rkIdx       = 0;
    };
    std::vector<ExtraClassEntry> extraClasses;

    /* Built CM (filled by buildHookCM) */
    std::vector<uint8_t> newCMBytes;
    uint64_t newCMRemoteAddr = 0;

    /* Rebuilt StackMapTable. When haveNewStackMap is set, commitKlass allocates
       a remote Array<u1>, writes [int32 length][u1 data...], and points
       ConstMethod::_stackmap_data at it instead of NULLing it + downgrading
       _major_version. */
    std::vector<uint8_t> newStackMapBytes;
    bool                 haveNewStackMap       = false;
    uint64_t             newStackMapRemoteAddr = 0;

    /* Extra stack slots consumed by the target instruction's operands (set by
       buildHookCM for INVOKE/FIELD/NEW; used when updating _max_stack). */
    uint16_t extraMaxStack = 0;

    bool wantObjectCpEntry() const {
        return (hasArgCapture && !targetParams.empty()) || needObjectCp;
    }
    uint32_t numCPEntries() const {
        uint32_t n = 20;
        if (wantObjectCpEntry()) n += 2;
        if (needsUnbox) n += 6;
        n += (uint32_t)extraClasses.size() * 2;
        return n;
    }
    uint32_t numCacheEntries() const { return needsUnbox ? 5u : 4u; }
    uint32_t numRKEntries()    const {
        uint32_t n = 2;
        if (wantObjectCpEntry()) n++;
        if (needsUnbox) n++;
        n += (uint32_t)extraClasses.size();
        return n;
    }
};

/* Forward declarations — implementations appear after helper zone. */
static bool preResolveInjectionTargets(HookData& h, const std::string& kind,
                                        const std::string& targetSpec);
static int  registerExtraClass(HookData& h, const std::string& internalName);
static bool registerMethodEntryExtraClasses(HookData& h);

/* Phase A: resolve all klass/method/symbol addresses for one hook.
   Returns false on any lookup failure (sets g_lastError). */
static bool resolveHookData(uint64_t klassAddr,
                                  const std::string& methodName,
                                  const std::string& paramDesc,
                                  const HookSpecExtended& spec,
                                  HookData& out) {
    HANDLE proc = g_target.handle;

    out.methodName = methodName;
    out.paramDesc  = paramDesc;
    out.injectAt   = spec.injectAt;
    out.hookClass  = spec.hookClass;
    out.hookMethod = spec.hookMethod;
    out.hookDesc   = spec.hookDesc;

    /* 1. Find the target Method* */
    std::string dotName;
    { std::string iname; if (!readKlassName(proc, klassAddr, &iname)) { setError("readKlassName_failed"); return false; }
      out.targetClassInternalName = iname;
      dotName = iname; for (char& c : dotName) if (c == '/') c = '.'; }

    if (!findJavaMethod(dotName.c_str(), methodName.c_str(), paramDesc.c_str(), &out.methodAddr)) return false;

    /* 2. ConstMethod* */
    int64_t cmOff = structOffset("Method", "_constMethod"); if (cmOff < 0) cmOff = 8;
    if (!readRemotePointer(proc, out.methodAddr + (uint64_t)cmOff, &out.origConstMethodAddr) || !out.origConstMethodAddr) {
        setError("cannot_read_constmethod"); return false;
    }

    /* 3. Original bytecode */
    uint64_t bcAddr; uint32_t csz;
    if (!readConstMethodBytecode(out.origConstMethodAddr, &out.origBytecode, &bcAddr, &csz)) return false;

    /* 4. Access flags + signature (read from current CM._constants, which is oldCP₀) */
    int64_t afOff = structOffset("Method", "_access_flags");
    if (afOff >= 0) { int32_t fl = 0; readRemoteI32(proc, out.methodAddr+(uint64_t)afOff, &fl); out.targetIsStatic = (fl & 0x0008) != 0; }

    int64_t cmcOff = structOffset("ConstMethod", "_constants"); if (cmcOff < 0) cmcOff = 8;
    uint64_t curCP = 0; readRemotePointer(proc, out.origConstMethodAddr + (uint64_t)cmcOff, &curCP);
    if (curCP) {
        int64_t sigIdxOff = structOffset("ConstMethod", "_signature_index");
        if (sigIdxOff >= 0) {
            uint16_t sigIdx = 0;
            if (readRemoteU16(proc, out.origConstMethodAddr + (uint64_t)sigIdxOff, &sigIdx) && sigIdx > 0) {
                int64_t cpHdr = typeSize("ConstantPool"); if (cpHdr < 0) cpHdr = 0x138;
                uint64_t sigSym = 0;
                if (readRemotePointer(proc, curCP + (uint64_t)cpHdr + (uint64_t)sigIdx * 8, &sigSym) && sigSym) {
                    std::string fullSig;
                    if (readSymbolBody(proc, sigSym, &fullSig)) {
                        size_t cp2 = fullSig.find(')');
                        if (cp2 != std::string::npos && cp2 + 1 < fullSig.size()) {
                            out.targetReturnDesc = fullSig.substr(cp2 + 1);
                            /* Replace any caller-supplied paramDesc (which may
                               be empty for wildcard candidates) with the
                               authoritative "(...)" portion of the resolved
                               method's signature. Downstream code that needs to
                               walk the param list — including the rebuilt
                               StackMapTable — depends on this. */
                            out.paramDesc = fullSig.substr(0, cp2 + 1);
                        }
                        out.targetParams = parseParamSlots(fullSig, out.targetIsStatic);
                        out.hasArgCapture = !out.targetParams.empty();
                    }
                    /* All route-2 inject points rebuild a StackMapTable that
                       declares method-entry locals at the trampoline tail; ref
                       slots are encoded as ITEM_Object(java/lang/Object), so the
                       Object CP entry must be allocated regardless of arg-
                       capture state. */
                    {
                        const std::string& ia = spec.injectAt;
                        bool anyRoute2 =
                            (ia == "HEAD" || ia == "RETURN" ||
                             ia.compare(0, 7,  "INVOKE:")    == 0 ||
                             ia.compare(0, 10, "FIELD_GET:") == 0 ||
                             ia.compare(0, 10, "FIELD_PUT:") == 0 ||
                             ia.compare(0, 4,  "NEW:")       == 0);
                        if (anyRoute2) {
                            if (!out.targetIsStatic) out.needObjectCp = true;
                            for (auto& p : out.targetParams)
                                if (p.isRef) { out.needObjectCp = true; break; }
                            if (ia == "RETURN" &&
                                !out.targetReturnDesc.empty() &&
                                (out.targetReturnDesc[0] == 'L' ||
                                 out.targetReturnDesc[0] == '[')) {
                                out.needObjectCp = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if (out.targetReturnDesc.empty()) out.targetReturnDesc = "V";

    /* 5. Unbox info */
    auto& rd = out.targetReturnDesc;
    if (rd == "V")  { out.unboxReturnOp = 0xB1; }
    else if (rd == "Z") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Boolean";   out.unboxMethodName="booleanValue"; out.unboxMethodDesc="()Z"; out.unboxReturnOp=0xAC; }
    else if (rd == "B") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Byte";      out.unboxMethodName="byteValue";    out.unboxMethodDesc="()B"; out.unboxReturnOp=0xAC; }
    else if (rd == "C") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Character"; out.unboxMethodName="charValue";    out.unboxMethodDesc="()C"; out.unboxReturnOp=0xAC; }
    else if (rd == "S") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Short";     out.unboxMethodName="shortValue";   out.unboxMethodDesc="()S"; out.unboxReturnOp=0xAC; }
    else if (rd == "I") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Integer";   out.unboxMethodName="intValue";     out.unboxMethodDesc="()I"; out.unboxReturnOp=0xAC; }
    else if (rd == "F") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Float";     out.unboxMethodName="floatValue";   out.unboxMethodDesc="()F"; out.unboxReturnOp=0xAE; }
    else if (rd == "J") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Long";      out.unboxMethodName="longValue";    out.unboxMethodDesc="()J"; out.unboxReturnOp=0xAD; }
    else if (rd == "D") { out.needsUnbox=true; out.unboxWrapperClass="java/lang/Double";    out.unboxMethodName="doubleValue";  out.unboxMethodDesc="()D"; out.unboxReturnOp=0xAF; }
    else { out.unboxReturnOp = 0xB0; }

    /* 6. Hook klass/method */
    std::string hci = toInternalName(spec.hookClass.c_str());
    if (!findInstanceKlassByName(hci, &out.hookKlassAddr)) return false;
    if (!findMethodInKlass(out.hookKlassAddr, spec.hookMethod.c_str(), spec.hookDesc.c_str(), &out.hookMethodAddr)) return false;

    /* FvmCallback */
    if (!findInstanceKlassByName("forgevm/forge/FvmCallback", &out.cbKlassAddr)) return false;
    if (!findMethodInKlass(out.cbKlassAddr, "<init>",          "(Ljava/lang/Object;[Ljava/lang/Object;)V", &out.cbInitAddr))       return false;
    if (!findMethodInKlass(out.cbKlassAddr, "isCancelled",     "()Z",                                      &out.cbIsCancelledAddr)) return false;
    if (!findMethodInKlass(out.cbKlassAddr, "getReturnValue",  "()Ljava/lang/Object;",                     &out.cbGetReturnAddr))   return false;

    /* java/lang/Object — needed for anewarray (arg capture) and/or as the
       supertype for ITEM_Object verification types in the rebuilt
       StackMapTable. */
    if (out.hasArgCapture || out.needObjectCp) {
        if (!findInstanceKlassByName("java/lang/Object", &out.objectKlassAddr)) {
            out.hasArgCapture = false;
            out.needObjectCp  = false;
        }
    }

    /* Unbox wrapper */
    if (out.needsUnbox) {
        if (!findInstanceKlassByName(out.unboxWrapperClass, &out.unboxKlassAddr)) return false;
        if (!findMethodInKlass(out.unboxKlassAddr, out.unboxMethodName.c_str(), out.unboxMethodDesc.c_str(), &out.unboxMethodAddr)) return false;
    }

    /* 7. Interned symbols */
    out.symHookClass = readKlassNameSymbol(out.hookKlassAddr);
    if (!readMethodSymbols(out.hookMethodAddr,    &out.symHookMethod,   &out.symHookDesc))   return false;
    out.symCbClass = readKlassNameSymbol(out.cbKlassAddr);
    if (!readMethodSymbols(out.cbInitAddr,        &out.symInit,         &out.symInitDesc))   return false;
    if (!readMethodSymbols(out.cbIsCancelledAddr, &out.symIsCancelled,  &out.symIsCancelledD)) return false;
    if (!readMethodSymbols(out.cbGetReturnAddr,   &out.symGetRetVal,    &out.symGetRetValD)) return false;
    if (out.hasArgCapture || out.needObjectCp) {
        out.symObjectClass = readKlassNameSymbol(out.objectKlassAddr);
        if (!out.symObjectClass) { out.hasArgCapture = false; out.needObjectCp = false; }
    }
    if (out.needsUnbox) {
        out.symUnboxClass = readKlassNameSymbol(out.unboxKlassAddr);
        if (!readMethodSymbols(out.unboxMethodAddr, &out.symUnboxMethod, &out.symUnboxDesc)) return false;
    }

    if (!out.symHookClass || !out.symHookMethod || !out.symHookDesc ||
        !out.symCbClass   || !out.symInit       || !out.symInitDesc  ||
        !out.symIsCancelled || !out.symIsCancelledD ||
        !out.symGetRetVal   || !out.symGetRetValD) {
        setError("failed_to_read_interned_symbols"); return false;
    }

    /* For INVOKE/FIELD/NEW: pre-scan original bytecode to accumulate the
       extraClasses needed for the rebuilt SMT. Must run before assignPoolLayout
       so CP entry counts are correct. */
    {
        std::string kind, targetSpec;
        size_t c = out.injectAt.find(':');
        if (c != std::string::npos) {
            kind = out.injectAt.substr(0, c);
            targetSpec = out.injectAt.substr(c + 1);
        } else {
            kind = out.injectAt;
        }
        if (kind == "INVOKE" || kind == "FIELD_GET" ||
            kind == "FIELD_PUT" || kind == "NEW") {
            if (!preResolveInjectionTargets(out, kind, targetSpec)) return false;
        }
    }

    /* Register CP Class entries for the method-entry verification types
       (declaring class + reference parameter / return types). The rebuilt
       trampoline StackMapTable must type local 0 and reference parameters with
       their exact declared classes, not java/lang/Object: the goto_w that
       enters the tail carries the real method-entry frame, and the verifier
       requires that frame assignable to the tail frame. Must run before
       assignPoolLayout so CP entry counts are correct. */
    if (!registerMethodEntryExtraClasses(out)) return false;

    return true;
}

/* Assign CP / CPCache / RK slot indices for every hook given the true-oldCP base. */
static void assignPoolLayout(uint32_t oldPoolLen, int32_t origRKLen, int origCacheLen,
                                std::vector<HookData>& hooks) {
    uint32_t cpCur    = oldPoolLen;
    int      rkCur    = (int)origRKLen;
    int      cacheCur = origCacheLen;

    for (auto& h : hooks) {
        h.cpBase = cpCur;

        h.hookClassRKIdx   = rkCur++;
        h.cbClassRKIdx     = rkCur++;
        if (h.wantObjectCpEntry()) h.objectClassRKIdx = rkCur++;
        if (h.needsUnbox)  h.unboxClassRKIdx = rkCur++;

        h.hookCacheIdx   = cacheCur++;
        h.initCacheIdx   = cacheCur++;
        h.cancelCacheIdx = cacheCur++;
        h.retValCacheIdx = cacheCur++;
        if (h.needsUnbox) h.unboxCacheIdx = cacheCur++;

        uint32_t P = h.cpBase;
        h.cbClassCpIdx = (uint16_t)(P + 11);

        uint32_t E = 20;
        if (h.wantObjectCpEntry()) {
            h.objClassCpIdx = (uint16_t)(P + E + 1);
            E += 2;
        }
        if (h.needsUnbox) {
            h.unboxClassCpIdx    = (uint16_t)(P + E + 3);
            h.unboxMethodrefCpOff = E + 5;
            E += 6;
        }
        for (auto& ex : h.extraClasses) {
            ex.rkIdx      = rkCur++;
            ex.nameCpIdx  = (uint16_t)(P + E);
            ex.classCpIdx = (uint16_t)(P + E + 1);
            E += 2;
        }

        cpCur += h.numCPEntries();
    }
}

/* Build the merged ConstantPool byte buffer from TRUE oldCP₀.
   newRKRemoteAddr / newCacheRemoteAddr / newTagsRemoteAddr must be
   pre-allocated remote addresses (written into header fields here). */
static std::vector<uint8_t> buildPoolBytes(
    const std::vector<uint8_t>& oldPoolBytes,
    uint32_t oldPoolLen,
    size_t   oldPoolByteSize,
    int64_t  cpHeaderSize,
    const std::vector<HookData>& hooks,
    uint32_t newPoolLen,
    uint64_t newRKAddr,
    uint64_t newCacheAddr,
    uint64_t newTagsAddr)
{
    size_t newPoolByteSize = oldPoolByteSize + (newPoolLen - oldPoolLen) * 8;
    std::vector<uint8_t> nb(newPoolByteSize, 0);
    memcpy(nb.data(), oldPoolBytes.data(), oldPoolByteSize);

    /* Update header fields */
    int64_t lenOff   = structOffset("ConstantPool", "_length");
    int64_t cacheOff = structOffset("ConstantPool", "_cache");
    int64_t rkOff    = structOffset("ConstantPool", "_resolved_klasses");
    int64_t tagsOff  = structOffset("ConstantPool", "_tags");
    if (lenOff   >= 0) { int32_t nl = (int32_t)newPoolLen;  memcpy(nb.data() + lenOff,   &nl,          4); }
    if (cacheOff >= 0 && newCacheAddr) memcpy(nb.data() + cacheOff, &newCacheAddr, 8);
    if (rkOff    >= 0 && newRKAddr)    memcpy(nb.data() + rkOff,    &newRKAddr,    8);
    if (tagsOff  >= 0 && newTagsAddr)  memcpy(nb.data() + tagsOff,  &newTagsAddr,  8);

    /* _major_version downgrade is only needed by the legacy goto_w-trampoline
     * path, which NULLs _stackmap_data and relies on the old type-inference
     * verifier. If every hook on this class rebuilt a consistent StackMapTable
     * (HEAD clean-prepend), the split verifier is satisfied and we MUST keep
     * the original major version — downgrading to 50 would make Java 8+
     * bytecode (e.g. invokestatic to an InterfaceMethodref) illegal and break
     * any not-yet-linked class that uses such bytecode. */
    bool needLegacyVerifierBypass = false;
    for (const auto& hk : hooks)
        if (!hk.haveNewStackMap) { needLegacyVerifierBypass = true; break; }

    /* For class major version >= 51 (Java 7+) HotSpot's split verifier is
     * authoritative and FailOverToOldVerifier does NOT apply: a NULL or
     * inconsistent _stackmap_data causes a hard VerifyError with no recovery.
     * Patching _major_version to 50 (Java 6) here forces the old type-inference
     * verifier for any class that hasn't been linked yet, which ignores the
     * stackmap entirely and infers types from bytecode flow.
     * For already-linked classes this field is never re-consulted, so the change
     * is invisible at runtime.
     *
     * ConstantPool::_major_version was removed from VMStructs in JDK 11+.
     * Fallback: scan the CP header for the native-LE u2 pattern [MV, 0] where
     * MV ∈ [45,67], adjacent u2 == 0 (minor_version).  Known 8-byte pointer
     * regions (tags / cache / pool_holder / operands / resolved_klasses) and
     * the 4-byte _length field are skipped to minimise false positives. */
    int64_t mvOff = structOffset("ConstantPool", "_major_version");
    if (!needLegacyVerifierBypass) {
        FVM_LOG("buildPoolBytes: _major_version preserved (all hooks rebuilt StackMapTable)");
    } else if (mvOff >= 0 && (size_t)(mvOff + 2) <= nb.size()) {
        uint16_t v50 = 50;
        memcpy(nb.data() + mvOff, &v50, 2);
        FVM_LOG("buildPoolBytes: _major_version→50 via VMStructs off=%lld", (long long)mvOff);
    } else if (cpHeaderSize >= 4) {
        int64_t phOff  = structOffset("ConstantPool", "_pool_holder");
        int64_t opOff  = structOffset("ConstantPool", "_operands");
        /* pointer-field regions to skip (8 bytes each) */
        int64_t ptrFlds[] = { tagsOff, cacheOff, phOff, opOff, rkOff };
        int64_t probeEnd = cpHeaderSize < (int64_t)nb.size() - 3
                         ? cpHeaderSize : (int64_t)nb.size() - 3;
        bool patched = false;
        for (int64_t off = 8; !patched && off + 4 <= probeEnd; off += 2) {
            bool skip = false;
            for (int64_t pf : ptrFlds)
                if (pf >= 0 && off >= pf && off < pf + 8) { skip = true; break; }
            if (!skip && lenOff >= 0 && off >= lenOff && off < lenOff + 4) skip = true;
            if (skip) continue;
            /* native little-endian u16 reads */
            uint16_t v0 = (uint16_t)nb[off]   | ((uint16_t)nb[off+1] << 8);
            uint16_t v1 = (uint16_t)nb[off+2] | ((uint16_t)nb[off+3] << 8);
            int64_t  mvOff2   = -1;
            uint16_t found_mv = 0;
            /* major first (HotSpot layout), minor first (fallback) */
            if      (v0 >= 45 && v0 <= 67 && (v1 == 0 || v1 == 0xFFFF))
                { mvOff2 = off;     found_mv = v0; }
            else if (v1 >= 45 && v1 <= 67 && (v0 == 0 || v0 == 0xFFFF))
                { mvOff2 = off + 2; found_mv = v1; }
            if (mvOff2 < 0) continue;
            FVM_LOG("buildPoolBytes: probed _major_version=%u at off=%lld",
                    (unsigned)found_mv, (long long)mvOff2);
            if (found_mv >= 51) {
                uint16_t v50 = 50;
                memcpy(nb.data() + mvOff2, &v50, 2);
                FVM_LOG("buildPoolBytes: _major_version→50 via probe");
            }
            patched = true;
        }
        if (!patched)
            FVM_LOG("buildPoolBytes: WARN _major_version not found in CP header "
                    "(off range [8,%lld]) — split verifier may reject unlinked patched classes",
                    (long long)probeEnd);
    }

    uint64_t* slots = (uint64_t*)(nb.data() + cpHeaderSize);
    for (auto& h : hooks) {
        uint32_t P = h.cpBase;
        uint32_t E = 20;

        slots[P+ 0] = h.symHookClass;   slots[P+ 1] = h.symHookMethod;  slots[P+ 2] = h.symHookDesc;
        slots[P+ 3] = h.symCbClass;     slots[P+ 4] = h.symInit;        slots[P+ 5] = h.symInitDesc;
        slots[P+ 6] = h.symIsCancelled; slots[P+ 7] = h.symIsCancelledD;
        slots[P+ 8] = h.symGetRetVal;   slots[P+ 9] = h.symGetRetValD;

        slots[P+10] = (uint64_t)(((uint32_t)(P+ 0) << 16) | (uint32_t)h.hookClassRKIdx);
        slots[P+11] = (uint64_t)(((uint32_t)(P+ 3) << 16) | (uint32_t)h.cbClassRKIdx);

        slots[P+12] = (uint64_t)(((uint32_t)(P+ 2) << 16) | (uint32_t)(P+ 1));
        slots[P+13] = (uint64_t)(((uint32_t)(P+ 5) << 16) | (uint32_t)(P+ 4));
        slots[P+14] = (uint64_t)(((uint32_t)(P+ 7) << 16) | (uint32_t)(P+ 6));
        slots[P+15] = (uint64_t)(((uint32_t)(P+ 9) << 16) | (uint32_t)(P+ 8));

        slots[P+16] = (uint64_t)(((uint32_t)(P+12) << 16) | (uint32_t)(P+10));
        slots[P+17] = (uint64_t)(((uint32_t)(P+13) << 16) | (uint32_t)(P+11));
        slots[P+18] = (uint64_t)(((uint32_t)(P+14) << 16) | (uint32_t)(P+11));
        slots[P+19] = (uint64_t)(((uint32_t)(P+15) << 16) | (uint32_t)(P+11));

        if (h.wantObjectCpEntry()) {
            slots[P+E]   = h.symObjectClass;
            slots[P+E+1] = (uint64_t)(((uint32_t)(P+E) << 16) | (uint32_t)h.objectClassRKIdx);
            E += 2;
        }
        if (h.needsUnbox) {
            slots[P+E]   = h.symUnboxClass;
            slots[P+E+1] = h.symUnboxMethod;
            slots[P+E+2] = h.symUnboxDesc;
            slots[P+E+3] = (uint64_t)(((uint32_t)(P+E)   << 16) | (uint32_t)h.unboxClassRKIdx);
            slots[P+E+4] = (uint64_t)(((uint32_t)(P+E+2) << 16) | (uint32_t)(P+E+1));
            slots[P+E+5] = (uint64_t)(((uint32_t)(P+E+4) << 16) | (uint32_t)(P+E+3));
            E += 6;
        }
        for (auto& ex : h.extraClasses) {
            slots[ex.nameCpIdx]  = ex.symbolAddr;
            slots[ex.classCpIdx] = (uint64_t)(((uint32_t)ex.nameCpIdx << 16) | (uint32_t)ex.rkIdx);
        }
    }
    return nb;
}

/* Build tags array from TRUE oldCP₀ tags + new hook tags. */
static std::vector<uint8_t> buildPoolTagsBytes(
    HANDLE proc, uint64_t origTagsAddr,
    uint32_t newPoolLen,
    const std::vector<HookData>& hooks)
{
    int64_t tagLenOff  = structOffset("Array<u1>", "_length");  if (tagLenOff  < 0) tagLenOff  = 0;
    int64_t tagDataOff = structOffset("Array<u1>", "_data");    if (tagDataOff < 0) tagDataOff = 4;

    size_t newTagsSize = ((size_t)tagDataOff + newPoolLen + 7) & ~7;
    std::vector<uint8_t> tb(newTagsSize, 0);

    if (origTagsAddr) {
        int32_t oldTagLen = 0;
        readRemoteI32(proc, origTagsAddr + (uint64_t)tagLenOff, &oldTagLen);
        size_t toCopy = (size_t)tagDataOff + (size_t)oldTagLen;
        if (toCopy > newTagsSize) toCopy = newTagsSize;
        readRemoteMem(proc, origTagsAddr, tb.data(), toCopy);
    }
    int32_t nl = (int32_t)newPoolLen;
    memcpy(tb.data() + tagLenOff, &nl, 4);

    uint8_t* td = tb.data() + tagDataOff;
    for (auto& h : hooks) {
        uint32_t P = h.cpBase, E = 20;
        for (int i = 0; i < 10; i++) td[P+i] = 1;
        td[P+10]=7; td[P+11]=7;
        td[P+12]=12; td[P+13]=12; td[P+14]=12; td[P+15]=12;
        td[P+16]=10; td[P+17]=10; td[P+18]=10; td[P+19]=10;
        if (h.wantObjectCpEntry()) { td[P+E]=1; td[P+E+1]=7; E+=2; }
        if (h.needsUnbox) { td[P+E]=1; td[P+E+1]=1; td[P+E+2]=1; td[P+E+3]=7; td[P+E+4]=12; td[P+E+5]=10; E+=6; }
        for (auto& ex : h.extraClasses) {
            td[ex.nameCpIdx]  = 1;
            td[ex.classCpIdx] = 7;
        }
    }
    return tb;
}

/* Build RK array from TRUE oldCP₀ RK + new hook entries. */
static std::vector<uint8_t> buildPoolRKBytes(
    HANDLE proc, uint64_t origRKAddr, int32_t origRKLen, int32_t newRKLen)
{
    int64_t rkLenOff  = structOffset("Array<Klass*>", "_length"); if (rkLenOff  < 0) rkLenOff  = 0;
    int64_t rkDataOff = structOffset("Array<Klass*>", "_data");   if (rkDataOff < 0) rkDataOff = 8;

    size_t origRKSize = (size_t)rkDataOff + origRKLen * 8;
    size_t newRKSize  = ((size_t)rkDataOff + newRKLen * 8 + 7) & ~7;
    std::vector<uint8_t> rb(newRKSize, 0);
    if (origRKAddr) readRemoteMem(proc, origRKAddr, rb.data(), origRKSize);
    memcpy(rb.data() + rkLenOff, &newRKLen, 4);
    return rb;
}

/* Fill pre-resolved tail entries into the CPCache byte buffer (already sized for
   origCacheLen + total new entries; prefix [0, origCacheLen) left for post-suspend
   snapshot). */
static void fillPoolCacheTail(
    std::vector<uint8_t>& cacheBytes,
    int64_t cacheHdrSize, int64_t cacheEntrySize,
    const std::vector<HookData>& hooks)
{
    int64_t iOff = structOffset("ConstantPoolCacheEntry", "_indices"); if (iOff < 0) iOff = 0;
    int64_t fOff = structOffset("ConstantPoolCacheEntry", "_f1");      if (fOff < 0) fOff = 8;
    int64_t gOff = structOffset("ConstantPoolCacheEntry", "_f2");      if (gOff < 0) gOff = 16;
    int64_t hOff = structOffset("ConstantPoolCacheEntry", "_flags");   if (hOff < 0) hOff = 24;

    for (auto& hk : hooks) {
        int numEnt = (int)hk.numCacheEntries();
        int cpIdxTable[5] = {
            (int)(hk.cpBase + 16), (int)(hk.cpBase + 17),
            (int)(hk.cpBase + 18), (int)(hk.cpBase + 19),
            hk.needsUnbox ? (int)(hk.cpBase + hk.unboxMethodrefCpOff) : 0,
        };
        uint8_t  bcTable[5]     = { 0xB8, 0xB7, 0xB7, 0xB7, 0xB7 };
        uint64_t methodTable[5] = { hk.hookMethodAddr, hk.cbInitAddr,
                                    hk.cbIsCancelledAddr, hk.cbGetReturnAddr, hk.unboxMethodAddr };

        int unboxTos = 4;
        if (hk.needsUnbox) {
            switch (hk.unboxReturnOp) {
                case 0xAC: unboxTos=4; break; case 0xAD: unboxTos=5; break;
                case 0xAE: unboxTos=6; break; case 0xAF: unboxTos=7; break;
                case 0xB0: unboxTos=8; break; default: unboxTos=9; break;
            }
        }
        int64_t flagsTable[5] = {
            ((int64_t)9<<28)|1, ((int64_t)9<<28)|3,
            ((int64_t)4<<28)|1, ((int64_t)8<<28)|1,
            hk.needsUnbox ? (((int64_t)unboxTos<<28)|1) : 0LL,
        };

        for (int i = 0; i < numEnt; i++) {
            size_t eOff = (size_t)cacheHdrSize + (size_t)(hk.hookCacheIdx + i) * (size_t)cacheEntrySize;
            if (eOff + (size_t)cacheEntrySize > cacheBytes.size()) break;
            uint8_t* entry = cacheBytes.data() + eOff;
            int64_t iv = (int64_t)cpIdxTable[i] | ((int64_t)bcTable[i] << 16);
            memcpy(entry + iOff, &iv, 8);
            memcpy(entry + fOff, &methodTable[i], 8);
            uint64_t zero = 0; memcpy(entry + gOff, &zero, 8);
            memcpy(entry + hOff, &flagsTable[i], 8);
        }
    }
}

/* ============================================================
 * StackMapTable rebuild for goto_w-trampoline HEAD injection.
 *
 * Layout: [goto_w → tailBCI][nop pad up to bci J][orig[J..end) verbatim]
 *         [prologue @ tailBCI ... ifeq → pop @ popBci]
 *         [rescued copy of orig[0..J) with branches rebased][goto J]
 *
 * Where J is the bci of the first original StackMapTable frame (or
 * origBytecode.size() when the method has no frames). With this choice every
 * original bci ≥ J is preserved verbatim in the new bytecode, so any trailing
 * ConstMethod section that carries a bci (LocalVariableTable, exception_table,
 * LineNumberTable) remains valid without rebasing.
 *
 * New StackMapTable contents:
 *   • All original frames verbatim — their absolute bcis are unchanged, so the
 *     first frame's offset_delta (== J) and every subsequent frame's delta are
 *     copied byte-for-byte.
 *   • full_frame @ tailBCI: locals describe the method-entry frame derived from
 *     the method descriptor + ACC_STATIC. Reference slots are encoded as
 *     ITEM_Null (subtype of every reference type ⇒ verifier accepts it for
 *     aload / aastore / invokespecial-receiver), so we avoid synthesizing a CP
 *     entry for the declaring class. Primitives map to ITEM_Integer / Long /
 *     Float / Double per JVMS §4.10.1.2.
 *   • same_locals_1_stack_item_extended @ popBci: ifeq branch target, locals
 *     inherited from tailBCI's full_frame, stack=[ ITEM_Object(FvmCallback) ].
 *
 * Frames at fall-through bcis (rescuedBCI, J) need no explicit entry; the
 * verifier walks instructions from the nearest explicit frame.
 *
 * StackMapTable is class-file byte order: all u2 are BIG-ENDIAN.
 * ============================================================ */

static inline uint16_t smReadU2BE(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}
static inline void smPushU2BE(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back((uint8_t)(v >> 8)); o.push_back((uint8_t)(v & 0xFF));
}

/* Length in bytes of one verification_type_info at buf[pos]. 0 = malformed. */
static size_t smVtiLen(const std::vector<uint8_t>& buf, size_t pos) {
    if (pos >= buf.size()) return 0;
    uint8_t tag = buf[pos];
    if (tag <= 6) return 1;          /* Top/Int/Float/Double/Long/Null/UninitThis */
    if (tag == 7 || tag == 8) return 3; /* Object(cp u2) / Uninitialized(bci u2) */
    return 0;                        /* invalid tag */
}

/* Parse one stack_map_frame at src@pos: extract offset_delta, total byte
   length, and the [start,end) span of its verification_type_info content.
   Returns false on malformed input. */
struct SmFrameInfo {
    uint16_t tag;
    uint16_t offsetDelta;
    size_t   totalLen;     /* full frame size in bytes */
    size_t   vtiStart;     /* first vti byte (or == frameEnd if none) */
    size_t   vtiEnd;       /* one past last vti byte */
};
static bool smParseFrame(const std::vector<uint8_t>& src, size_t pos, SmFrameInfo& fi) {
    if (pos >= src.size()) return false;
    uint8_t tag = src[pos];
    fi.tag = tag;
    if (tag <= 63) {                              /* same_frame */
        fi.offsetDelta = tag; fi.totalLen = 1;
        fi.vtiStart = fi.vtiEnd = pos + 1; return true;
    }
    if (tag >= 64 && tag <= 127) {                /* same_locals_1_stack_item */
        fi.offsetDelta = (uint16_t)(tag - 64);
        size_t vl = smVtiLen(src, pos + 1); if (!vl) return false;
        fi.totalLen = 1 + vl; fi.vtiStart = pos + 1; fi.vtiEnd = pos + 1 + vl;
        return true;
    }
    if (tag == 247) {                             /* same_locals_1_stack_item_extended */
        if (pos + 3 > src.size()) return false;
        fi.offsetDelta = smReadU2BE(&src[pos + 1]);
        size_t vl = smVtiLen(src, pos + 3); if (!vl) return false;
        fi.totalLen = 3 + vl; fi.vtiStart = pos + 3; fi.vtiEnd = pos + 3 + vl;
        return true;
    }
    if (tag >= 248 && tag <= 250) {               /* chop_frame */
        if (pos + 3 > src.size()) return false;
        fi.offsetDelta = smReadU2BE(&src[pos + 1]);
        fi.totalLen = 3; fi.vtiStart = fi.vtiEnd = pos + 3; return true;
    }
    if (tag == 251) {                             /* same_frame_extended */
        if (pos + 3 > src.size()) return false;
        fi.offsetDelta = smReadU2BE(&src[pos + 1]);
        fi.totalLen = 3; fi.vtiStart = fi.vtiEnd = pos + 3; return true;
    }
    if (tag >= 252 && tag <= 254) {               /* append_frame */
        if (pos + 3 > src.size()) return false;
        fi.offsetDelta = smReadU2BE(&src[pos + 1]);
        int nLocals = tag - 251;
        size_t p = pos + 3;
        for (int i = 0; i < nLocals; i++) {
            size_t vl = smVtiLen(src, p); if (!vl || p + vl > src.size()) return false;
            p += vl;
        }
        fi.totalLen = p - pos; fi.vtiStart = pos + 3; fi.vtiEnd = p; return true;
    }
    if (tag == 255) {                             /* full_frame */
        if (pos + 3 > src.size()) return false;
        fi.offsetDelta = smReadU2BE(&src[pos + 1]);
        size_t p = pos + 3;
        if (p + 2 > src.size()) return false;
        uint16_t nLoc = smReadU2BE(&src[p]); p += 2;
        for (int i = 0; i < nLoc; i++) {
            size_t vl = smVtiLen(src, p); if (!vl || p + vl > src.size()) return false;
            p += vl;
        }
        if (p + 2 > src.size()) return false;
        uint16_t nStk = smReadU2BE(&src[p]); p += 2;
        for (int i = 0; i < nStk; i++) {
            size_t vl = smVtiLen(src, p); if (!vl || p + vl > src.size()) return false;
            p += vl;
        }
        fi.totalLen = p - pos; fi.vtiStart = pos + 3; fi.vtiEnd = p; return true;
    }
    return false;  /* reserved/invalid tag range 128..246 */
}

/* Inject a `same_frame` entry into origSM for every bci immediately following
   a goto_w trampoline jumpsite. JVMS §4.7.4 / §4.10.1.4 require an explicit
   StackMapTable entry at the instruction following any unconditional branch
   (goto, goto_w, *return, athrow, tableswitch, lookupswitch). The trampoline
   layout `goto_w (5B) + nop pad` leaves bci X+5 with no original frame; the
   verifier rejects the class with "Expected stackmap frame at this location".

   For each postGotoBci that does not coincide with an original frame's
   absolute bci, this helper emits a `same_frame` at that position. same_frame
   inherits the previous frame's type state — safe for nop padding (which
   neither pops nor pushes), and the inserted entry only needs to mark a
   valid basic-block start for the verifier's linear scan.

   The first non-coinciding original frame whose preceding anchor changes has
   its offset_delta re-encoded; tag form is preserved when possible
   (same_frame ↔ same_frame_extended, same_locals_1_stack_item ↔ _extended).

   `reservedBcis` lists bcis where the trampoline rebuild will itself emit a
   frame (tail full_frame / pop frame). A postGotoBci coinciding with one is
   skipped: injecting there would produce two frames at the same bci, and the
   second's offset_delta would underflow to 0xFFFF. This happens when the
   original method is exactly 5 bytes — the goto_w target (tailBCI) then
   equals the post-goto bci 5, and the tail's own full_frame already covers
   it. */
static bool injectPostGotoStackMapFrames(std::vector<uint8_t>& origSM,
                                          std::vector<uint32_t> postGotoBcis,
                                          const std::vector<uint32_t>& reservedBcis) {
    if (postGotoBcis.empty()) return true;

    std::vector<SmFrameInfo> frames;
    if (origSM.size() >= 2) {
        uint16_t origCount = smReadU2BE(&origSM[0]);
        size_t pos = 2;
        for (uint16_t i = 0; i < origCount; i++) {
            SmFrameInfo fi;
            if (!smParseFrame(origSM, pos, fi)) { setError("smt_parse_failed"); return false; }
            frames.push_back(fi);
            pos += fi.totalLen;
        }
    }

    std::vector<uint32_t> origAbs(frames.size());
    {
        uint32_t a = 0;
        for (size_t i = 0; i < frames.size(); i++) {
            a = (i == 0) ? frames[i].offsetDelta : (a + (uint32_t)frames[i].offsetDelta + 1);
            origAbs[i] = a;
        }
    }

    std::sort(postGotoBcis.begin(), postGotoBcis.end());
    postGotoBcis.erase(std::unique(postGotoBcis.begin(), postGotoBcis.end()),
                       postGotoBcis.end());

    std::vector<uint32_t> toInsert;
    toInsert.reserve(postGotoBcis.size());
    for (uint32_t b : postGotoBcis) {
        bool dup = false;
        for (uint32_t a : origAbs)     if (a == b) { dup = true; break; }
        if (!dup)
            for (uint32_t r : reservedBcis) if (r == b) { dup = true; break; }
        if (!dup) toInsert.push_back(b);
    }
    if (toInsert.empty()) return true;

    struct Item { uint32_t absBci; int kind; size_t origIdx; };
    std::vector<Item> items;
    items.reserve(frames.size() + toInsert.size());
    for (size_t i = 0; i < frames.size(); i++) items.push_back({ origAbs[i], 0, i });
    for (uint32_t b : toInsert)                items.push_back({ b, 1, (size_t)0 });
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.absBci != b.absBci) return a.absBci < b.absBci;
        return a.kind < b.kind;
    });

    std::vector<uint8_t> newSM;
    smPushU2BE(newSM, (uint16_t)items.size());
    uint32_t prevBci = 0;
    bool havePrev = false;
    for (const Item& it : items) {
        uint32_t delta = havePrev ? (it.absBci - prevBci - 1) : it.absBci;
        if (it.kind == 1) {
            if (delta < 64) {
                newSM.push_back((uint8_t)delta);
            } else {
                newSM.push_back(251);
                smPushU2BE(newSM, (uint16_t)delta);
            }
        } else {
            const SmFrameInfo& fi = frames[it.origIdx];
            uint8_t tag = (uint8_t)fi.tag;
            if (tag <= 63) {
                if (delta < 64) {
                    newSM.push_back((uint8_t)delta);
                } else {
                    newSM.push_back(251);
                    smPushU2BE(newSM, (uint16_t)delta);
                }
            } else if (tag >= 64 && tag <= 127) {
                if (delta < 64) {
                    newSM.push_back((uint8_t)(64 + delta));
                    newSM.insert(newSM.end(),
                                 origSM.begin() + (ptrdiff_t)fi.vtiStart,
                                 origSM.begin() + (ptrdiff_t)fi.vtiEnd);
                } else {
                    newSM.push_back(247);
                    smPushU2BE(newSM, (uint16_t)delta);
                    newSM.insert(newSM.end(),
                                 origSM.begin() + (ptrdiff_t)fi.vtiStart,
                                 origSM.begin() + (ptrdiff_t)fi.vtiEnd);
                }
            } else {
                /* Tags 247..255 already use u2 offset_delta; preserve tag form
                   and append the verbatim post-delta payload. */
                newSM.push_back(tag);
                smPushU2BE(newSM, (uint16_t)delta);
                newSM.insert(newSM.end(),
                             origSM.begin() + (ptrdiff_t)fi.vtiStart,
                             origSM.begin() + (ptrdiff_t)fi.vtiEnd);
            }
        }
        prevBci = it.absBci;
        havePrev = true;
    }

    origSM = std::move(newSM);
    return true;
}

/* ============================================================
 * Route-2 helper zone: CP readers, extra-class registry, abstract
 * interpretation, match helpers, stack-prefix VTI builders, and
 * pre-resolve scan for INVOKE / FIELD_GET / FIELD_PUT / NEW.
 * ============================================================ */

static bool readCPSlotU8(uint64_t cpAddr, int64_t cpHdrSize, uint16_t idx, uint64_t* outU8) {
    if (idx == 0) return false;
    uint64_t slotAddr = cpAddr + (uint64_t)cpHdrSize + (uint64_t)idx * 8;
    return readRemoteMem(g_target.handle, slotAddr, outU8, 8);
}

static bool readCPMethodOrFieldRef(uint64_t cpAddr, int64_t cpHdrSize, uint16_t idx,
                                    uint16_t* outClassIdx, uint16_t* outNameIdx,
                                    uint16_t* outDescIdx) {
    uint64_t slot;
    if (!readCPSlotU8(cpAddr, cpHdrSize, idx, &slot)) return false;
    uint16_t classIdx = (uint16_t)( slot        & 0xFFFF);
    uint16_t natIdx   = (uint16_t)((slot >> 16) & 0xFFFF);
    if (classIdx == 0 || natIdx == 0) return false;
    uint64_t natSlot;
    if (!readCPSlotU8(cpAddr, cpHdrSize, natIdx, &natSlot)) return false;
    uint16_t nameIdx = (uint16_t)( natSlot        & 0xFFFF);
    uint16_t descIdx = (uint16_t)((natSlot >> 16) & 0xFFFF);
    if (nameIdx == 0 || descIdx == 0) return false;
    *outClassIdx = classIdx; *outNameIdx = nameIdx; *outDescIdx = descIdx;
    return true;
}

static bool readCPClassNameIdx(uint64_t cpAddr, int64_t cpHdrSize, uint16_t idx,
                                uint16_t* outNameIdx) {
    uint64_t slot;
    if (!readCPSlotU8(cpAddr, cpHdrSize, idx, &slot)) return false;
    *outNameIdx = (uint16_t)((slot >> 16) & 0xFFFF);
    return (*outNameIdx != 0);
}

static bool readCPUtf8Symbol(uint64_t cpAddr, int64_t cpHdrSize, uint16_t idx,
                              uint64_t* outSymbolAddr) {
    return readCPSlotU8(cpAddr, cpHdrSize, idx, outSymbolAddr) && *outSymbolAddr != 0;
}

static bool readCPMethodNameDesc(uint64_t cpAddr, int64_t cpHdrSize, uint16_t mrefIdx,
                                  std::string* outName, std::string* outDesc) {
    uint16_t ci, ni, di;
    if (!readCPMethodOrFieldRef(cpAddr, cpHdrSize, mrefIdx, &ci, &ni, &di)) return false;
    uint64_t nameSym, descSym;
    if (!readCPUtf8Symbol(cpAddr, cpHdrSize, ni, &nameSym)) return false;
    if (!readCPUtf8Symbol(cpAddr, cpHdrSize, di, &descSym)) return false;
    if (!readSymbolBody(g_target.handle, nameSym, outName)) return false;
    if (!readSymbolBody(g_target.handle, descSym, outDesc)) return false;
    return true;
}

static bool readCPClassName(uint64_t cpAddr, int64_t cpHdrSize, uint16_t classIdx,
                             std::string* outInternalName) {
    uint16_t ni;
    if (!readCPClassNameIdx(cpAddr, cpHdrSize, classIdx, &ni)) return false;
    uint64_t nameSym;
    if (!readCPUtf8Symbol(cpAddr, cpHdrSize, ni, &nameSym)) return false;
    return readSymbolBody(g_target.handle, nameSym, outInternalName);
}

static int registerExtraClass(HookData& h, const std::string& internalName) {
    for (size_t i = 0; i < h.extraClasses.size(); i++)
        if (h.extraClasses[i].internalName == internalName) return (int)i;
    HookData::ExtraClassEntry e;
    e.internalName = internalName;
    if (!findInstanceKlassByName(internalName, &e.klassAddr)) return -1;
    e.symbolAddr = readKlassNameSymbol(e.klassAddr);
    if (e.symbolAddr == 0) return -1;
    h.extraClasses.push_back(e);
    return (int)(h.extraClasses.size() - 1);
}

/* Register a CP Class entry for every reference type that appears in the
   patched method's signature — the declaring class (local 0 `this`), each
   reference-class parameter, and a reference-class return type. The rebuilt
   trampoline StackMapTable uses these as exact verification types so a class
   verified after patching (not-yet-linked) passes the branch-target frame
   check at the trampoline tail.

   Array-typed and otherwise non-InstanceKlass parameters cannot be registered
   (registerExtraClass resolves only InstanceKlasses); those slots fall back to
   java/lang/Object at StackMapTable build time — correct for the branch check
   (every reference type, arrays included, is assignable to Object) though it
   would under-type the slot if the rescued prologue performed array-specific
   operations on it. This is logged, not fatal. */
static bool registerMethodEntryExtraClasses(HookData& h) {
    const std::string& ia = h.injectAt;
    bool route2 = (ia == "HEAD" || ia == "RETURN" ||
                   ia.compare(0, 7,  "INVOKE:")    == 0 ||
                   ia.compare(0, 10, "FIELD_GET:") == 0 ||
                   ia.compare(0, 10, "FIELD_PUT:") == 0 ||
                   ia.compare(0, 4,  "NEW:")       == 0);
    if (!route2) return true;

    /* local 0 = this */
    if (!h.targetIsStatic && !h.targetClassInternalName.empty()) {
        if (registerExtraClass(h, h.targetClassInternalName) < 0) {
            FVM_LOG("registerMethodEntryExtraClasses: declaring class '%s' "
                    "unresolved — `this` local will fall back to Object",
                    h.targetClassInternalName.c_str());
        }
    }

    /* reference-class parameters */
    const std::string& pd = h.paramDesc;
    if (!pd.empty() && pd[0] == '(') {
        size_t i = 1;
        while (i < pd.size() && pd[i] != ')') {
            char c = pd[i];
            if (c == 'L') {
                size_t e = pd.find(';', i);
                if (e == std::string::npos) break;
                std::string iname = pd.substr(i + 1, e - i - 1);
                if (registerExtraClass(h, iname) < 0)
                    FVM_LOG("registerMethodEntryExtraClasses: param class '%s' "
                            "unresolved — slot falls back to Object", iname.c_str());
                i = e + 1;
            } else if (c == '[') {
                /* array param — skip the whole descriptor; slot → Object */
                while (i < pd.size() && pd[i] == '[') i++;
                if (i < pd.size() && pd[i] == 'L') {
                    size_t e = pd.find(';', i);
                    if (e == std::string::npos) break;
                    i = e + 1;
                } else if (i < pd.size()) {
                    i++;
                }
            } else {
                i++;  /* primitive */
            }
        }
    }

    /* reference-class return type (RETURN inject only) */
    if (ia == "RETURN" && !h.targetReturnDesc.empty() &&
        h.targetReturnDesc[0] == 'L') {
        size_t e = h.targetReturnDesc.find(';');
        if (e != std::string::npos) {
            std::string iname = h.targetReturnDesc.substr(1, e - 1);
            if (registerExtraClass(h, iname) < 0)
                FVM_LOG("registerMethodEntryExtraClasses: return class '%s' "
                        "unresolved — return slot falls back to Object", iname.c_str());
        }
    }
    return true;
}

static bool methodHasExceptionTable(uint64_t origConstMethodAddr) {
    int64_t flagsOff = structOffset("ConstMethod", "_flags");
    if (flagsOff < 0) return false;
    uint16_t flags = 0;
    if (!readRemoteU16(g_target.handle, origConstMethodAddr + (uint64_t)flagsOff, &flags))
        return false;
    return (flags & 0x0008) != 0;
}

static uint64_t readOrigCMConstants(uint64_t origConstMethodAddr) {
    int64_t cmcOff = structOffset("ConstMethod", "_constants");
    if (cmcOff < 0) cmcOff = 8;
    uint64_t cp = 0;
    readRemotePointer(g_target.handle, origConstMethodAddr + (uint64_t)cmcOff, &cp);
    return cp;
}

static bool matchInvokeTarget(const std::string& spec, const std::string& aName,
                               const std::string& aDesc) {
    size_t lp = spec.find('(');
    if (lp == std::string::npos) return spec == aName;
    if (spec.substr(0, lp) != aName) return false;
    std::string sTail = spec.substr(lp);
    if (sTail.size() > aDesc.size()) return false;
    return aDesc.compare(0, sTail.size(), sTail) == 0;
}

static bool matchFieldTarget(const std::string& spec, const std::string& aName,
                              const std::string& aDesc) {
    size_t cp = spec.find(':');
    if (cp == std::string::npos) return spec == aName;
    return spec.substr(0, cp) == aName && spec.substr(cp + 1) == aDesc;
}

static bool matchClassName(const std::string& spec, const std::string& aInternal) {
    std::string s = spec;
    for (char& c : s) if (c == '.') c = '/';
    return s == aInternal;
}

/* Per-opcode stack delta. INT32_MIN = data-dependent, handled by caller. */
static int stackDeltaForOp(uint8_t op) {
    switch (op) {
    case 0x00: return 0;  /* nop */
    /* constants */
    case 0x01: return 1;  /* aconst_null */
    case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: case 0x08: return 1; /* iconst */
    case 0x09: case 0x0A: return 2; /* lconst */
    case 0x0B: case 0x0C: case 0x0D: return 1; /* fconst */
    case 0x0E: case 0x0F: return 2; /* dconst */
    case 0x10: return 1;  /* bipush */
    case 0x11: return 1;  /* sipush */
    case 0x12: return 1;  /* ldc */
    case 0x13: return 1;  /* ldc_w */
    case 0x14: return 2;  /* ldc2_w */
    /* loads */
    case 0x15: case 0x17: case 0x19: return 1; /* iload, fload, aload */
    case 0x16: case 0x18: return 2; /* lload, dload */
    case 0x1A: case 0x1B: case 0x1C: case 0x1D: return 1; /* iload_N */
    case 0x1E: case 0x1F: case 0x20: case 0x21: return 2; /* lload_N */
    case 0x22: case 0x23: case 0x24: case 0x25: return 1; /* fload_N */
    case 0x26: case 0x27: case 0x28: case 0x29: return 2; /* dload_N */
    case 0x2A: case 0x2B: case 0x2C: case 0x2D: return 1; /* aload_N */
    /* array loads: pop array+idx(2), push element */
    case 0x2E: case 0x30: return -1; /* iaload/faload: push 1-slot val */
    case 0x32: case 0x33: case 0x34: case 0x35: return -1; /* aaload/baload/caload/saload */
    case 0x2F: case 0x31: return 0;  /* laload/daload: pop 2, push 2 */
    /* stores */
    case 0x36: case 0x38: case 0x3A: return -1; /* istore, fstore, astore */
    case 0x37: case 0x39: return -2; /* lstore, dstore */
    case 0x3B: case 0x3C: case 0x3D: case 0x3E: return -1; /* istore_N */
    case 0x3F: case 0x40: case 0x41: case 0x42: return -2; /* lstore_N */
    case 0x43: case 0x44: case 0x45: case 0x46: return -1; /* fstore_N */
    case 0x47: case 0x48: case 0x49: case 0x4A: return -2; /* dstore_N */
    case 0x4B: case 0x4C: case 0x4D: case 0x4E: return -1; /* astore_N */
    /* array stores */
    case 0x4F: case 0x51: case 0x53: case 0x54: case 0x55: case 0x56: return -3; /* iastore/fastore/aastore/bastore/castore/sastore */
    case 0x50: case 0x52: return -4; /* lastore, dastore */
    /* stack */
    case 0x57: return -1; /* pop */
    case 0x58: return -2; /* pop2 */
    case 0x59: return 1;  /* dup */
    case 0x5A: return 1;  /* dup_x1 */
    case 0x5B: return 1;  /* dup_x2 */
    case 0x5C: return 2;  /* dup2 */
    case 0x5D: return 2;  /* dup2_x1 */
    case 0x5E: return 2;  /* dup2_x2 */
    case 0x5F: return 0;  /* swap */
    /* arithmetic (int/float: pop 2 push 1 = -1; long/double: pop 4 push 2 = -2) */
    case 0x60: case 0x62: case 0x64: case 0x66: return -1; /* iadd fadd isub fsub */
    case 0x61: case 0x63: case 0x65: case 0x67: return -2; /* ladd dadd lsub dsub */
    case 0x68: case 0x6A: case 0x6C: case 0x6E: return -1; /* imul fmul idiv fdiv */
    case 0x69: case 0x6B: case 0x6D: case 0x6F: return -2; /* lmul dmul ldiv ddiv */
    case 0x70: case 0x72: return -1; /* irem frem */
    case 0x71: case 0x73: return -2; /* lrem drem */
    case 0x74: case 0x76: return 0;  /* ineg fneg (pop 1 push 1) */
    case 0x75: case 0x77: return 0;  /* lneg dneg (pop 2 push 2) */
    case 0x78: case 0x7A: case 0x7C: return -1; /* ishl ishr iushr */
    case 0x79: case 0x7B: case 0x7D: return -1; /* lshl/lshr/lushr: pop long(2)+int(1)=3, push long(2), net=-1 */
    case 0x7E: return -1; /* iand */
    case 0x7F: return -2; /* land: pop 4, push 2 = -2 */
    case 0x80: return -1; /* ior */
    case 0x81: return -2; /* lor */
    case 0x82: return -1; /* ixor */
    case 0x83: return -2; /* lxor */
    case 0x84: return 0;  /* iinc */
    /* conversions */
    case 0x85: return 1;  /* i2l */
    case 0x86: return 0;  /* i2f */
    case 0x87: return 1;  /* i2d */
    case 0x88: return -1; /* l2i */
    case 0x89: return -1; /* l2f */
    case 0x8A: return 0;  /* l2d */
    case 0x8B: return 0;  /* f2i */
    case 0x8C: return 1;  /* f2l */
    case 0x8D: return 1;  /* f2d */
    case 0x8E: return -1; /* d2i */
    case 0x8F: return -1; /* d2f */
    case 0x90: return 0;  /* d2l: pop double(2) push long(2) = 0... actually -2+2=0 */
    case 0x91: return 0;  /* i2b */
    case 0x92: return 0;  /* i2c */
    case 0x93: return 0;  /* i2s */
    /* comparisons */
    case 0x94: return -3; /* lcmp: pop 2J push I = -4+1=-3 */
    case 0x95: case 0x96: return -1; /* fcmpl/fcmpg */
    case 0x97: case 0x98: return -3; /* dcmpl/dcmpg: pop 2D push I = -4+1=-3 */
    /* conditional branches (pop 1 or 2) */
    case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: return -1; /* ifeq..ifle */
    case 0x9F: case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4: return -2; /* if_icmp* */
    case 0xA5: case 0xA6: return -2; /* if_acmpeq/ne */
    case 0xC6: case 0xC7: return -1; /* ifnull/ifnonnull */
    /* unconditional branches */
    case 0xA7: return 0;  /* goto */
    case 0xC8: return 0;  /* goto_w */
    /* returns — treated as terminators by caller */
    case 0xAC: case 0xAE: case 0xB0: return -1; /* ireturn freturn areturn */
    case 0xAD: case 0xAF: return -2; /* lreturn dreturn */
    case 0xB1: return 0;  /* return */
    /* field/invoke/new — data-dependent */
    case 0xB2: case 0xB3: case 0xB4: case 0xB5: return INT32_MIN;
    case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA: return INT32_MIN;
    case 0xBB: return 1;  /* new */
    case 0xBC: return 0;  /* newarray: pop int push array = 0 */
    case 0xBD: return 0;  /* anewarray */
    case 0xBE: return 0;  /* arraylength: pop arr push int = 0 */
    case 0xBF: return INT32_MIN; /* athrow — terminator */
    case 0xC0: return 0;  /* checkcast */
    case 0xC1: return 0;  /* instanceof */
    case 0xC2: case 0xC3: return -1; /* monitorenter/exit */
    case 0xC4: return INT32_MIN; /* wide — fail-fast */
    case 0xC5: return INT32_MIN; /* multianewarray — data-dependent */
    case 0xC9: return INT32_MIN; /* jsr_w — fail-fast */
    case 0xA8: case 0xA9: return INT32_MIN; /* jsr/ret — fail-fast */
    case 0xAA: case 0xAB: return INT32_MIN; /* tableswitch/lookupswitch — fail-fast */
    default:
        return INT32_MIN;
    }
}

/* Compute the stack depth (in slots) at targetBci by abstract interpretation
   starting from the nearest StackMapTable frame at bci ≤ targetBci. */
static bool computeStackDepthAtBci(const std::vector<uint8_t>& code,
                                    const std::vector<uint8_t>& origSM,
                                    uint64_t cpAddr, int64_t cpHdrSize,
                                    size_t targetBci,
                                    int* outStackDepth) {
    /* Parse all frames, find the last one with abs bci ≤ targetBci. */
    size_t startBci = 0;
    int    startDepth = 0;

    if (origSM.size() >= 2) {
        uint16_t fc = smReadU2BE(&origSM[0]);
        size_t pos = 2;
        uint32_t abs_ = 0;
        for (uint16_t i = 0; i < fc; i++) {
            SmFrameInfo fi;
            if (!smParseFrame(origSM, pos, fi)) {
                setError("inject_abstract_interp_smt_parse_failed"); return false;
            }
            uint32_t thisBci = (i == 0) ? fi.offsetDelta : (abs_ + (uint32_t)fi.offsetDelta + 1);
            abs_ = thisBci;

            if (thisBci <= (uint32_t)targetBci) {
                startBci = (size_t)thisBci;
                /* Count stack items in this frame (Long/Double each count as 1 VTI). */
                startDepth = 0;
                if (fi.tag >= 64 && fi.tag <= 127) {
                    startDepth = 1; /* same_locals_1_stack_item: always 1 stack item at entry */
                    /* Actually at frame entry stack has 1 item */
                    startDepth = 1;
                } else if (fi.tag == 247) {
                    startDepth = 1;
                } else if (fi.tag == 255) {
                    /* full_frame: read stack count from vti payload */
                    /* vtiStart points after locals count+vtis; we need to skip locals */
                    size_t p = fi.vtiStart;
                    /* Skip locals u2 + locals vtis (already accounted for in vtiStart) */
                    /* Actually for full_frame vtiStart is after tag+offsetDelta, before locals_count */
                    /* Re-read: smParseFrame sets vtiStart = pos + 3 (after tag+offsetDelta)
                       for full_frame. From that point: u2 nLoc, nLoc vtis, u2 nStk, nStk vtis. */
                    if (p + 2 <= origSM.size()) {
                        uint16_t nLoc = smReadU2BE(&origSM[p]); p += 2;
                        for (int j = 0; j < nLoc; j++) {
                            size_t vl = smVtiLen(origSM, p);
                            if (!vl) { setError("inject_abstract_interp_smt_parse_failed"); return false; }
                            p += vl;
                        }
                        if (p + 2 <= origSM.size()) {
                            uint16_t nStk = smReadU2BE(&origSM[p]); p += 2;
                            startDepth = 0;
                            for (int j = 0; j < nStk; j++) {
                                size_t vl = smVtiLen(origSM, p);
                                if (!vl) { setError("inject_abstract_interp_smt_parse_failed"); return false; }
                                /* Long/Double VTI tag 4 or 3 still counts as 1 VTI but 2 slots */
                                if (p < origSM.size()) {
                                    uint8_t vtag = origSM[p];
                                    startDepth += (vtag == 4 || vtag == 3) ? 2 : 1;
                                }
                                p += vl;
                            }
                        }
                    }
                } else {
                    startDepth = 0; /* same_frame / chop / append — stack is empty at entry */
                }
            } else {
                break; /* frames past targetBci */
            }
            pos += fi.totalLen;
        }
    }

    /* Walk from startBci to targetBci, accumulating stack depth. */
    int depth = startDepth;
    static const int8_t bcL2[256] = {
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,
        3,3,3,3,3,3,3,3,3,2,-1,-1,1,1,1,1, 1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,
        3,3,1,1,-1,4,3,3,5,5,1,3,3,3,3,3, 3,3,3,3,3,3,3,3,3,3,3,3,1,4,4,4,
        2,4,3,3,-1,-1,2,3,1,3,3,3,1,2,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    };
    auto getL2 = [&](size_t off) -> int {
        if (off >= code.size()) return -1;
        uint8_t op = code[off];
        if (op == 0xAA) { int pad=(4-((off+1)%4))%4; if(off+1+pad+12>code.size()) return -1;
            int32_t lo,hi; memcpy(&lo,&code[off+1+pad+4],4); lo=_byteswap_ulong(lo);
            memcpy(&hi,&code[off+1+pad+8],4); hi=_byteswap_ulong(hi);
            return 1+pad+12+(hi-lo+1)*4; }
        if (op==0xAB) { int pad=(4-((off+1)%4))%4; if(off+1+pad+8>code.size()) return -1;
            int32_t np; memcpy(&np,&code[off+1+pad+4],4); np=_byteswap_ulong(np);
            return 1+pad+8+np*8; }
        if (op==0xC4) { if(off+1>=code.size()) return -1; return code[off+1]==0x84?6:4; }
        int l = bcL2[op]; return l > 0 ? l : 1;
    };

    /* Parse a single JVM type char at desc[pos] and return its slot count; advance pos. */
    auto descTypeSlots = [](const std::string& desc, size_t& pos) -> int {
        if (pos >= desc.size()) return 0;
        char c = desc[pos++];
        if (c == 'J' || c == 'D') return 2;
        if (c == 'L') { while (pos < desc.size() && desc[pos] != ';') pos++; if (pos < desc.size()) pos++; return 1; }
        if (c == '[') {
            while (pos < desc.size() && desc[pos] == '[') pos++;
            if (pos < desc.size() && desc[pos] == 'L') { while (pos < desc.size() && desc[pos] != ';') pos++; if (pos < desc.size()) pos++; }
            else if (pos < desc.size()) pos++;
            return 1;
        }
        return 1; /* Z B C S I F */
    };

    for (size_t off = startBci; off < targetBci;) {
        if (off >= code.size()) { setError("inject_abstract_interp_out_of_bounds"); return false; }
        uint8_t op = code[off];
        int len = getL2(off); if (len <= 0) { setError("inject_abstract_interp_decode_failed"); return false; }

        /* Terminators before targetBci → unreachable */
        if ((op >= 0xAC && op <= 0xB1) || op == 0xBF) {
            setError("inject_abstract_interp_unreachable_target"); return false;
        }

        /* fail-fast unsupported in cover zone */
        if (op == 0xAA || op == 0xAB || op == 0xC4 || op == 0xA8 || op == 0xA9 || op == 0xC9) {
            setError("inject_abstract_interp_unsupported_opcode"); return false;
        }

        /* forward goto: check if it skips past targetBci */
        if (op == 0xA7 && off + 2 < code.size()) {
            int16_t br = (int16_t)(((uint16_t)code[off+1] << 8) | code[off+2]);
            if (br < 0) { setError("inject_abstract_interp_back_branch"); return false; }
            size_t dst = off + (size_t)(int)br;
            if (dst > targetBci) { setError("inject_abstract_interp_back_branch"); return false; }
            off += (size_t)len; continue;
        }
        if (op == 0xC8 && off + 4 < code.size()) {
            int32_t br = (int32_t)(((uint32_t)code[off+1]<<24)|((uint32_t)code[off+2]<<16)|((uint32_t)code[off+3]<<8)|(uint32_t)code[off+4]);
            if (br < 0) { setError("inject_abstract_interp_back_branch"); return false; }
            size_t dst = off + (size_t)(int32_t)br;
            if (dst > targetBci) { setError("inject_abstract_interp_back_branch"); return false; }
            off += (size_t)len; continue;
        }
        /* conditional branches: don't follow, continue straight */
        if ((op >= 0x99 && op <= 0xA6) || op == 0xC6 || op == 0xC7) {
            /* check for backward branch target */
            if (off + 2 < code.size()) {
                int16_t br = (int16_t)(((uint16_t)code[off+1] << 8) | code[off+2]);
                if ((int)off + (int)br < 0) { setError("inject_abstract_interp_back_branch"); return false; }
            }
            depth += stackDeltaForOp(op);
            off += (size_t)len; continue;
        }

        int delta = stackDeltaForOp(op);
        if (delta != INT32_MIN) {
            depth += delta;
        } else {
            /* Data-dependent opcodes */
            if ((op >= 0xB6 && op <= 0xB9) || op == 0xBA) {
                /* invoke* */
                if (off + 2 < code.size()) {
                    uint16_t cpIdx = ((uint16_t)code[off+1] << 8) | code[off+2];
                    std::string mName, mDesc;
                    if (readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &mName, &mDesc)) {
                        size_t p = 1; /* skip '(' */
                        int argSlots = 0;
                        while (p < mDesc.size() && mDesc[p] != ')') argSlots += descTypeSlots(mDesc, p);
                        int retSlots = 0;
                        if (p < mDesc.size()) p++; /* skip ')' */
                        if (p < mDesc.size() && mDesc[p] != 'V') retSlots = descTypeSlots(mDesc, p);
                        int recv = (op == 0xB8) ? 0 : 1;
                        depth += retSlots - argSlots - recv;
                    }
                }
            } else if (op == 0xB4) { /* getfield */
                if (off + 2 < code.size()) {
                    uint16_t cpIdx = ((uint16_t)code[off+1] << 8) | code[off+2];
                    std::string fn, fd; readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fn, &fd);
                    size_t p = 0; int fs = descTypeSlots(fd, p);
                    depth += fs - 1;
                }
            } else if (op == 0xB2) { /* getstatic */
                if (off + 2 < code.size()) {
                    uint16_t cpIdx = ((uint16_t)code[off+1] << 8) | code[off+2];
                    std::string fn, fd; readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fn, &fd);
                    size_t p = 0; int fs = descTypeSlots(fd, p);
                    depth += fs;
                }
            } else if (op == 0xB5) { /* putfield */
                if (off + 2 < code.size()) {
                    uint16_t cpIdx = ((uint16_t)code[off+1] << 8) | code[off+2];
                    std::string fn, fd; readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fn, &fd);
                    size_t p = 0; int fs = descTypeSlots(fd, p);
                    depth += -1 - fs;
                }
            } else if (op == 0xB3) { /* putstatic */
                if (off + 2 < code.size()) {
                    uint16_t cpIdx = ((uint16_t)code[off+1] << 8) | code[off+2];
                    std::string fn, fd; readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fn, &fd);
                    size_t p = 0; int fs = descTypeSlots(fd, p);
                    depth += -fs;
                }
            } else if (op == 0xC5) { /* multianewarray */
                if (off + 3 < code.size()) {
                    int dim = code[off + 3];
                    depth += 1 - dim;
                }
            } else if (op == 0xBF) {
                break; /* athrow — terminator */
            }
        }
        off += (size_t)len;
    }
    *outStackDepth = depth;
    return true;
}

/* Pre-resolve injection targets: scan origBytecode for matching instructions,
   register any required ref-type extra classes. Sets g_lastError on F1/F7. */
static bool preResolveInjectionTargets(HookData& h, const std::string& kind,
                                        const std::string& targetSpec) {
    /* F1: method has exception table */
    if (methodHasExceptionTable(h.origConstMethodAddr)) {
        setError("head_invoke_field_new_exception_table_unsupported");
        FVM_LOG("preResolveInjectionTargets: %s skipped %s%s — exception table present",
                kind.c_str(), h.methodName.c_str(), h.paramDesc.c_str());
        return false;
    }

    uint64_t cpAddr = readOrigCMConstants(h.origConstMethodAddr);
    if (!cpAddr) return true; /* no CP → nothing to resolve; buildHookCM will fail-fast */
    int64_t cpHdrSize = typeSize("ConstantPool"); if (cpHdrSize < 0) cpHdrSize = 0x138;

    /* Helper: parse a single type from a descriptor string (L…;, […, prim). */
    auto parseSingleInternalName = [](const std::string& typeStr) -> std::string {
        if (typeStr.empty()) return "";
        if (typeStr[0] == 'L') {
            size_t end = typeStr.find(';');
            if (end != std::string::npos) return typeStr.substr(1, end - 1);
        }
        if (typeStr[0] == '[') return typeStr; /* array descriptor itself */
        return "";
    };

    /* Scan bytecode for candidate opcodes. */
    for (size_t i = 0; i < h.origBytecode.size();) {
        uint8_t op = h.origBytecode[i];

        bool isCandidate = false;
        if      (kind == "INVOKE")    isCandidate = (op==0xB6||op==0xB7||op==0xB8||op==0xB9);
        else if (kind == "FIELD_GET") isCandidate = (op==0xB4||op==0xB2);
        else if (kind == "FIELD_PUT") isCandidate = (op==0xB5||op==0xB3);
        else if (kind == "NEW")       isCandidate = (op==0xBB);

        if (!isCandidate || i + 2 >= h.origBytecode.size()) {
            /* get instruction length */
            uint8_t op2 = h.origBytecode[i];
            int l2 = 1;
            if (op2 == 0xAA) { int pad=(4-((i+1)%4))%4; int32_t hi,lo; if(i+1+pad+12<=h.origBytecode.size()){memcpy(&lo,&h.origBytecode[i+1+pad+4],4);lo=_byteswap_ulong(lo);memcpy(&hi,&h.origBytecode[i+1+pad+8],4);hi=_byteswap_ulong(hi);l2=1+pad+12+(hi-lo+1)*4;} }
            else if (op2==0xAB) { int pad=(4-((i+1)%4))%4; int32_t np; if(i+1+pad+8<=h.origBytecode.size()){memcpy(&np,&h.origBytecode[i+1+pad+4],4);np=_byteswap_ulong(np);l2=1+pad+8+np*8;} }
            else if (op2==0xC4) { if(i+1<h.origBytecode.size()) l2=h.origBytecode[i+1]==0x84?6:4; }
            else { static const int8_t bL[256]={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,-1,-1,1,1,1,1,1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,3,3,1,1,-1,4,3,3,5,5,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,1,4,4,4,2,4,3,3,-1,-1,2,3,1,3,3,3,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}; int v=bL[op2]; l2=v>0?v:1; }
            i += (size_t)(l2 > 0 ? l2 : 1);
            continue;
        }

        uint16_t cpIdx = ((uint16_t)h.origBytecode[i+1] << 8) | (uint16_t)h.origBytecode[i+2];
        int instrLen = 1; /* will refine below */
        {
            uint8_t op3 = h.origBytecode[i];
            if (op3==0xAA){int pad=(4-((i+1)%4))%4;int32_t lo,hi;if(i+1+pad+12<=h.origBytecode.size()){memcpy(&lo,&h.origBytecode[i+1+pad+4],4);lo=_byteswap_ulong(lo);memcpy(&hi,&h.origBytecode[i+1+pad+8],4);hi=_byteswap_ulong(hi);instrLen=1+pad+12+(hi-lo+1)*4;}}
            else if(op3==0xAB){int pad=(4-((i+1)%4))%4;int32_t np;if(i+1+pad+8<=h.origBytecode.size()){memcpy(&np,&h.origBytecode[i+1+pad+4],4);np=_byteswap_ulong(np);instrLen=1+pad+8+np*8;}}
            else if(op3==0xC4){if(i+1<h.origBytecode.size())instrLen=h.origBytecode[i+1]==0x84?6:4;}
            else{static const int8_t bL[256]={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,-1,-1,1,1,1,1,1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,3,3,1,1,-1,4,3,3,5,5,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,1,4,4,4,2,4,3,3,-1,-1,2,3,1,3,3,3,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};int v=bL[op3];instrLen=v>0?v:1;}
        }

        bool matched = false;
        if (kind == "INVOKE") {
            std::string mName, mDesc;
            if (!readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &mName, &mDesc)) {
                i += (size_t)instrLen; continue;
            }
            if (matchInvokeTarget(targetSpec, mName, mDesc)) {
                matched = true;
                /* Register ref parameter types */
                size_t p = 1;
                while (p < mDesc.size() && mDesc[p] != ')') {
                    char c = mDesc[p];
                    std::string iname;
                    if (c == 'L') {
                        size_t e = mDesc.find(';', p); if (e == std::string::npos) break;
                        iname = mDesc.substr(p + 1, e - p - 1); p = e + 1;
                    } else if (c == '[') {
                        size_t s = p;
                        while (p < mDesc.size() && mDesc[p] == '[') p++;
                        if (p < mDesc.size() && mDesc[p] == 'L') {
                            size_t e = mDesc.find(';', p); if (e == std::string::npos) break;
                            iname = mDesc.substr(s, e - s + 1); p = e + 1;
                        } else if (p < mDesc.size()) {
                            iname = mDesc.substr(s, p - s + 1); p++;
                        }
                    } else {
                        if (c == 'J' || c == 'D') {} /* 2-slot prim, no extra class */
                        p++;
                        continue;
                    }
                    if (!iname.empty()) {
                        int idx = registerExtraClass(h, iname);
                        if (idx < 0) {
                            setError("inject_extra_class_not_loaded:" + iname);
                            FVM_LOG("preResolveInjectionTargets: INVOKE extra class not loaded: %s", iname.c_str());
                            return false;
                        }
                    }
                }
            }
        } else if (kind == "FIELD_GET") {
            std::string fName, fDesc;
            if (readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fName, &fDesc))
                matched = matchFieldTarget(targetSpec, fName, fDesc);
            /* No extra classes needed for FIELD_GET */
        } else if (kind == "FIELD_PUT") {
            std::string fName, fDesc;
            if (readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fName, &fDesc) &&
                matchFieldTarget(targetSpec, fName, fDesc)) {
                matched = true;
                /* Register value type if ref */
                if (!fDesc.empty()) {
                    std::string iname;
                    if (fDesc[0] == 'L') {
                        size_t e = fDesc.find(';'); if (e != std::string::npos) iname = fDesc.substr(1, e - 1);
                    } else if (fDesc[0] == '[') {
                        iname = fDesc; /* array descriptor */
                    }
                    if (!iname.empty()) {
                        int idx = registerExtraClass(h, iname);
                        if (idx < 0) {
                            setError("inject_extra_class_not_loaded:" + iname);
                            FVM_LOG("preResolveInjectionTargets: FIELD_PUT extra class not loaded: %s", iname.c_str());
                            return false;
                        }
                    }
                }
            }
        } else if (kind == "NEW") {
            std::string cName;
            if (readCPClassName(cpAddr, cpHdrSize, cpIdx, &cName))
                matched = matchClassName(targetSpec, cName);
            /* No extra classes needed for NEW */
        }
        (void)matched;
        i += (size_t)instrLen;
    }
    return true;
}

/* Specification for one goto_w-trampoline tail's SMT frames. */
struct TrampolineFrameSpec {
    uint32_t             tailBCI;
    uint32_t             popBCI;
    std::vector<uint8_t> stackPrefixVtis;   /* VTI bytes for stack at tailBCI (no Cb) */
    uint16_t             stackPrefixCount;  /* number of VTI entries above */
};

/* Type specification for one operand-stack slot in a trampoline tail. */
struct StackTypeSpec {
    enum Kind { PRIM_INT, PRIM_LONG, PRIM_FLOAT, PRIM_DOUBLE, REF };
    Kind     kind;
    uint16_t refClassCpIdx;
};

static void appendStackPrefixVtis(const std::vector<StackTypeSpec>& types,
                                   std::vector<uint8_t>& outBytes,
                                   uint16_t& outCount) {
    outCount = 0;
    for (const auto& t : types) {
        switch (t.kind) {
            case StackTypeSpec::PRIM_INT:    outBytes.push_back(1); break;
            case StackTypeSpec::PRIM_LONG:   outBytes.push_back(4); break;
            case StackTypeSpec::PRIM_FLOAT:  outBytes.push_back(2); break;
            case StackTypeSpec::PRIM_DOUBLE: outBytes.push_back(3); break;
            case StackTypeSpec::REF:
                outBytes.push_back(7);              /* ITEM_Object */
                smPushU2BE(outBytes, t.refClassCpIdx);
                break;
        }
        outCount++;
    }
}

static size_t countSlotsOf(const std::vector<StackTypeSpec>& s) {
    size_t n = 0;
    for (const auto& t : s)
        n += (t.kind == StackTypeSpec::PRIM_LONG || t.kind == StackTypeSpec::PRIM_DOUBLE) ? 2 : 1;
    return n;
}

/* Look up an extra class's classCpIdx by internal name. Returns 0 if not found. */
static uint16_t lookupExtraClassCpIdx(const HookData& h, const std::string& internalName) {
    for (const auto& ex : h.extraClasses)
        if (ex.internalName == internalName) return ex.classCpIdx;
    return 0;
}

/* Parse a method descriptor's parameter list "(...)" into StackTypeSpecs.
   Ref types are resolved via h.extraClasses. Returns false on lookup failure. */
static bool parseDescParamsToStackSpecs(const std::string& methodDesc,
                                         const HookData& h,
                                         std::vector<StackTypeSpec>& outStack) {
    if (methodDesc.empty() || methodDesc[0] != '(') return true;
    size_t i = 1;
    while (i < methodDesc.size() && methodDesc[i] != ')') {
        char c = methodDesc[i];
        StackTypeSpec spec;
        if      (c == 'Z' || c == 'B' || c == 'C' || c == 'S' || c == 'I') { spec.kind = StackTypeSpec::PRIM_INT;    i++; }
        else if (c == 'F') { spec.kind = StackTypeSpec::PRIM_FLOAT;   i++; }
        else if (c == 'J') { spec.kind = StackTypeSpec::PRIM_LONG;    i++; }
        else if (c == 'D') { spec.kind = StackTypeSpec::PRIM_DOUBLE;  i++; }
        else if (c == 'L') {
            spec.kind = StackTypeSpec::REF;
            size_t e = methodDesc.find(';', i); if (e == std::string::npos) return false;
            std::string iname = methodDesc.substr(i + 1, e - i - 1);
            spec.refClassCpIdx = lookupExtraClassCpIdx(h, iname);
            if (spec.refClassCpIdx == 0) { setError("inject_extra_class_cp_not_found:" + iname); return false; }
            i = e + 1;
        } else if (c == '[') {
            spec.kind = StackTypeSpec::REF;
            size_t s = i;
            while (i < methodDesc.size() && methodDesc[i] == '[') i++;
            std::string iname;
            if (i < methodDesc.size() && methodDesc[i] == 'L') {
                size_t e = methodDesc.find(';', i); if (e == std::string::npos) return false;
                iname = methodDesc.substr(s, e - s + 1); i = e + 1;
            } else if (i < methodDesc.size()) {
                iname = methodDesc.substr(s, i - s + 1); i++;
            }
            spec.refClassCpIdx = lookupExtraClassCpIdx(h, iname);
            if (spec.refClassCpIdx == 0) { setError("inject_extra_class_cp_not_found:" + iname); return false; }
        } else {
            return false;
        }
        outStack.push_back(spec);
    }
    return true;
}

/* Parse a single field descriptor into a StackTypeSpec. */
static bool parseSingleDescTypeToStackSpec(const std::string& fieldDesc,
                                            const HookData& h,
                                            std::vector<StackTypeSpec>& outStack) {
    if (fieldDesc.empty()) return true;
    StackTypeSpec spec;
    char c = fieldDesc[0];
    if      (c == 'Z' || c == 'B' || c == 'C' || c == 'S' || c == 'I') spec.kind = StackTypeSpec::PRIM_INT;
    else if (c == 'F') spec.kind = StackTypeSpec::PRIM_FLOAT;
    else if (c == 'J') spec.kind = StackTypeSpec::PRIM_LONG;
    else if (c == 'D') spec.kind = StackTypeSpec::PRIM_DOUBLE;
    else if (c == 'L') {
        spec.kind = StackTypeSpec::REF;
        size_t e = fieldDesc.find(';');
        if (e == std::string::npos) return false;
        std::string iname = fieldDesc.substr(1, e - 1);
        spec.refClassCpIdx = lookupExtraClassCpIdx(h, iname);
        if (spec.refClassCpIdx == 0) { setError("inject_extra_class_cp_not_found:" + iname); return false; }
    } else if (c == '[') {
        spec.kind = StackTypeSpec::REF;
        spec.refClassCpIdx = lookupExtraClassCpIdx(h, fieldDesc);
        if (spec.refClassCpIdx == 0) { setError("inject_extra_class_cp_not_found:" + fieldDesc); return false; }
    } else {
        return false;
    }
    outStack.push_back(spec);
    return true;
}

/* ============================================================
 * End of route-2 helper zone.
 * ============================================================ */

/* Append method-entry locals as a packed verification_type_info[] to `out`,
   returning the locals_count in `outCount`. Each reference slot is encoded as
   ITEM_Object with the slot's *exact declared class* — local 0 is the
   declaring class, each reference-class parameter its declared type. The
   goto_w that enters the trampoline tail carries the real method-entry frame;
   the verifier requires that frame assignable to the tail frame, so the tail
   frame must declare the exact types (Object would be too wide — the rescued
   prologue's `aload_0; invokevirtual <declaringClass>.m` would then fail; Null
   too narrow — the incoming declaring-class value is not assignable to Null).
   The exact-class CP entries are registered up front by
   registerMethodEntryExtraClasses; a slot whose class could not be registered
   (array type, unresolvable class) falls back to java/lang/Object.
   Primitives map to ITEM_Integer / Long / Float / Double; Long and Double take
   one VTI slot each per JVMS §4.7.4 (the JVM's "two-slot" rule for J/D applies
   to slot indices, not to the SMT entry count). */
static bool appendMethodEntryLocalsVtis(const HookData& h,
                                        std::vector<uint8_t>& out,
                                        uint16_t& outCount) {
    outCount = 0;
    auto pushRef = [&](uint16_t classCpIdx) {
        out.push_back(7);                  /* ITEM_Object */
        smPushU2BE(out, classCpIdx ? classCpIdx : h.objClassCpIdx);
        outCount++;
    };
    if (!h.targetIsStatic)                 /* locals[0] = this */
        pushRef(lookupExtraClassCpIdx(h, h.targetClassInternalName));

    const std::string& paramDesc = h.paramDesc;
    if (paramDesc.empty() || paramDesc[0] != '(') {
        setError("invalid_param_descriptor"); return false;
    }
    size_t i = 1;
    while (i < paramDesc.size() && paramDesc[i] != ')') {
        char c = paramDesc[i];
        if      (c == 'B' || c == 'C' || c == 'I' || c == 'S' || c == 'Z') {
            out.push_back(1); outCount++; i++;
        } else if (c == 'F') { out.push_back(2); outCount++; i++; }
        else   if (c == 'J') { out.push_back(4); outCount++; i++; }
        else   if (c == 'D') { out.push_back(3); outCount++; i++; }
        else   if (c == 'L') {
            size_t e = paramDesc.find(';', i);
            std::string iname = (e == std::string::npos)
                              ? std::string()
                              : paramDesc.substr(i + 1, e - i - 1);
            pushRef(lookupExtraClassCpIdx(h, iname));
            i = (e == std::string::npos) ? paramDesc.size() : e + 1;
        } else if (c == '[') {
            /* array-typed param — no InstanceKlass CP entry; Object fallback */
            pushRef(0);
            while (i < paramDesc.size() && paramDesc[i] == '[') i++;
            if (i < paramDesc.size() && paramDesc[i] == 'L') {
                while (i < paramDesc.size() && paramDesc[i] != ';') i++;
                if (i < paramDesc.size()) i++;
            } else if (i < paramDesc.size()) {
                i++;
            }
        } else {
            setError("invalid_param_descriptor_char"); return false;
        }
    }
    return true;
}

/* Build the rebuilt StackMapTable body ([u2 count][frames]) for any goto_w
   trampoline injection. Original frames are copied verbatim (bcis preserved);
   each TrampolineFrameSpec contributes a full_frame@tailBCI and a (247 or 255)
   frame@popBCI. Tails must be sorted by tailBCI ascending. */
static bool rebuildStackMapTrampoline(
    const std::vector<uint8_t>& origSM,
    const std::vector<TrampolineFrameSpec>& tails,
    const HookData& h,
    std::vector<uint8_t>& out) {
    uint16_t cbClassCpIdx = h.cbClassCpIdx;
    out.clear();

    /* Parse original frames once. */
    std::vector<SmFrameInfo> frames;
    if (origSM.size() >= 2) {
        uint16_t origCount = smReadU2BE(&origSM[0]);
        size_t pos = 2;
        for (uint16_t i = 0; i < origCount; i++) {
            SmFrameInfo fi;
            if (!smParseFrame(origSM, pos, fi)) { setError("smt_parse_failed"); return false; }
            frames.push_back(fi);
            pos += fi.totalLen;
        }
    }

    /* Pre-build method-entry locals VTI bytes (reused by every tail frame). */
    std::vector<uint8_t> localsVtiBytes;
    uint16_t numLocals = 0;
    if (!appendMethodEntryLocalsVtis(h, localsVtiBytes, numLocals)) return false;

    smPushU2BE(out, (uint16_t)(frames.size() + 2 * tails.size()));

    /* Copy each original frame verbatim. Absolute bcis are unchanged in the
       new bytecode, so the delta encoding is preserved exactly. */
    uint32_t prevBci = 0;
    uint32_t origAbs = 0;
    for (size_t i = 0; i < frames.size(); i++) {
        const SmFrameInfo& fi = frames[i];
        origAbs = (i == 0) ? fi.offsetDelta : (origAbs + (uint32_t)fi.offsetDelta + 1);
        size_t frameStart = fi.vtiStart - ((fi.tag <= 127) ? 1u : 3u);
        out.insert(out.end(), origSM.begin() + (ptrdiff_t)frameStart,
                              origSM.begin() + (ptrdiff_t)(frameStart + fi.totalLen));
        prevBci = origAbs;
    }

    /* For each tail: full_frame@tailBCI + (247 or full_frame)@popBCI. */
    for (size_t t = 0; t < tails.size(); t++) {
        const TrampolineFrameSpec& spec = tails[t];
        uint32_t tailDelta = (t == 0 && frames.empty())
                           ? spec.tailBCI
                           : (spec.tailBCI - prevBci - 1);
        out.push_back(255);
        smPushU2BE(out, (uint16_t)tailDelta);
        smPushU2BE(out, numLocals);
        out.insert(out.end(), localsVtiBytes.begin(), localsVtiBytes.end());
        smPushU2BE(out, spec.stackPrefixCount);
        out.insert(out.end(), spec.stackPrefixVtis.begin(), spec.stackPrefixVtis.end());
        prevBci = spec.tailBCI;

        uint32_t popDelta = spec.popBCI - prevBci - 1;
        if (spec.stackPrefixCount == 0) {
            out.push_back(247);
            smPushU2BE(out, (uint16_t)popDelta);
            out.push_back(7);
            smPushU2BE(out, cbClassCpIdx);
        } else {
            out.push_back(255);
            smPushU2BE(out, (uint16_t)popDelta);
            smPushU2BE(out, numLocals);
            out.insert(out.end(), localsVtiBytes.begin(), localsVtiBytes.end());
            smPushU2BE(out, (uint16_t)(spec.stackPrefixCount + 1));
            out.insert(out.end(), spec.stackPrefixVtis.begin(), spec.stackPrefixVtis.end());
            out.push_back(7);
            smPushU2BE(out, cbClassCpIdx);
        }
        prevBci = spec.popBCI;
    }
    return true;
}

/* Build the new ConstMethod bytes for a single hook (bytecode injection + trailing data). */
static bool buildHookCM(HookData& h, uint64_t newPoolRemoteAddr) {
    HANDLE proc = g_target.handle;

    /* bcLengths table */
    static const int8_t bcL[256] = {
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,
        3,3,3,3,3,3,3,3,3,2,-1,-1,1,1,1,1, 1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,
        3,3,1,1,-1,4,3,3,5,5,1,3,3,3,3,3, 3,3,3,3,3,3,3,3,3,3,3,3,1,4,4,4,
        2,4,3,3,-1,-1,2,3,1,3,3,3,1,2,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    };
    auto getLen = [&](size_t off) -> int {
        uint8_t op = h.origBytecode[off];
        if (op == 0xAA) { int pad=(4-((off+1)%4))%4; if(off+1+pad+12>h.origBytecode.size())return-1;
            int32_t lo,hi; memcpy(&lo,&h.origBytecode[off+1+pad+4],4); lo=_byteswap_ulong(lo);
            memcpy(&hi,&h.origBytecode[off+1+pad+8],4); hi=_byteswap_ulong(hi);
            return 1+pad+12+(hi-lo+1)*4; }
        if (op==0xAB||op==0xE4||op==0xE5) { int pad=(4-((off+1)%4))%4; if(off+1+pad+8>h.origBytecode.size())return-1;
            int32_t np; memcpy(&np,&h.origBytecode[off+1+pad+4],4); np=_byteswap_ulong(np);
            return 1+pad+8+np*8; }
        if (op==0xC4) { if(off+1>=h.origBytecode.size())return-1; return h.origBytecode[off+1]==0x84?6:4; }
        int l = bcL[op]; return l>0?l:1;
    };

    auto emitIdx = [](std::vector<uint8_t>& bc, uint16_t idx) {
        bc.push_back((uint8_t)(idx>>8)); bc.push_back((uint8_t)(idx&0xFF)); };
    auto emitNI  = [](std::vector<uint8_t>& bc, uint16_t idx) {
        bc.push_back((uint8_t)(idx&0xFF)); bc.push_back((uint8_t)(idx>>8)); };
    auto emitGW  = [](std::vector<uint8_t>& bc, int32_t ph) -> size_t {
        bc.push_back(0xC8); size_t fi=bc.size(); uint32_t v=(uint32_t)ph;
        bc.push_back(v>>24); bc.push_back(v>>16); bc.push_back(v>>8); bc.push_back(v); return fi; };
    auto patchGW = [](std::vector<uint8_t>& bc, size_t fi, size_t instrBCI, size_t tgt) {
        uint32_t v=(uint32_t)((int32_t)tgt-(int32_t)instrBCI);
        bc[fi]=v>>24; bc[fi+1]=v>>16; bc[fi+2]=v>>8; bc[fi+3]=v; };
    auto coverEnd= [&](size_t x)->size_t {
        size_t k=x; while(k<x+5&&k<h.origBytecode.size()){int l=getLen(k);if(l<=0)l=1;k+=(size_t)l;} return k; };

    /* Invoke operands are CPCache indices (native u2 — little-endian on x86),
       per HotSpot's post-rewrite convention. The target class is always linked
       and rewritten by the time it reaches here (commitKlass refuses unlinked
       classes; they are parked for deferred commit). */
    uint16_t hookCI16   = (uint16_t)h.hookCacheIdx;
    uint16_t initCI16   = (uint16_t)h.initCacheIdx;
    uint16_t cancelCI16 = (uint16_t)h.cancelCacheIdx;
    uint16_t retValCI16 = (uint16_t)h.retValCacheIdx;
    uint16_t unboxCI16  = h.needsUnbox ? (uint16_t)h.unboxCacheIdx : 0;

    /* cancelReturn sequence */
    std::vector<uint8_t> cancelReturn;
    if (h.unboxReturnOp == 0xB1) {
        cancelReturn.push_back(0x57); cancelReturn.push_back(0xB1);
    } else {
        cancelReturn.push_back(0xB7); emitNI(cancelReturn, retValCI16);
        if (h.needsUnbox) {
            cancelReturn.push_back(0xC0); emitIdx(cancelReturn, h.unboxClassCpIdx);
            cancelReturn.push_back(0xB7); emitNI(cancelReturn, unboxCI16);
        }
        cancelReturn.push_back(h.unboxReturnOp);
    }
    int16_t ifeqOff = (int16_t)(3 + (int)cancelReturn.size());

    /* emitCallbackPrologue inline helper */
    auto emitPrologue = [&](std::vector<uint8_t>& bc) {
        bc.push_back(0xBB); emitIdx(bc, h.cbClassCpIdx);
        bc.push_back(0x59);
        if (h.targetIsStatic) bc.push_back(0x01); else bc.push_back(0x2A);
        if (!h.hasArgCapture || h.targetParams.empty()) {
            bc.push_back(0x01);
        } else {
            int n=(int)h.targetParams.size();
            if (n<=5) bc.push_back((uint8_t)(0x03+n)); else { bc.push_back(0x10); bc.push_back((uint8_t)n); }
            bc.push_back(0xBD); emitIdx(bc, h.objClassCpIdx);
            for (int i=0;i<n;i++) {
                bc.push_back(0x59);
                if (i<=5) bc.push_back((uint8_t)(0x03+i)); else { bc.push_back(0x10); bc.push_back((uint8_t)i); }
                if (h.targetParams[i].isRef) {
                    int sl=h.targetParams[i].slot;
                    if(sl<=3) bc.push_back((uint8_t)(0x2A+sl)); else { bc.push_back(0x19); bc.push_back((uint8_t)sl); }
                } else bc.push_back(0x01);
                bc.push_back(0x53);
            }
        }
        bc.push_back(0xB7); emitNI(bc, initCI16);
        bc.push_back(0x59); bc.push_back(0x59);
        bc.push_back(0xB8); emitNI(bc, hookCI16);
        bc.push_back(0xB7); emitNI(bc, cancelCI16);
        bc.push_back(0x99); bc.push_back((uint8_t)(ifeqOff>>8)); bc.push_back((uint8_t)(ifeqOff&0xFF));
        bc.insert(bc.end(), cancelReturn.begin(), cancelReturn.end());
        bc.push_back(0x57);
    };

    /* buildTrampoline inline helper */
    std::string injectType = h.injectAt;
    std::string injectTargetName;
    size_t colonPos = h.injectAt.find(':');
    if (colonPos != std::string::npos) {
        injectType = h.injectAt.substr(0, colonPos);
        injectTargetName = h.injectAt.substr(colonPos + 1);
    }

    std::vector<uint8_t> newBytecode;

    auto buildTramp = [&](size_t x, uint8_t tailRetOp) -> bool {
        size_t k = coverEnd(x);
        if (k > h.origBytecode.size()) k = h.origBytecode.size();
        size_t gwiBCI = newBytecode.size();
        size_t fi = emitGW(newBytecode, 0);
        for (size_t b=x+5; b<k; b++) newBytecode.push_back(0x00);
        std::vector<uint8_t> rescued(h.origBytecode.begin()+x, h.origBytecode.begin()+k);
        for (size_t off=0; off<rescued.size();) {
            uint8_t op=rescued[off];
            if (op==0xAA||op==0xAB||op==0xC4||op==0xA8||op==0xA9||op==0xC9||op==0xE4||op==0xE5) {
                setError("rescue_zone_contains_unsupported_opcode"); return false;
            }
            int rl=bcL[op]; if(rl<=0)rl=1; off+=(size_t)rl;
        }
        for (size_t b=k; b<h.origBytecode.size(); b++) newBytecode.push_back(h.origBytecode[b]);
        size_t tailBCI = newBytecode.size();
        patchGW(newBytecode, fi, gwiBCI, tailBCI);
        emitPrologue(newBytecode);
        size_t rescuedBCI = newBytecode.size();
        int32_t shift = (int32_t)x - (int32_t)rescuedBCI;
        for (size_t off=0; off<rescued.size();) {
            uint8_t op=rescued[off]; int rl=bcL[op]; if(rl<=0)rl=1;
            bool b2 = (op>=0x99&&op<=0xA7)||op==0xC6||op==0xC7;
            bool b4 = (op==0xC8);
            if (b2&&off+2<rescued.size()) {
                int16_t or2=(int16_t)(((uint16_t)rescued[off+1]<<8)|rescued[off+2]);
                int32_t nr=(int32_t)or2+shift;
                if(nr>32767||nr<-32768){setError("rescue_branch_offset_overflow_int16");return false;}
                rescued[off+1]=(uint8_t)((uint16_t)nr>>8); rescued[off+2]=(uint8_t)((uint16_t)nr&0xFF);
            } else if (b4&&off+4<rescued.size()) {
                int32_t or4=(int32_t)(((uint32_t)rescued[off+1]<<24)|((uint32_t)rescued[off+2]<<16)|((uint32_t)rescued[off+3]<<8)|(uint32_t)rescued[off+4]);
                int32_t nr=or4+shift;
                rescued[off+1]=(uint8_t)((uint32_t)nr>>24); rescued[off+2]=(uint8_t)((uint32_t)nr>>16);
                rescued[off+3]=(uint8_t)((uint32_t)nr>>8);  rescued[off+4]=(uint8_t)((uint32_t)nr&0xFF);
            }
            off+=(size_t)rl;
        }
        newBytecode.insert(newBytecode.end(), rescued.begin(), rescued.end());
        if (tailRetOp != 0) {
            newBytecode.push_back(tailRetOp);
        } else if (k < h.origBytecode.size()) {
            size_t gbiBCI = newBytecode.size();
            size_t fib = emitGW(newBytecode, 0);
            patchGW(newBytecode, fib, gbiBCI, k);
        }
        return true;
    };

    newBytecode.reserve(h.origBytecode.size() + 128);

    if (injectType == "HEAD") {
        /* goto_w-trampoline layout — original bcis ≥ J are preserved verbatim,
         * so LocalVariableTable / exception_table / LineNumberTable need no
         * rebase. J is the bci of the first original StackMapTable frame (or
         * origSize when there are none). Methods whose first frame is too
         * early to host a goto_w prefix, or whose rescue zone contains opcodes
         * that cannot be safely relocated, are rejected up-front. */

        /* Read original StackMapTable (Array<u1>{ int _length; u1 _data[] }). */
        std::vector<uint8_t> origSM;
        {
            int64_t smOff0 = structOffset("ConstMethod", "_stackmap_data");
            if (smOff0 >= 0) {
                uint64_t smArr = 0;
                if (readRemotePointer(proc, h.origConstMethodAddr + (uint64_t)smOff0, &smArr)
                    && smArr != 0) {
                    int64_t aLen  = structOffset("Array<u1>", "_length"); if (aLen  < 0) aLen  = 0;
                    int64_t aData = structOffset("Array<u1>", "_data");   if (aData < 0) aData = 4;
                    int32_t n = 0;
                    if (readRemoteI32(proc, smArr + (uint64_t)aLen, &n) && n > 0 && n < (1 << 24)) {
                        origSM.resize((size_t)n);
                        if (!readRemoteMem(proc, smArr + (uint64_t)aData, origSM.data(), (size_t)n))
                            origSM.clear();
                    }
                }
            }
        }

        /* Compute J = first original frame's absolute bci, or origSize. */
        size_t J;
        if (origSM.size() >= 2 && smReadU2BE(&origSM[0]) > 0) {
            SmFrameInfo f0;
            if (!smParseFrame(origSM, 2, f0)) {
                setError("smt_parse_failed");
                FVM_LOG("buildHookCM: HEAD skipped %s%s — StackMapTable parse failed",
                        h.methodName.c_str(), h.paramDesc.c_str());
                return false;
            }
            J = (size_t)f0.offsetDelta;
        } else {
            J = h.origBytecode.size();
        }

        if (J < 5 || J > h.origBytecode.size()) {
            setError("head_rescue_zone_invalid_size");
            FVM_LOG("buildHookCM: HEAD skipped %s%s — rescue size J=%zu out of "
                    "range (need 5..%zu)", h.methodName.c_str(), h.paramDesc.c_str(),
                    J, h.origBytecode.size());
            return false;
        }

        /* Validate orig[0..J): every instruction boundary, no opcode that
           cannot be safely relocated to the rescued tail (tableswitch,
           lookupswitch, wide, jsr/ret, goto_w/jsr_w in rescue zone). */
        for (size_t off = 0; off < J;) {
            uint8_t op = h.origBytecode[off];
            if (op==0xAA||op==0xAB||op==0xC4||op==0xA8||op==0xA9||op==0xC9||op==0xE4||op==0xE5) {
                setError("head_rescue_zone_unsupported_opcode");
                FVM_LOG("buildHookCM: HEAD skipped %s%s — rescue zone contains "
                        "unsupported opcode 0x%02X at bci %zu",
                        h.methodName.c_str(), h.paramDesc.c_str(), op, off);
                return false;
            }
            int l = getLen(off);
            if (l <= 0) {
                setError("head_rescue_zone_decode_failed");
                return false;
            }
            off += (size_t)l;
            if (off > J) {
                setError("head_J_not_on_instr_boundary");
                FVM_LOG("buildHookCM: HEAD skipped %s%s — first frame bci %zu "
                        "is not on an instruction boundary",
                        h.methodName.c_str(), h.paramDesc.c_str(), J);
                return false;
            }
        }

        /* Build trampoline bytecode.
         *   bci 0..4         : goto_w → tailBCI (patched once tailBCI is known)
         *   bci 5..J-1       : nop pad
         *   bci J..origEnd-1 : orig[J..end) verbatim
         *   bci tailBCI..    : prologue, rescued copy of orig[0..J), goto J */
        size_t gwBCI = newBytecode.size();           /* = 0 for HEAD */
        size_t gwFi  = emitGW(newBytecode, 0);
        for (size_t b = gwBCI + 5; b < J; b++) newBytecode.push_back(0x00);
        for (size_t b = J; b < h.origBytecode.size(); b++) newBytecode.push_back(h.origBytecode[b]);

        size_t tailBCI = newBytecode.size();
        patchGW(newBytecode, gwFi, gwBCI, tailBCI);

        emitPrologue(newBytecode);
        size_t popBCI = newBytecode.size() - 1;       /* the trailing `pop` (0x57) */

        size_t rescuedBCI = newBytecode.size();
        std::vector<uint8_t> rescued(h.origBytecode.begin(),
                                     h.origBytecode.begin() + (ptrdiff_t)J);
        int32_t shift = (int32_t)gwBCI - (int32_t)rescuedBCI;
        size_t lastInstrOff = 0;
        for (size_t off = 0; off < rescued.size();) {
            lastInstrOff = off;
            uint8_t op = rescued[off];
            int rl = bcL[op]; if (rl <= 0) rl = 1;
            bool b2 = (op >= 0x99 && op <= 0xA7) || op == 0xC6 || op == 0xC7;
            bool b4 = (op == 0xC8);
            if (b2 && off + 2 < rescued.size()) {
                int16_t or2 = (int16_t)(((uint16_t)rescued[off+1] << 8) | rescued[off+2]);
                int32_t nr  = (int32_t)or2 + shift;
                if (nr > 32767 || nr < -32768) {
                    setError("head_rescue_branch_offset_overflow_int16");
                    return false;
                }
                rescued[off+1] = (uint8_t)((uint16_t)nr >> 8);
                rescued[off+2] = (uint8_t)((uint16_t)nr & 0xFF);
            } else if (b4 && off + 4 < rescued.size()) {
                int32_t or4 = (int32_t)(((uint32_t)rescued[off+1] << 24)
                                      | ((uint32_t)rescued[off+2] << 16)
                                      | ((uint32_t)rescued[off+3] <<  8)
                                      |  (uint32_t)rescued[off+4]);
                int32_t nr  = or4 + shift;
                rescued[off+1] = (uint8_t)((uint32_t)nr >> 24);
                rescued[off+2] = (uint8_t)((uint32_t)nr >> 16);
                rescued[off+3] = (uint8_t)((uint32_t)nr >>  8);
                rescued[off+4] = (uint8_t)((uint32_t)nr & 0xFF);
            }
            off += (size_t)rl;
        }
        newBytecode.insert(newBytecode.end(), rescued.begin(), rescued.end());
        /* Emit the jumpback goto_w → J only when control can fall through the
           end of the rescued prologue. If its last instruction is an
           unconditional terminator (goto / goto_w / *return / athrow), the
           jumpback is unreachable dead code — and being the instruction right
           after a terminator it would require its own StackMapTable frame,
           which the rebuilt table does not provide ("Expecting a stack map
           frame" at that goto_w). */
        {
            uint8_t lastOp = rescued.empty() ? 0 : rescued[lastInstrOff];
            bool rescuedEndsTerminator =
                (lastOp == 0xA7 || lastOp == 0xC8 || lastOp == 0xBF ||
                 (lastOp >= 0xAC && lastOp <= 0xB1));
            if (J < h.origBytecode.size() && !rescuedEndsTerminator) {
                size_t gbBCI = newBytecode.size();
                size_t gbFi  = emitGW(newBytecode, 0);
                patchGW(newBytecode, gbFi, gbBCI, J);
            }
        }

        if (h.needObjectCp && h.objClassCpIdx == 0) {
            setError("head_object_cp_idx_not_allocated");
            FVM_LOG("buildHookCM: HEAD skipped %s%s — Object CP entry was not "
                    "allocated (resolveHookData layout state inconsistent)",
                    h.methodName.c_str(), h.paramDesc.c_str());
            return false;
        }
        /* JVMS §4.7.4: bci immediately following the goto_w (= 5) must carry
           an explicit StackMapTable entry, even though the nop padding is
           unreachable in practice. Skipped when tailBCI == 5 (5-byte original
           method) — the tail's own full_frame already sits at bci 5. */
        if (!injectPostGotoStackMapFrames(origSM, { (uint32_t)5 },
                                          { (uint32_t)tailBCI, (uint32_t)popBCI }))
            return false;
        {
            TrampolineFrameSpec spec;
            spec.tailBCI = (uint32_t)tailBCI;
            spec.popBCI  = (uint32_t)popBCI;
            spec.stackPrefixCount = 0;
            if (!rebuildStackMapTrampoline(origSM, { spec }, h,
                                           h.newStackMapBytes))
                return false;
        }
        h.haveNewStackMap = true;
        FVM_LOG("buildHookCM: HEAD goto_w-tramp J=%zu tailBCI=%zu popBCI=%zu "
                "origSM=%zuB newSM=%zuB",
                J, tailBCI, popBCI, origSM.size(), h.newStackMapBytes.size());
    } else if (injectType == "RETURN") {
        /* Each `*return` is replaced in-place with goto_w → tailBCI plus nop
         * padding extending to the original instruction boundary at the end of
         * a 5-byte (or longer) cover zone. The cover zone preserves every bci
         * outside it, so trailing ConstMethod sections (LocalVariableTable /
         * exception_table / LineNumberTable) need no rebase — same property
         * the HEAD trampoline relies on. */

        /* Read original StackMapTable (Array<u1>{ int _length; u1 _data[] }). */
        std::vector<uint8_t> origSM;
        {
            int64_t smOff0 = structOffset("ConstMethod", "_stackmap_data");
            if (smOff0 >= 0) {
                uint64_t smArr = 0;
                if (readRemotePointer(proc, h.origConstMethodAddr + (uint64_t)smOff0, &smArr)
                    && smArr != 0) {
                    int64_t aLen  = structOffset("Array<u1>", "_length"); if (aLen  < 0) aLen  = 0;
                    int64_t aData = structOffset("Array<u1>", "_data");   if (aData < 0) aData = 4;
                    int32_t n = 0;
                    if (readRemoteI32(proc, smArr + (uint64_t)aLen, &n) && n > 0 && n < (1 << 24)) {
                        origSM.resize((size_t)n);
                        if (!readRemoteMem(proc, smArr + (uint64_t)aData, origSM.data(), (size_t)n))
                            origSM.clear();
                    }
                }
            }
        }

        uint8_t retOp = 0xB1;
        std::vector<size_t> retFi, retBCI;
        std::vector<std::pair<size_t,size_t>> coverZones;   /* (X, k) per *return */
        for (size_t i=0; i<h.origBytecode.size();) {
            uint8_t op = h.origBytecode[i];
            if (op>=0xAC&&op<=0xB1) {
                retOp = op;
                size_t instrBCI = newBytecode.size();
                size_t fi = emitGW(newBytecode, 0);
                retFi.push_back(fi); retBCI.push_back(instrBCI);
                size_t k = coverEnd(i);
                for (size_t b=i+5; b<k; b++) newBytecode.push_back(0x00);
                coverZones.push_back({ i, k });
                i = k;
            } else {
                int l=getLen(i); if(l<=0)l=1;
                for(int j=0;j<l;j++) newBytecode.push_back(h.origBytecode[i+j]); i+=(size_t)l;
            }
        }

        /* Reject the hook if any original frame falls strictly inside a cover
           zone — those bcis no longer correspond to instruction boundaries. */
        if (origSM.size() >= 2) {
            uint16_t fc = smReadU2BE(&origSM[0]);
            size_t pos = 2;
            uint32_t abs_ = 0;
            for (uint16_t fi = 0; fi < fc; fi++) {
                SmFrameInfo si;
                if (!smParseFrame(origSM, pos, si)) {
                    setError("smt_parse_failed");
                    FVM_LOG("buildHookCM: RETURN skipped %s%s — StackMapTable parse failed",
                            h.methodName.c_str(), h.paramDesc.c_str());
                    return false;
                }
                abs_ = (fi == 0) ? si.offsetDelta : (abs_ + (uint32_t)si.offsetDelta + 1);
                for (auto& z : coverZones) {
                    if (abs_ > z.first && abs_ < z.second) {
                        setError("return_frame_inside_cover_zone");
                        FVM_LOG("buildHookCM: RETURN skipped %s%s — original "
                                "frame bci %u falls inside cover zone (%zu,%zu)",
                                h.methodName.c_str(), h.paramDesc.c_str(),
                                abs_, z.first, z.second);
                        return false;
                    }
                }
                pos += si.totalLen;
            }
        }

        size_t tailBCI = newBytecode.size();
        emitPrologue(newBytecode);
        size_t popBCI = newBytecode.size() - 1;          /* the trailing `pop` (0x57) */
        newBytecode.push_back(retOp);
        for (size_t r=0; r<retFi.size(); r++) patchGW(newBytecode, retFi[r], retBCI[r], tailBCI);

        if (h.needObjectCp && h.objClassCpIdx == 0) {
            setError("return_object_cp_idx_not_allocated");
            FVM_LOG("buildHookCM: RETURN skipped %s%s — Object CP entry was not "
                    "allocated (resolveHookData layout state inconsistent)",
                    h.methodName.c_str(), h.paramDesc.c_str());
            return false;
        }
        /* JVMS §4.7.4: every bci immediately after a trampoline goto_w
           (replacing a *return) requires an explicit StackMapTable entry. */
        {
            std::vector<uint32_t> postGotoBcis;
            postGotoBcis.reserve(coverZones.size());
            for (auto& z : coverZones) postGotoBcis.push_back((uint32_t)(z.first + 5));
            if (!injectPostGotoStackMapFrames(
                    origSM, postGotoBcis,
                    { (uint32_t)tailBCI, (uint32_t)popBCI })) return false;
        }
        {
            TrampolineFrameSpec spec;
            spec.tailBCI = (uint32_t)tailBCI;
            spec.popBCI  = (uint32_t)popBCI;
            spec.stackPrefixCount = 0;
            /* For non-void RETURN, stack at tailBCI has the return value. */
            bool hasRetVal = !h.targetReturnDesc.empty() && h.targetReturnDesc[0] != 'V';
            if (hasRetVal) {
                char c = h.targetReturnDesc[0];
                StackTypeSpec st;
                if      (c=='Z'||c=='B'||c=='C'||c=='S'||c=='I') st.kind = StackTypeSpec::PRIM_INT;
                else if (c=='F') st.kind = StackTypeSpec::PRIM_FLOAT;
                else if (c=='J') st.kind = StackTypeSpec::PRIM_LONG;
                else if (c=='D') st.kind = StackTypeSpec::PRIM_DOUBLE;
                else {
                    /* Reference return: the rescued `areturn` pops this value;
                       a goto_w replacing the original *return carries the real
                       return-typed value into the tail frame, and the verifier
                       requires the incoming type assignable to the declared
                       stack type. It must be the exact return class — Object
                       is too wide for the incoming-frame check, Null too
                       narrow. Registered by registerMethodEntryExtraClasses;
                       array / unresolvable return types fall back to Object. */
                    st.kind = StackTypeSpec::REF;
                    uint16_t retCp = 0;
                    if (c == 'L') {
                        size_t e = h.targetReturnDesc.find(';');
                        if (e != std::string::npos)
                            retCp = lookupExtraClassCpIdx(
                                h, h.targetReturnDesc.substr(1, e - 1));
                    }
                    st.refClassCpIdx = retCp ? retCp : h.objClassCpIdx;
                }
                appendStackPrefixVtis({ st }, spec.stackPrefixVtis, spec.stackPrefixCount);
            }
            if (!rebuildStackMapTrampoline(origSM, { spec }, h,
                                           h.newStackMapBytes))
                return false;
        }
        h.haveNewStackMap = true;
        FVM_LOG("buildHookCM: RETURN goto_w-tramp tailBCI=%zu popBCI=%zu "
                "retDesc=%s origSM=%zuB newSM=%zuB",
                tailBCI, popBCI, h.targetReturnDesc.c_str(),
                origSM.size(), h.newStackMapBytes.size());
    } else if (injectType == "INVOKE" || injectType == "FIELD_GET" ||
               injectType == "FIELD_PUT" || injectType == "NEW") {

        /* ── F1: exception table ── */
        if (methodHasExceptionTable(h.origConstMethodAddr)) {
            setError("head_invoke_field_new_exception_table_unsupported");
            FVM_LOG("buildHookCM: %s skipped %s%s — method has an exception table",
                    injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str());
            return false;
        }

        /* ── read original SMT ── */
        std::vector<uint8_t> origSM;
        {
            int64_t smOff0 = structOffset("ConstMethod", "_stackmap_data");
            if (smOff0 >= 0) {
                uint64_t smArr = 0;
                if (readRemotePointer(proc, h.origConstMethodAddr + (uint64_t)smOff0, &smArr) && smArr) {
                    int64_t aLen  = structOffset("Array<u1>", "_length"); if (aLen  < 0) aLen  = 0;
                    int64_t aData = structOffset("Array<u1>", "_data");   if (aData < 0) aData = 4;
                    int32_t n = 0;
                    if (readRemoteI32(proc, smArr + (uint64_t)aLen, &n) && n > 0 && n < (1<<24)) {
                        origSM.resize((size_t)n);
                        if (!readRemoteMem(proc, smArr + (uint64_t)aData, origSM.data(), (size_t)n))
                            origSM.clear();
                    }
                }
            }
        }

        /* ── CP base for lookups ── */
        uint64_t cpAddr = readOrigCMConstants(h.origConstMethodAddr);
        int64_t cpHdrSize = typeSize("ConstantPool"); if (cpHdrSize < 0) cpHdrSize = 0x138;

        /* ── Step 4: scan matching bcis ── */
        struct Match {
            size_t bciX;
            size_t instrLen;
            size_t coverEndV;
            std::vector<StackTypeSpec> stackPrefix;
            uint16_t oldCPClassIdx; /* for INVOKE receiver / FIELD receiver (old CP idx) */
        };
        std::vector<Match> matches;

        for (size_t i = 0; i < h.origBytecode.size();) {
            uint8_t op = h.origBytecode[i];
            int l = getLen(i); if (l <= 0) { setError("inject_abstract_interp_decode_failed"); return false; }

            bool isCandidate = false;
            if      (injectType == "INVOKE")    isCandidate = (op==0xB6||op==0xB7||op==0xB8||op==0xB9);
            else if (injectType == "FIELD_GET") isCandidate = (op==0xB4||op==0xB2);
            else if (injectType == "FIELD_PUT") isCandidate = (op==0xB5||op==0xB3);
            else if (injectType == "NEW")       isCandidate = (op==0xBB);

            if (!isCandidate || i + 2 >= h.origBytecode.size()) { i += (size_t)l; continue; }

            if (op == 0xBA) { /* invokedynamic — skip */
                i += (size_t)l; continue;
            }

            uint16_t cpIdx = ((uint16_t)h.origBytecode[i+1] << 8) | (uint16_t)h.origBytecode[i+2];
            bool matched = false;
            std::vector<StackTypeSpec> stackPrefix;
            uint16_t oldClassCpIdx = 0;

            if (injectType == "INVOKE") {
                std::string mName, mDesc;
                if (!readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &mName, &mDesc)) {
                    setError("inject_cp_resolve_failed");
                    FVM_LOG("buildHookCM: INVOKE failed to read CP@%u at bci %zu", (unsigned)cpIdx, i);
                    return false;
                }
                if (matchInvokeTarget(injectTargetName, mName, mDesc)) {
                    matched = true;
                    uint16_t ci = 0, ni = 0, di = 0;
                    readCPMethodOrFieldRef(cpAddr, cpHdrSize, cpIdx, &ci, &ni, &di);
                    oldClassCpIdx = ci;
                    bool isStatic = (op == 0xB8);
                    if (!isStatic && ci != 0) {
                        StackTypeSpec s; s.kind = StackTypeSpec::REF; s.refClassCpIdx = ci;
                        stackPrefix.push_back(s);
                    }
                    if (!parseDescParamsToStackSpecs(mDesc, h, stackPrefix)) return false;
                }
            } else if (injectType == "FIELD_GET" || injectType == "FIELD_PUT") {
                std::string fName, fDesc;
                if (!readCPMethodNameDesc(cpAddr, cpHdrSize, cpIdx, &fName, &fDesc)) {
                    setError("inject_cp_resolve_failed"); return false;
                }
                if (matchFieldTarget(injectTargetName, fName, fDesc)) {
                    matched = true;
                    uint16_t ci = 0, ni = 0, di = 0;
                    readCPMethodOrFieldRef(cpAddr, cpHdrSize, cpIdx, &ci, &ni, &di);
                    oldClassCpIdx = ci;
                    bool isStaticAccess = (op == 0xB2 || op == 0xB3);
                    if (!isStaticAccess && ci != 0) {
                        StackTypeSpec s; s.kind = StackTypeSpec::REF; s.refClassCpIdx = ci;
                        stackPrefix.push_back(s);
                    }
                    if (injectType == "FIELD_PUT") {
                        if (!parseSingleDescTypeToStackSpec(fDesc, h, stackPrefix)) return false;
                    }
                }
            } else if (injectType == "NEW") {
                std::string cName;
                if (!readCPClassName(cpAddr, cpHdrSize, cpIdx, &cName)) {
                    setError("inject_cp_resolve_failed"); return false;
                }
                if (matchClassName(injectTargetName, cName)) {
                    matched = true;
                    /* stack prefix is empty: `new` has no inputs */
                }
            }

            if (matched) {
                Match m;
                m.bciX = i;
                m.instrLen = (size_t)l;
                m.coverEndV = coverEnd(i);
                m.stackPrefix = std::move(stackPrefix);
                m.oldCPClassIdx = oldClassCpIdx;
                matches.push_back(m);
            }
            i += (size_t)l;
        }

        /* ── F8: no matches ── */
        if (matches.empty()) {
            setError("inject_target_not_found:" + injectTargetName);
            FVM_LOG("buildHookCM: %s skipped %s%s — no target matches '%s'",
                    injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str(),
                    injectTargetName.c_str());
            return false;
        }

        /* ── F3: outer stack depth at each bci must equal stackPrefix slot count ── */
        for (auto& m : matches) {
            int depth = 0;
            if (!computeStackDepthAtBci(h.origBytecode, origSM, cpAddr, cpHdrSize, m.bciX, &depth)) {
                FVM_LOG("buildHookCM: %s skipped %s%s — abstract interp failed at bci %zu (%s)",
                        injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str(),
                        m.bciX, g_lastError.c_str());
                return false;
            }
            size_t expected = countSlotsOf(m.stackPrefix);
            if ((size_t)depth != expected) {
                setError("inject_outer_stack_nonempty");
                FVM_LOG("buildHookCM: %s skipped %s%s — outer stack non-empty at bci %zu "
                        "(depth=%d, prefix needs %zu slots)",
                        injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str(),
                        m.bciX, depth, expected);
                return false;
            }
        }

        /* ── F2: no original frame inside a cover zone ── */
        if (origSM.size() >= 2) {
            uint16_t fc = smReadU2BE(&origSM[0]);
            size_t pos = 2; uint32_t abs_ = 0;
            for (uint16_t fi = 0; fi < fc; fi++) {
                SmFrameInfo si;
                if (!smParseFrame(origSM, pos, si)) { setError("smt_parse_failed"); return false; }
                abs_ = (fi == 0) ? si.offsetDelta : (abs_ + (uint32_t)si.offsetDelta + 1);
                for (auto& m : matches) {
                    if (abs_ > m.bciX && abs_ < m.coverEndV) {
                        setError("inject_frame_inside_cover_zone");
                        FVM_LOG("buildHookCM: %s skipped %s%s — original frame bci %u inside "
                                "cover zone (%zu,%zu)",
                                injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str(),
                                abs_, m.bciX, m.coverEndV);
                        return false;
                    }
                }
                pos += si.totalLen;
            }
        }

        /* ── F11: needObjectCp but no objClassCpIdx ── */
        if (h.needObjectCp && h.objClassCpIdx == 0) {
            setError("inject_object_cp_idx_not_allocated");
            FVM_LOG("buildHookCM: %s skipped %s%s — Object CP idx not allocated",
                    injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str());
            return false;
        }

        /* ── Step 7: build new bytecode ── */
        /* Pass 1: copy main flow, replacing each match bci with goto_w placeholder. */
        std::vector<size_t> gwFis(matches.size()), gwBcis(matches.size());
        {
            size_t mi = 0;
            for (size_t i = 0; i < h.origBytecode.size();) {
                if (mi < matches.size() && i == matches[mi].bciX) {
                    gwBcis[mi] = newBytecode.size();
                    gwFis[mi]  = emitGW(newBytecode, 0);
                    size_t cEnd = matches[mi].coverEndV;
                    for (size_t b = i + 5; b < cEnd; b++) newBytecode.push_back(0x00);
                    i = cEnd; mi++;
                } else {
                    int l = getLen(i); if (l <= 0) l = 1;
                    for (int j = 0; j < l; j++) newBytecode.push_back(h.origBytecode[i+j]);
                    i += (size_t)l;
                }
            }
        }

        /* Pass 2: append each tail, patch its goto_w. */
        std::vector<size_t> tailStarts(matches.size()), tailPopBcis(matches.size());
        for (size_t t = 0; t < matches.size(); t++) {
            size_t tailBCI = newBytecode.size();
            tailStarts[t] = tailBCI;
            patchGW(newBytecode, gwFis[t], gwBcis[t], tailBCI);

            emitPrologue(newBytecode);
            tailPopBcis[t] = newBytecode.size() - 1; /* the trailing `pop` (0x57) */

            /* Rescued copy of orig[bciX..coverEndV). */
            size_t cEnd = matches[t].coverEndV;
            for (size_t b = matches[t].bciX; b < cEnd; b++)
                newBytecode.push_back(h.origBytecode[b]);

            /* Last instruction of the rescued span — walk it; an unconditional
               terminator means control cannot fall through to a jumpback. */
            uint8_t rescuedLastOp = 0;
            for (size_t b = matches[t].bciX; b < cEnd;) {
                rescuedLastOp = h.origBytecode[b];
                int l = getLen(b); if (l <= 0) l = 1;
                b += (size_t)l;
            }
            bool rescuedEndsTerminator =
                (rescuedLastOp == 0xA7 || rescuedLastOp == 0xC8 ||
                 rescuedLastOp == 0xBF ||
                 (rescuedLastOp >= 0xAC && rescuedLastOp <= 0xB1));

            /* If coverEnd < origSize: goto_w back to coverEnd in main flow —
               unless the rescued span already ends in an unconditional
               terminator, in which case the jumpback is unreachable dead code
               that would itself demand a StackMapTable frame. */
            if (cEnd < h.origBytecode.size() && !rescuedEndsTerminator) {
                size_t gbBCI = newBytecode.size();
                size_t fib = emitGW(newBytecode, 0);
                patchGW(newBytecode, fib, gbBCI, cEnd);
            } else if (cEnd >= h.origBytecode.size()) {
                /* coverEnd == origSize: rescued bytes must end in a terminator,
                   otherwise control falls off the end of the method. */
                if (!rescuedEndsTerminator) {
                    setError("rescued_falls_off_end");
                    FVM_LOG("buildHookCM: %s skipped %s%s — rescued code falls off bytecode end at bci %zu",
                            injectType.c_str(), h.methodName.c_str(), h.paramDesc.c_str(), matches[t].bciX);
                    return false;
                }
            }
        }

        /* ── Step 8: TrampolineFrameSpec per match ── */
        std::vector<TrampolineFrameSpec> tailSpecs(matches.size());
        size_t maxPrefixSlots = 0;
        for (size_t t = 0; t < matches.size(); t++) {
            TrampolineFrameSpec& spec = tailSpecs[t];
            spec.tailBCI = (uint32_t)tailStarts[t];
            spec.popBCI  = (uint32_t)tailPopBcis[t];
            appendStackPrefixVtis(matches[t].stackPrefix, spec.stackPrefixVtis, spec.stackPrefixCount);
            size_t ps = countSlotsOf(matches[t].stackPrefix);
            if (ps > maxPrefixSlots) maxPrefixSlots = ps;
        }
        h.extraMaxStack = (uint16_t)maxPrefixSlots;

        /* ── Step 9: rebuild SMT ──
           JVMS §4.7.4: every bci immediately after a trampoline goto_w
           (replacing the matched bytecode) requires an explicit
           StackMapTable entry. */
        {
            std::vector<uint32_t> postGotoBcis;
            postGotoBcis.reserve(matches.size());
            for (auto& m : matches) postGotoBcis.push_back((uint32_t)(m.bciX + 5));
            std::vector<uint32_t> reservedBcis;
            reservedBcis.reserve(tailSpecs.size() * 2);
            for (auto& s : tailSpecs) {
                reservedBcis.push_back(s.tailBCI);
                reservedBcis.push_back(s.popBCI);
            }
            if (!injectPostGotoStackMapFrames(origSM, postGotoBcis, reservedBcis))
                return false;
        }
        if (!rebuildStackMapTrampoline(origSM, tailSpecs, h,
                                       h.newStackMapBytes)) {
            return false;
        }
        h.haveNewStackMap = true;
        FVM_LOG("buildHookCM: %s goto_w-tramp %zu match(es) %s%s newSM=%zuB",
                injectType.c_str(), matches.size(), h.methodName.c_str(),
                h.paramDesc.c_str(), h.newStackMapBytes.size());
    } else {
        setError("unknown_inject_point_merged:" + injectType); return false;
    }

    /* Build the ConstMethod bytes */
    int64_t constMethodTypeSize = typeSize("ConstMethod");
    if (constMethodTypeSize < 0) { setError("cannot_determine_ConstMethod_size"); return false; }

    /* Read original ConstMethod to get trailing data + header fields */
    size_t origCMSize = (size_t)constMethodTypeSize + h.origBytecode.size();
    int64_t cmSizeOff = structOffset("ConstMethod", "_constMethod_size");
    if (cmSizeOff >= 0) {
        int32_t cmWords = 0;
        readRemoteI32(proc, h.origConstMethodAddr + (uint64_t)cmSizeOff, &cmWords);
        if (cmWords > 0) origCMSize = (size_t)cmWords * 8;
    }
    size_t trailingSize = 0;
    if (origCMSize > (size_t)constMethodTypeSize + h.origBytecode.size())
        trailingSize = origCMSize - (size_t)constMethodTypeSize - h.origBytecode.size();

    std::vector<uint8_t> origCMBytes(origCMSize);
    if (!readRemoteMem(proc, h.origConstMethodAddr, origCMBytes.data(), origCMSize)) {
        setError("cannot_read_full_constmethod"); return false;
    }

    size_t newCMSize = ((size_t)constMethodTypeSize + newBytecode.size() + trailingSize + 7) & ~7;
    h.newCMBytes.assign(newCMSize, 0);
    memcpy(h.newCMBytes.data(), origCMBytes.data(), (size_t)constMethodTypeSize);
    memcpy(h.newCMBytes.data() + constMethodTypeSize, newBytecode.data(), newBytecode.size());
    if (trailingSize > 0) {
        size_t trailingStart = newCMSize - trailingSize;
        memcpy(h.newCMBytes.data() + trailingStart,
               origCMBytes.data() + constMethodTypeSize + h.origBytecode.size(), trailingSize);
    }

    /* Update _constants pointer → newPoolRemoteAddr */
    int64_t cmcOff = structOffset("ConstMethod", "_constants"); if (cmcOff < 0) cmcOff = 8;
    memcpy(h.newCMBytes.data() + cmcOff, &newPoolRemoteAddr, 8);

    /* _stackmap_data handling.
     *
     * HEAD clean-prepend path (h.haveNewStackMap): a consistent StackMapTable
     * was rebuilt in buildHookCM. Leave the field pointing at the original
     * Array<u1> for now; commitKlass allocates a remote Array<u1> for
     * h.newStackMapBytes and repoints _stackmap_data at it. _major_version is
     * NOT downgraded for these classes, so Java 8+ bytecode (e.g. invokestatic
     * to an InterfaceMethodref) stays legal.
     *
     * Legacy goto_w-trampoline path (!haveNewStackMap): the original stackmap
     * references pre-injection BCIs and is inconsistent with the new code. NULL
     * it; buildPoolBytes downgraded _major_version to 50 so the old
     * type-inference verifier (which ignores _stackmap_data) is used. */
    int64_t smOff = structOffset("ConstMethod", "_stackmap_data");
    if (h.haveNewStackMap) {
        if (smOff < 0) {
            setError("stackmap_data_offset_unknown_for_HEAD");
            return false;
        }
        /* pointer patched later by commitKlass once the remote array exists */
    } else if (smOff >= 0) {
        uint64_t origSm = 0;
        memcpy(&origSm, h.newCMBytes.data() + smOff, 8);
        uint64_t nullPtr = 0;
        memcpy(h.newCMBytes.data() + smOff, &nullPtr, 8);
        FVM_LOG("buildCM: cleared _stackmap_data (off=%lld, was 0x%llX)",
                (long long)smOff, (unsigned long long)origSm);
    } else {
        FVM_LOG("buildCM: WARN ConstMethod::_stackmap_data not in VMStructs — "
                "verify may fail on classes with strict stackmap");
    }

    /* Update _code_size */
    int64_t codeSzOff = structOffset("ConstMethod", "_code_size");
    if (codeSzOff >= 0) { uint16_t cs=(uint16_t)newBytecode.size(); memcpy(h.newCMBytes.data()+codeSzOff,&cs,2); }

    /* Update _max_stack */
    int64_t maxStkOff = structOffset("ConstMethod", "_max_stack");
    if (maxStkOff >= 0) {
        uint16_t origMS=0; memcpy(&origMS, h.newCMBytes.data()+maxStkOff, 2);
        uint16_t need=(uint16_t)((h.hasArgCapture&&!h.targetParams.empty()?7:4) + h.extraMaxStack);
        if (origMS < need) memcpy(h.newCMBytes.data()+maxStkOff, &need, 2);
    }

    /* Update _constMethod_size */
    if (cmSizeOff >= 0) { int32_t nw=(int32_t)((newCMSize+7)/8); memcpy(h.newCMBytes.data()+cmSizeOff,&nw,4); }

    return true;
}

/* ============================================================
 * Per-class plan-once-commit-once API
 *
 * commitClassPlan implements the per-class transform (§17.5 Phase A→D):
 *   * unload any existing plan (→ oldCP₀)
 *   * resolve all hooks (replay existing + new candidates)
 *   * single VirtualAllocEx for new CP / RK / Tags / Cache
 *   * one suspend window → snapshot CPCache prefix → leaf-then-root swap → resume
 *   * deopt sweep (unless deferDeopt)
 *
 * Guarantees:
 *   * One CP per class per commit (not layered).
 *   * All methods share the same newCP after commit.
 *   * oldCP never freed (§17.10).
 * ============================================================ */

/* Read a Method*'s declared name (e.g. "tick") and full signature (e.g. "(F)V").
 * Used to replay an existing plan's hooks: when commitClassPlan re-commits an
 * existing patched method, we recover the method's identity from its Method*
 * (which is stable until class unload). */
static bool readMethodNameAndSig(uint64_t methodAddr,
                                 std::string* outName,
                                 std::string* outSig) {
    HANDLE proc = g_target.handle;

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t cm = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &cm) || cm == 0) {
        return false;
    }

    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;

    uint64_t cp = 0;
    if (!readRemotePointer(proc, cm + (uint64_t)cmConstsOff, &cp) || cp == 0) {
        return false;
    }

    int64_t nameIdxOff = structOffset("ConstMethod", "_name_index");
    int64_t sigIdxOff  = structOffset("ConstMethod", "_signature_index");
    if (nameIdxOff < 0 || sigIdxOff < 0) return false;

    int64_t cpHdr = typeSize("ConstantPool");
    if (cpHdr < 0) cpHdr = 0x138;

    uint16_t nameIdx = 0, sigIdx = 0;
    if (!readRemoteU16(proc, cm + (uint64_t)nameIdxOff, &nameIdx)) return false;
    if (!readRemoteU16(proc, cm + (uint64_t)sigIdxOff,  &sigIdx))  return false;

    uint64_t nameSym = 0, sigSym = 0;
    if (!readRemotePointer(proc, cp + (uint64_t)cpHdr + (uint64_t)nameIdx * 8, &nameSym) || nameSym == 0) return false;
    if (!readRemotePointer(proc, cp + (uint64_t)cpHdr + (uint64_t)sigIdx  * 8, &sigSym)  || sigSym  == 0) return false;

    if (!readSymbolBody(proc, nameSym, outName)) return false;
    if (!readSymbolBody(proc, sigSym,  outSig))  return false;
    return true;
}

/* Internal class-level rollback (§17.7). Reverts the plan for klassAddr
 * atomically: suspend → write back InstanceKlass._constants → write back each
 * method's _constMethod and CM._constants → resume → forceDeoptimizeAll.
 * Does not touch g_plans for OTHER klasses. Returns true on success, false
 * if no plan exists for this klass. */
static bool unloadClassPlanForKlass(uint64_t klassAddr) {
    HANDLE proc = g_target.handle;

    /* Drop any not-yet-committed deferred transform for this klass so the retry
       thread will not resurrect it after an unload. Caller holds g_transformLock. */
    bool droppedPending = false;
    for (size_t i = 0; i < g_pendingTransforms.size(); i++) {
        if (g_pendingTransforms[i].klassAddr == klassAddr) {
            g_pendingTransforms.erase(g_pendingTransforms.begin() + (ptrdiff_t)i);
            droppedPending = true;
            break;
        }
    }

    auto it = g_plans.find(klassAddr);
    if (it == g_plans.end()) return droppedPending;

    ClassTransformPlan plan = std::move(it->second);   // move out, keep state coherent
    g_plans.erase(it);

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;
    int64_t codeOff = structOffset("Method", "_code");
    int64_t mdoOff  = structOffset("Method", "_method_data");
    int64_t mctrOff = structOffset("Method", "_method_counters");

    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("UNLOAD_CLASS_PLAN: suspended %zu threads, klass=0x%llX, %zu patched method(s)",
            threadIds.size(), (unsigned long long)klassAddr, plan.patchedMethods.size());

    // Step 1: commit barrier — restore InstanceKlass._constants → oldCPAddr
    int64_t ikConstsOff = structOffset("InstanceKlass", "_constants");
    if (ikConstsOff < 0) {
        // Scan first 256 bytes of InstanceKlass for the last newCP we wrote.
        std::vector<uint8_t> ikHdr(256, 0);
        if (readRemoteMem(proc, klassAddr, ikHdr.data(), 256)) {
            for (int off = 0; off + 8 <= 256; off += 8) {
                uint64_t v = 0; memcpy(&v, ikHdr.data() + off, 8);
                if (v == plan.newCPAddr) { ikConstsOff = off; break; }
            }
        }
    }
    if (ikConstsOff >= 0 && plan.oldCPAddr != 0) {
        writeRemoteMem(proc, klassAddr + (uint64_t)ikConstsOff, &plan.oldCPAddr, 8);
        FVM_LOG("UNLOAD_CLASS_PLAN: IK._constants -> oldCP=0x%llX", (unsigned long long)plan.oldCPAddr);
    }

    // Step 2: restore every class method from backups (covers patched and unpatched).
    for (const MethodCMBackup& b : plan.methodBackups) {
        if (b.methodAddr == 0) continue;
        if (b.origConstMethodAddr != 0) {
            writeRemoteMem(proc, b.methodAddr + (uint64_t)constMethodOff, &b.origConstMethodAddr, 8);
        }
        if (b.origConstMethodAddr != 0 && b.origConstantsPtr != 0) {
            writeRemoteMem(proc, b.origConstMethodAddr + (uint64_t)cmConstsOff, &b.origConstantsPtr, 8);
        }
    }

    // Step 3: clear JIT state on patched methods and restore compilable state.
    int64_t afOffUL = structOffset("Method", "_access_flags");
    for (const PatchedMethodInfo& pmi : plan.patchedMethods) {
        if (pmi.methodAddr == 0) continue;
        uint64_t zero = 0;
        if (codeOff >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)codeOff, &zero, 8);
        if (mdoOff  >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mdoOff,  &zero, 8);
        if (mctrOff >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mctrOff, &zero, 8);
        /* Clear NOT_C1/C2_COMPILABLE bits so the restored method is again JIT-eligible */
        if (afOffUL >= 0) {
            uint32_t af = 0;
            if (readRemoteU32(proc, pmi.methodAddr + (uint64_t)afOffUL, &af)) {
                uint32_t newAF = af & ~(0x80000u | 0x100000u | 0x200000u);
                if (newAF != af)
                    writeRemoteMem(proc, pmi.methodAddr + (uint64_t)afOffUL, &newAF, 4);
            }
        }
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("UNLOAD_CLASS_PLAN: resumed %zu threads", threadIds.size());

    /* §17.10: do NOT VirtualFreeEx newCP/newCPCache/newRK/newCM allocations.
     * Mid-frame execution may still reference them; process exit reclaims. */

    return true;
}

int unloadClassPlan(const char* targetClassName, bool includeSubclasses) {
    HANDLE proc = g_target.handle;
    if (proc == NULL) { setError("agent_not_bootstrapped"); return 0; }

    std::string internal = toInternalName(targetClassName);
    uint64_t klassAddr = 0;
    if (!findInstanceKlassByName(internal, &klassAddr)) {
        setError("class_not_found:" + internal);
        return 0;
    }

    /* Serialize against commitClassPlan and the retry thread — unloadClass
       Plan must not race a deferred commit landing on the same klass. */
    std::lock_guard<std::mutex> _txLock(g_transformLock);

    bool any = unloadClassPlanForKlass(klassAddr);

    if (includeSubclasses) {
        std::vector<uint64_t> subs = findAllSubclasses(klassAddr);
        for (uint64_t s : subs) {
            if (unloadClassPlanForKlass(s)) any = true;
        }
    }

    if (any) {
        forceDeoptimizeAll();
        setError("ok");
        return 1;
    }
    setError("not_transformed:" + internal);
    return 0;
}

/* Commit a single klass: build new CP/RK/Tags/Cache, suspend, swap, resume.
   Assumes no active plan on this klass (caller unloaded first).
   outResults: parallel to hooks, filled for NEW hooks; replay hooks get matched=true. */
static int commitKlass(uint64_t klassAddr,
                              std::vector<HookData>& hooks,
                              const std::vector<bool>& isNew,
                              std::vector<HookOutcome>* outResults) {
    HANDLE proc = g_target.handle;

    FVM_LOG("CLASS_COMMIT klass=0x%llX hooks=%zu", (unsigned long long)klassAddr, hooks.size());

    /* ── Phase A: read TRUE oldCP₀ from IK._constants (plan was just unloaded) ── */
    int64_t ikCOff = structOffset("InstanceKlass", "_constants");
    uint64_t oldCPAddr = 0;
    if (ikCOff >= 0) readRemotePointer(proc, klassAddr + (uint64_t)ikCOff, &oldCPAddr);
    if (oldCPAddr == 0) { setError("cannot_read_IK_constants"); return 0; }

    std::vector<uint8_t> oldPoolBytes;
    uint32_t oldPoolLen = 0;
    size_t   oldPoolByteSize = 0;
    if (!readConstantPool(oldCPAddr, &oldPoolBytes, &oldPoolLen, &oldPoolByteSize)) {
        setError("cannot_read_oldCP"); return 0;
    }

    int64_t cpHeaderSize = typeSize("ConstantPool"); if (cpHeaderSize < 0) cpHeaderSize = 0x138;

    /* RK / Cache from oldCP */
    int64_t rkOff0    = structOffset("ConstantPool", "_resolved_klasses");
    int64_t cacheOff0 = structOffset("ConstantPool", "_cache");
    int64_t tagsOff0  = structOffset("ConstantPool", "_tags");

    uint64_t origRKAddr = 0, origCacheAddr = 0, origTagsAddr = 0;
    if (rkOff0    >= 0) memcpy(&origRKAddr,    oldPoolBytes.data() + rkOff0,    8);
    if (cacheOff0 >= 0) memcpy(&origCacheAddr,  oldPoolBytes.data() + cacheOff0, 8);
    if (tagsOff0  >= 0) memcpy(&origTagsAddr,   oldPoolBytes.data() + tagsOff0,  8);

    /* Defense in depth: only a linked (rewritten) class — one whose CP already
       has a ConstantPoolCache — may be transformed. Unlinked classes are meant
       to be parked in g_pendingTransforms by the caller and re-committed after
       the game links them; reaching here with origCacheAddr == 0 means that
       gate was bypassed. Refuse rather than build a transform HotSpot's link
       pipeline cannot survive. Return 2 = "deferred / not linked". */
    if (origCacheAddr == 0) {
        setError("class_not_linked");
        FVM_LOG("CLASS_COMMIT: klass=0x%llX has no ConstantPoolCache (not linked) "
                "— refusing transform", (unsigned long long)klassAddr);
        return 2;
    }

    int32_t origRKLen = 0;
    if (origRKAddr) {
        int64_t rkLenOff = structOffset("Array<Klass*>","_length"); if(rkLenOff<0)rkLenOff=0;
        readRemoteI32(proc, origRKAddr + (uint64_t)rkLenOff, &origRKLen);
    }

    int64_t cacheHdrSize   = typeSize("ConstantPoolCache");   if (cacheHdrSize   < 0) cacheHdrSize   = 16;
    int64_t cacheEntrySize = typeSize("ConstantPoolCacheEntry"); if (cacheEntrySize < 0) cacheEntrySize = 32;
    int64_t cacheLenOff    = structOffset("ConstantPoolCache", "_length"); if (cacheLenOff < 0) cacheLenOff = 0;
    int64_t cacheCPOff     = structOffset("ConstantPoolCache", "_constant_pool"); if (cacheCPOff < 0) cacheCPOff = 8;
    int32_t origCacheLen   = 0;
    if (origCacheAddr) readRemoteI32(proc, origCacheAddr + (uint64_t)cacheLenOff, &origCacheLen);

    /* ── Assign merged layout ── */
    assignPoolLayout((uint32_t)oldPoolLen, origRKLen, origCacheLen, hooks);

    uint32_t totalNewCPEntries = 0;
    int32_t  totalNewRKEntries = 0;
    int      totalNewCacheEntries = 0;
    for (auto& h : hooks) {
        totalNewCPEntries    += h.numCPEntries();
        totalNewRKEntries    += (int32_t)h.numRKEntries();
        totalNewCacheEntries += (int)h.numCacheEntries();
    }
    uint32_t newPoolLen   = oldPoolLen + totalNewCPEntries;
    int32_t  newRKLen     = origRKLen  + totalNewRKEntries;
    int      newCacheLen  = origCacheLen + totalNewCacheEntries;

    /* ── Phase B: Remote allocations (no suspend yet) ── */
    size_t newPoolByteSize = oldPoolByteSize + totalNewCPEntries * 8;
    uint64_t newPoolAddr = (uint64_t)VirtualAllocEx(proc, NULL, newPoolByteSize,
                                                     MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!newPoolAddr) { setError("VirtualAllocEx_newCP_failed"); return 0; }

    /* RK */
    int64_t rkLenOff2  = structOffset("Array<Klass*>","_length"); if(rkLenOff2<0)rkLenOff2=0;
    int64_t rkDataOff2 = structOffset("Array<Klass*>","_data");   if(rkDataOff2<0)rkDataOff2=8;
    size_t newRKSize = ((size_t)rkDataOff2 + (size_t)newRKLen*8 + 7) & ~7;
    uint64_t newRKAddr = (uint64_t)VirtualAllocEx(proc, NULL, newRKSize,
                                                   MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!newRKAddr) { VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE); setError("VirtualAllocEx_mergedRK_failed"); return 0; }

    /* Tags */
    int64_t tagLenOff2  = structOffset("Array<u1>","_length");  if(tagLenOff2<0)tagLenOff2=0;
    int64_t tagDataOff2 = structOffset("Array<u1>","_data");    if(tagDataOff2<0)tagDataOff2=4;
    size_t newTagsSize = ((size_t)tagDataOff2 + (size_t)newPoolLen + 7) & ~7;
    uint64_t newTagsAddr = (uint64_t)VirtualAllocEx(proc, NULL, newTagsSize,
                                                     MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!newTagsAddr) {
        VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE);
        VirtualFreeEx(proc,(LPVOID)newRKAddr,0,MEM_RELEASE);
        setError("VirtualAllocEx_mergedTags_failed"); return 0;
    }

    /* CPCache (sized, prefix snapshot deferred to post-suspend). */
    size_t   newCacheSize = (size_t)cacheHdrSize + (size_t)newCacheLen * (size_t)cacheEntrySize;
    uint64_t newCacheAddr = (uint64_t)VirtualAllocEx(proc, NULL, newCacheSize,
                                                      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!newCacheAddr) {
        VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE);
        VirtualFreeEx(proc,(LPVOID)newRKAddr,0,MEM_RELEASE);
        VirtualFreeEx(proc,(LPVOID)newTagsAddr,0,MEM_RELEASE);
        setError("VirtualAllocEx_mergedCache_failed"); return 0;
    }

    /* Allocate each hook's newCM */
    for (auto& h : hooks) {
        if (!buildHookCM(h, newPoolAddr)) {
            FVM_LOG("CLASS_COMMIT: buildHookCM FAILED for %s%s: %s",
                    h.methodName.c_str(), h.paramDesc.c_str(), g_lastError.c_str());
            /* free already-allocated CMs */
            for (auto& h2 : hooks) if (h2.newCMRemoteAddr) VirtualFreeEx(proc,(LPVOID)h2.newCMRemoteAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newRKAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newTagsAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newCacheAddr,0,MEM_RELEASE);
            return 0;
        }
        h.newCMRemoteAddr = (uint64_t)VirtualAllocEx(proc, NULL, h.newCMBytes.size(),
                                                       MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!h.newCMRemoteAddr) {
            for (auto& h2 : hooks) if (h2.newCMRemoteAddr) VirtualFreeEx(proc,(LPVOID)h2.newCMRemoteAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newRKAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newTagsAddr,0,MEM_RELEASE);
            VirtualFreeEx(proc,(LPVOID)newCacheAddr,0,MEM_RELEASE);
            setError("VirtualAllocEx_newCM_failed"); return 0;
        }
    }

    /* Build merged data buffers */
    std::vector<uint8_t> newPoolBytes = buildPoolBytes(
        oldPoolBytes, oldPoolLen, oldPoolByteSize, cpHeaderSize,
        hooks, newPoolLen, newRKAddr, newCacheAddr, newTagsAddr);

    std::vector<uint8_t> newTagsBytes = buildPoolTagsBytes(proc, origTagsAddr, newPoolLen, hooks);

    std::vector<uint8_t> newRKBytes = buildPoolRKBytes(proc, origRKAddr, origRKLen, newRKLen);
    /* Fill RK data entries for each hook */
    {
        uint64_t* rkData = (uint64_t*)(newRKBytes.data() + rkDataOff2);
        for (auto& h : hooks) {
            rkData[h.hookClassRKIdx] = h.hookKlassAddr;
            rkData[h.cbClassRKIdx]   = h.cbKlassAddr;
            if (h.wantObjectCpEntry()) rkData[h.objectClassRKIdx] = h.objectKlassAddr;
            if (h.needsUnbox) rkData[h.unboxClassRKIdx] = h.unboxKlassAddr;
            for (auto& ex : h.extraClasses) rkData[ex.rkIdx] = ex.klassAddr;
        }
    }

    /* CPCache: sized to newCacheSize, prefix filled post-suspend. */
    std::vector<uint8_t> newCacheBytes(newCacheSize, 0);
    /* Pre-fill the tail entries (new hooks) */
    fillPoolCacheTail(newCacheBytes, cacheHdrSize, cacheEntrySize, hooks);

    /* Allocate + write a remote Array<u1> for each rebuilt StackMapTable
       (HEAD clean-prepend) and repoint ConstMethod::_stackmap_data at it.
       Layout matches the tags array: { int32 _length; u1 _data[_length] }.
       Like newCP / newCM, these arrays are intentionally never freed — an
       in-flight frame may still reference the patched ConstMethod. */
    {
        int64_t smOff   = structOffset("ConstMethod", "_stackmap_data");
        int64_t aLenOff  = structOffset("Array<u1>", "_length"); if (aLenOff  < 0) aLenOff  = 0;
        int64_t aDataOff = structOffset("Array<u1>", "_data");   if (aDataOff < 0) aDataOff = 4;
        for (auto& h : hooks) {
            if (!h.haveNewStackMap) continue;
            size_t dataLen = h.newStackMapBytes.size();
            size_t arrSize = ((size_t)aDataOff + dataLen + 7) & ~(size_t)7;
            std::vector<uint8_t> arr(arrSize, 0);
            int32_t len32 = (int32_t)dataLen;
            memcpy(arr.data() + aLenOff, &len32, 4);
            memcpy(arr.data() + aDataOff, h.newStackMapBytes.data(), dataLen);

            h.newStackMapRemoteAddr = (uint64_t)VirtualAllocEx(
                proc, NULL, arrSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!h.newStackMapRemoteAddr) {
                for (auto& h2 : hooks) if (h2.newCMRemoteAddr) VirtualFreeEx(proc,(LPVOID)h2.newCMRemoteAddr,0,MEM_RELEASE);
                VirtualFreeEx(proc,(LPVOID)newPoolAddr,0,MEM_RELEASE);
                VirtualFreeEx(proc,(LPVOID)newRKAddr,0,MEM_RELEASE);
                VirtualFreeEx(proc,(LPVOID)newTagsAddr,0,MEM_RELEASE);
                VirtualFreeEx(proc,(LPVOID)newCacheAddr,0,MEM_RELEASE);
                setError("VirtualAllocEx_stackmap_failed"); return 0;
            }
            writeRemoteMem(proc, h.newStackMapRemoteAddr, arr.data(), arr.size());
            memcpy(h.newCMBytes.data() + smOff, &h.newStackMapRemoteAddr, 8);
            FVM_LOG("CLASS_COMMIT: stackmap_data → 0x%llX (%zuB) for %s%s",
                    (unsigned long long)h.newStackMapRemoteAddr, dataLen,
                    h.methodName.c_str(), h.paramDesc.c_str());
        }
    }

    /* Write non-cache data to remote (safe before suspend) */
    writeRemoteMem(proc, newPoolAddr,  newPoolBytes.data(),  newPoolBytes.size());
    writeRemoteMem(proc, newRKAddr,    newRKBytes.data(),    newRKBytes.size());
    writeRemoteMem(proc, newTagsAddr,  newTagsBytes.data(),  newTagsBytes.size());
    for (auto& h : hooks) {
        writeRemoteMem(proc, h.newCMRemoteAddr, h.newCMBytes.data(), h.newCMBytes.size());
    }

    /* ── Read all class methods for the per-class CM._constants sweep ── */
    std::vector<uint64_t> allClassMethods;
    {
        int64_t mOff = structOffset("InstanceKlass", "_methods");
        if (mOff >= 0) {
            uint64_t mArr = 0; readRemotePointer(proc, klassAddr + (uint64_t)mOff, &mArr);
            if (mArr) {
                int64_t aLenOff = structOffset("Array<int>","_length"); if(aLenOff<0)aLenOff=0;
                int64_t aDataOff= structOffset("Array<int>","_data");   if(aDataOff<0)aDataOff=8;
                int32_t mc=0; readRemoteI32(proc, mArr+(uint64_t)aLenOff, &mc);
                if (mc>0&&mc<10000) { allClassMethods.resize(mc); readRemoteMem(proc, mArr+(uint64_t)aDataOff, allClassMethods.data(), mc*8); }
            }
        }
    }

    /* ── Phase C: single suspend → snapshot cache prefix → write cache → swap → resume ── */
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("CLASS_COMMIT: suspended %zu threads", threadIds.size());

    /* Post-suspend: snapshot origCache prefix (race-free). origCacheAddr is
       always non-NULL here — the guard at the top refused unlinked classes. */
    {
        size_t origCacheSize = (size_t)cacheHdrSize + origCacheLen * (size_t)cacheEntrySize;
        std::vector<uint8_t> origCacheSnap(origCacheSize);
        if (readRemoteMem(proc, origCacheAddr, origCacheSnap.data(), origCacheSize)) {
            memcpy(newCacheBytes.data(), origCacheSnap.data(), origCacheSize);
        }
        /* Restore overwritten header fields */
        memcpy(newCacheBytes.data() + cacheLenOff, &newCacheLen, 4);
        if (cacheCPOff >= 0) memcpy(newCacheBytes.data() + cacheCPOff, &newPoolAddr, 8);
        /* Re-fill tail (prefix copy may have stomped them if origCacheSize > cacheHdrSize) */
        fillPoolCacheTail(newCacheBytes, cacheHdrSize, cacheEntrySize, hooks);
        writeRemoteMem(proc, newCacheAddr, newCacheBytes.data(), newCacheBytes.size());
    }

    /* Capture plan backups (first patch on this klass) */
    {
        ClassTransformPlan& plan = g_plans[klassAddr];
        plan.className.clear(); /* recovered from klass name if needed */
        plan.klassAddr = klassAddr;
        plan.oldCPAddr = oldCPAddr;
        plan.newCPAddr      = newPoolAddr;
        plan.newCPCacheAddr = newCacheAddr;
        plan.newRKAddr      = newRKAddr;
        plan.methodBackups.clear();
        for (uint64_t mAddr : allClassMethods) {
            if (!mAddr) continue;
            MethodCMBackup b; b.methodAddr = mAddr;
            int64_t cmOff2 = structOffset("Method","_constMethod"); if(cmOff2<0)cmOff2=8;
            int64_t cmcOff2= structOffset("ConstMethod","_constants"); if(cmcOff2<0)cmcOff2=8;
            readRemotePointer(proc, mAddr+(uint64_t)cmOff2, &b.origConstMethodAddr);
            if (b.origConstMethodAddr) readRemotePointer(proc, b.origConstMethodAddr+(uint64_t)cmcOff2, &b.origConstantsPtr);
            plan.methodBackups.push_back(b);
        }
    }

    /* §17.5 Phase C step 7 — leaf-then-root swap */
    int64_t constMethodOff2= structOffset("Method","_constMethod");   if(constMethodOff2<0)constMethodOff2=8;
    int64_t cmConstsOff2   = structOffset("ConstMethod","_constants"); if(cmConstsOff2<0)cmConstsOff2=8;
    int64_t codeOff2       = structOffset("Method","_code");

    /* Build set of patched method addrs for quick lookup */
    std::unordered_set<uint64_t> patchedAddrs;
    for (auto& h : hooks) patchedAddrs.insert(h.methodAddr);

    /* Step 7a: update all unpatched methods' CM._constants → newPoolAddr */
    for (uint64_t mAddr : allClassMethods) {
        if (!mAddr || patchedAddrs.count(mAddr)) continue;
        uint64_t cm=0; if(!readRemotePointer(proc, mAddr+(uint64_t)constMethodOff2, &cm)||!cm) continue;
        writeRemoteMem(proc, cm+(uint64_t)cmConstsOff2, &newPoolAddr, 8);
    }

    /* Step 7b: swap each patched method → newCM, clear JIT state */
    for (auto& h : hooks) {
        writeRemoteMem(proc, h.methodAddr+(uint64_t)constMethodOff2, &h.newCMRemoteAddr, 8);
        if (codeOff2>=0) { uint64_t z=0; writeRemoteMem(proc, h.methodAddr+(uint64_t)codeOff2, &z, 8); }
        clearMethodProfilingState(h.methodAddr, /*setDontInline=*/true, "CLASS_COMMIT");
    }

    /* Step 7c: commit barrier — IK._constants → newPoolAddr */
    if (ikCOff >= 0) writeRemoteMem(proc, klassAddr+(uint64_t)ikCOff, &newPoolAddr, 8);

    /* Update plan's patchedMethods */
    {
        ClassTransformPlan& plan = g_plans[klassAddr];
        plan.patchedMethods.clear();
        for (auto& h : hooks) {
            PatchedMethodInfo pmi;
            pmi.methodAddr = h.methodAddr;
            pmi.newCMAddr  = h.newCMRemoteAddr;
            pmi.hook = HookSpec{ h.hookClass, h.hookMethod, h.hookDesc, h.injectAt };
            plan.patchedMethods.push_back(pmi);
        }
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("CLASS_COMMIT: resumed %zu threads, newCP=0x%llX hooks=%zu",
            threadIds.size(), (unsigned long long)newPoolAddr, hooks.size());
    return 1;
}

/* True once the class has a ConstantPoolCache — i.e. HotSpot has linked and
   rewritten it. An unlinked class cannot be transformed yet (commitKlass's
   own guard refuses it); callers park such classes in g_pendingTransforms. */
static bool klassIsLinked(uint64_t kAddr) {
    HANDLE proc = g_target.handle;
    int64_t ikCOff = structOffset("InstanceKlass", "_constants");
    if (ikCOff < 0) return true;       /* unknown layout — assume linked */
    uint64_t cpAddr = 0;
    if (!readRemotePointer(proc, kAddr + (uint64_t)ikCOff, &cpAddr) || !cpAddr)
        return true;                   /* cannot tell — let commitKlass decide */
    int64_t cacheOff = structOffset("ConstantPool", "_cache");
    if (cacheOff < 0) return true;
    uint64_t cacheAddr = 0;
    readRemotePointer(proc, cpAddr + (uint64_t)cacheOff, &cacheAddr);
    return cacheAddr != 0;
}

/* Start the deferred-transform retry thread once, lazily. Caller holds
   g_transformLock. */
static void maybeStartDeferredRetryThread();

/* Park an unlinked klass's hook specs for the retry thread. Replaces any
   existing pending entry for the same klass. Caller holds g_transformLock. */
static void deferKlassTransform(uint64_t kAddr,
                                 const std::vector<HookSpecExtended>& specs) {
    for (auto& p : g_pendingTransforms) {
        if (p.klassAddr == kAddr) { p.specs = specs; return; }
    }
    g_pendingTransforms.push_back({ kAddr, specs });
    FVM_LOG("CLASS_PLAN: klass=0x%llX not linked yet — deferred (%zu spec(s), "
            "%zu pending total)", (unsigned long long)kAddr, specs.size(),
            g_pendingTransforms.size());
    maybeStartDeferredRetryThread();
}

/* Resolve every hook spec against kAddr and commit them with one merged newCP.
   Merges with the klass's existing plan (replayed) if one is present.
   Returns: 1 = committed, 0 = failed, 2 = deferred (class not linked).
   Caller holds g_transformLock and has suspended target threads. */
static int resolveAndCommitKlass(uint64_t kAddr,
                                  const std::vector<HookSpecExtended>& newSpecs,
                                  std::vector<HookOutcome>* results) {
    /* Gate: an unlinked class has no ConstantPoolCache. Transforming it would
       hand HotSpot's link/rewrite pipeline a synthetic CP it cannot survive
       (see commitKlass guard). Park the specs; the retry thread re-commits
       once the game links the class. A lightweight method lookup still fills
       `results` so subclass propagation sees which hooks matched. */
    if (!klassIsLinked(kAddr)) {
        if (results) {
            results->resize(newSpecs.size());
            for (size_t i = 0; i < newSpecs.size(); i++) {
                HookOutcome& out = (*results)[i];
                const HookSpecExtended& spec = newSpecs[i];
                out.reason = spec.candidates.empty() ? "no_candidates" : "method_not_found";
                for (auto& cand : spec.candidates) {
                    uint64_t mAddr = 0;
                    if (findMethodInKlass(kAddr, cand.methodName.c_str(),
                                          cand.paramDesc.c_str(), &mAddr)) {
                        out.matched    = true;
                        out.methodName = cand.methodName;
                        out.paramDesc  = cand.paramDesc;
                        out.methodAddr = mAddr;
                        break;
                    }
                }
            }
        }
        deferKlassTransform(kAddr, newSpecs);
        setError("ok");
        return 2;
    }

    /* Stash existing plan (if any) and unload it → back to oldCP₀ */
    std::vector<PatchedMethodInfo> existing;
    {
        auto it = g_plans.find(kAddr);
        if (it != g_plans.end()) existing = it->second.patchedMethods;
    }
    if (!existing.empty()) {
        unloadClassPlanForKlass(kAddr);  /* restores IK._constants → oldCP₀ */
        FVM_LOG("CLASS_PLAN: unloaded existing plan (%zu hooks) for klass=0x%llX",
                existing.size(), (unsigned long long)kAddr);
    }

    /* Phase A: resolve all hooks (existing replays + new) */
    std::vector<HookData> hooks;
    std::vector<bool>     isNew;

    /* 1. Replay existing hooks */
    for (auto& pmi : existing) {
        std::string mName, mSig;
        if (!readMethodNameAndSig(pmi.methodAddr, &mName, &mSig)) {
            FVM_LOG("CLASS_PLAN: cannot read name/sig for Method*=0x%llX, skipping",
                    (unsigned long long)pmi.methodAddr);
            continue;
        }
        HookSpecExtended ext;
        ext.hookClass=pmi.hook.hookClass; ext.hookMethod=pmi.hook.hookMethod;
        ext.hookDesc=pmi.hook.hookDesc;   ext.injectAt=pmi.hook.injectAt;
        ext.candidates.push_back({mName, mSig});

        HookData hd;
        if (resolveHookData(kAddr, mName, mSig, ext, hd)) {
            hooks.push_back(std::move(hd));
            isNew.push_back(false);
        } else {
            FVM_LOG("CLASS_PLAN: replay resolve FAILED %s%s: %s",
                    mName.c_str(), mSig.c_str(), g_lastError.c_str());
        }
    }

    /* 2. Resolve new hooks (try candidates) */
    if (results) results->resize(newSpecs.size());
    HookOutcome _dummyOutcome;
    for (size_t i = 0; i < newSpecs.size(); i++) {
        const HookSpecExtended& spec = newSpecs[i];
        HookOutcome& out = results ? (*results)[i] : _dummyOutcome;
        out = HookOutcome{};
        out.reason = spec.candidates.empty() ? "no_candidates" : "method_not_found";
        bool matched = false;
        for (auto& cand : spec.candidates) {
            HookData hd;
            if (resolveHookData(kAddr, cand.methodName, cand.paramDesc, spec, hd)) {
                out.matched    = true;
                out.methodName = cand.methodName;
                out.paramDesc  = cand.paramDesc;
                out.methodAddr = hd.methodAddr;
                hooks.push_back(std::move(hd));
                isNew.push_back(true);
                matched = true;
                break;
            }
            if (!g_lastError.empty()) out.reason = g_lastError;
        }
        if (!matched) {
            FVM_LOG("CLASS_PLAN: new hook[%zu] NO MATCH (%s.%s%s) reason=%s",
                    i, spec.hookClass.c_str(), spec.hookMethod.c_str(),
                    spec.hookDesc.c_str(), out.reason.c_str());
        }
    }

    if (hooks.empty()) { setError("no_hooks_resolved"); return 0; }

    /* Phase B+C: merged alloc + single suspend/write/swap. commitKlass returns
       2 if the class lost its cache between the gate check and here (a link
       race); park it in that case. */
    int crc = commitKlass(kAddr, hooks, isNew, nullptr);
    if (crc == 2) {
        deferKlassTransform(kAddr, newSpecs);
        setError("ok");
        return 2;
    }
    return crc == 1 ? 1 : 0;
}

/* Retry-thread body: periodically re-attempt every parked transform whose
   class has since been linked by the game. */
static DWORD WINAPI deferredRetryThread(LPVOID) {
    for (;;) {
        Sleep(250);
        if (g_target.handle == NULL) continue;

        std::lock_guard<std::mutex> _txLock(g_transformLock);
        if (g_pendingTransforms.empty()) continue;

        /* Collect the klasses that are now linked and ready to commit. */
        std::vector<PendingTransform> ready;
        for (size_t i = 0; i < g_pendingTransforms.size();) {
            if (klassIsLinked(g_pendingTransforms[i].klassAddr)) {
                ready.push_back(std::move(g_pendingTransforms[i]));
                g_pendingTransforms.erase(g_pendingTransforms.begin() + (ptrdiff_t)i);
            } else {
                i++;
            }
        }
        if (ready.empty()) continue;

        std::vector<DWORD> threadIds;
        suspendTargetThreads(g_target.pid, threadIds);
        for (auto& pt : ready) {
            FVM_LOG("DEFERRED_RETRY: klass=0x%llX now linked — committing %zu spec(s)",
                    (unsigned long long)pt.klassAddr, pt.specs.size());
            /* resolveAndCommitKlass re-parks the entry if it is somehow still
               unlinked (link race) — harmless, retried next tick. */
            resolveAndCommitKlass(pt.klassAddr, pt.specs, nullptr);
        }
        resumeTargetThreads(threadIds);
        forceDeoptimizeAll();
    }
    return 0;
}

/* Start the retry thread once, lazily, the first time a transform is deferred.
   Caller holds g_transformLock. */
static void maybeStartDeferredRetryThread() {
    if (g_retryThreadStarted) return;
    g_retryThreadStarted = true;
    HANDLE th = CreateThread(NULL, 0, deferredRetryThread, NULL, 0, NULL);
    if (th) {
        CloseHandle(th);
        FVM_LOG("CLASS_PLAN: deferred-transform retry thread started");
    } else {
        FVM_LOG("CLASS_PLAN: WARN failed to start deferred-transform retry thread");
    }
}

int commitClassPlan(const char* targetClassName,
                    const std::vector<HookSpecExtended>& additionalHooks,
                    bool includeSubclasses,
                    bool deferDeopt,
                    std::vector<HookOutcome>* outResults) {
    HANDLE proc = g_target.handle;
    if (proc == NULL) { setError("agent_not_bootstrapped"); return 0; }

    std::string internal = toInternalName(targetClassName);
    uint64_t klassAddr = 0;
    if (!findInstanceKlassByName(internal, &klassAddr)) {
        if (outResults) {
            outResults->resize(additionalHooks.size());
            for (auto& r : *outResults) { r.matched = false; r.reason = "class_not_found"; }
        }
        setError("class_not_found:" + internal);
        return 0;
    }

    FVM_LOG("=== CLASS_PLAN BEGIN (Stage3.1): %s (klass=0x%llX +%zu hooks subs=%d) ===",
            internal.c_str(), (unsigned long long)klassAddr,
            additionalHooks.size(), (int)includeSubclasses);

    if (outResults) outResults->resize(additionalHooks.size());

    std::lock_guard<std::mutex> _txLock(g_transformLock);

    /* Suspend target threads for the whole batch (Phase A includes no I/O that needs them
       but Phase B/C does; outer suspend keeps threads frozen across all klass commits) */
    std::vector<DWORD> outerThreadIds;
    suspendTargetThreads(g_target.pid, outerThreadIds);
    FVM_LOG("CLASS_PLAN: outer suspended %zu threads", outerThreadIds.size());

    /* rc: 1 = committed, 0 = failed, 2 = deferred (class not linked yet). */
    int rc = resolveAndCommitKlass(klassAddr, additionalHooks, outResults);

    /* A deferred top-level class still counts as accepted — outResults already
       carries the per-hook match info (resolveAndCommitKlass fills it before
       deferring), and subclass propagation below needs it. */
    if (includeSubclasses && (rc == 1 || rc == 2)) {
        std::vector<uint64_t> subs = findAllSubclasses(klassAddr);
        for (uint64_t s : subs) {
            /* For subclasses: propagate matching hooks (those matched on parent) */
            std::vector<HookSpecExtended> subHooks;
            if (outResults) {
                for (size_t i = 0; i < additionalHooks.size(); i++) {
                    if (i < outResults->size() && (*outResults)[i].matched) {
                        HookSpecExtended sub = additionalHooks[i];
                        sub.candidates = {{ (*outResults)[i].methodName, (*outResults)[i].paramDesc }};
                        subHooks.push_back(sub);
                    }
                }
            }
            if (!subHooks.empty()) {
                uint64_t subMethodCheck = 0;
                if (findMethodInKlass(s, subHooks[0].candidates[0].methodName.c_str(),
                                       subHooks[0].candidates[0].paramDesc.c_str(), &subMethodCheck)) {
                    resolveAndCommitKlass(s, subHooks, nullptr);
                }
            }
        }
    }

    resumeTargetThreads(outerThreadIds);
    FVM_LOG("CLASS_PLAN: outer resumed %zu threads", outerThreadIds.size());

    if (!deferDeopt) {
        FVM_LOG("CLASS_PLAN: running deopt sweep");
        forceDeoptimizeAll();
    }

    /* rc == 2: the class is not linked yet; its hooks are parked and the retry
       thread will commit them once the game links it. Report success — the
       hooks are accepted, outResults already carries per-hook match info. */
    bool accepted = (rc == 1 || rc == 2);
    FVM_LOG("=== CLASS_PLAN END: %s rc=%d accepted=%d ===",
            internal.c_str(), rc, (int)accepted);
    if (accepted) setError("ok");
    return accepted ? 1 : 0;
}

/* ============================================================
 * Exports for the per-class plan API
 * ============================================================ */

namespace {

/* Tiny single-pass JSON helpers used to decode the hooksJson array passed in
 * via the DLL ABI. JSON is well-formed (emitted by the Agent) so we can rely
 * on simple "key":"value" / "key":bool searches without a real parser. */

static std::string jsonExtractString(const std::string& obj, const std::string& key) {
    std::string needle = std::string("\"") + key + "\":\"";
    size_t i = obj.find(needle);
    if (i == std::string::npos) return std::string();
    size_t start = i + needle.size();
    size_t end = obj.find('"', start);
    if (end == std::string::npos) return std::string();
    return obj.substr(start, end - start);
}

static bool jsonExtractBool(const std::string& obj, const std::string& key, bool fallback) {
    std::string needle = std::string("\"") + key + "\":";
    size_t i = obj.find(needle);
    if (i == std::string::npos) return fallback;
    size_t p = i + needle.size();
    while (p < obj.size() && (obj[p] == ' ' || obj[p] == '\t')) p++;
    if (obj.compare(p, 4, "true")  == 0) return true;
    if (obj.compare(p, 5, "false") == 0) return false;
    return fallback;
}

/* Find the next outer JSON object [start..end) inside arr, returning its bounds
 * in [outStart, outEnd]. Returns false when no more objects. */
static bool jsonNextObject(const std::string& arr, size_t pos,
                           size_t* outStart, size_t* outEnd) {
    while (pos < arr.size() && arr[pos] != '{') pos++;
    if (pos >= arr.size()) return false;
    int depth = 0;
    size_t s = pos;
    for (; pos < arr.size(); pos++) {
        char c = arr[pos];
        if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) { *outStart = s; *outEnd = pos; return true; }
        }
    }
    return false;
}

static std::string jsonExtractArrayInner(const std::string& obj, const std::string& key) {
    std::string needle = std::string("\"") + key + "\":";
    size_t i = obj.find(needle);
    if (i == std::string::npos) return std::string();
    size_t bracket = obj.find('[', i);
    if (bracket == std::string::npos) return std::string();
    int depth = 0;
    for (size_t p = bracket; p < obj.size(); p++) {
        if (obj[p] == '[') depth++;
        else if (obj[p] == ']') {
            depth--;
            if (depth == 0) return obj.substr(bracket + 1, p - bracket - 1);
        }
    }
    return std::string();
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)(unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // namespace

/* Public DLL export: per-class plan-once-commit-once.
 *
 * hooksJson format:
 *   [{"hookClass":"...","hookMethod":"...","hookDesc":"...",
 *     "injectAt":"...",
 *     "candidates":[{"methodName":"...","paramDesc":"..."}, ...]}, ...]
 *
 * resultJsonBuf receives a JSON array (same length / order as input):
 *   [{"matched":true,"methodName":"...","paramDesc":"..."}, ...]
 * or {"matched":false,"reason":"..."} per entry.
 *
 * Returns 1 on commit success, 0 on commit failure (e.g. class not found). */
extern "C" __declspec(dllexport) int forgevm_forge_class_plan(
    const char* targetClassName,
    const char* hooksJson,
    int includeSubclasses,
    int deferDeopt,
    char* resultJsonBuf,
    int resultJsonBufSize) {

    if (resultJsonBuf != nullptr && resultJsonBufSize > 0) {
        resultJsonBuf[0] = '\0';
    }
    if (targetClassName == nullptr || hooksJson == nullptr) {
        setError("missing_params");
        return 0;
    }

    // Decode hooksJson.
    std::string arr(hooksJson);
    std::vector<HookSpecExtended> hooks;
    {
        size_t pos = 0;
        size_t s, e;
        while (jsonNextObject(arr, pos, &s, &e)) {
            std::string obj = arr.substr(s, e - s + 1);
            HookSpecExtended h;
            h.hookClass  = jsonExtractString(obj, "hookClass");
            h.hookMethod = jsonExtractString(obj, "hookMethod");
            h.hookDesc   = jsonExtractString(obj, "hookDesc");
            h.injectAt   = jsonExtractString(obj, "injectAt");
            std::string injectTarget = jsonExtractString(obj, "injectTarget");
            if (!injectTarget.empty()) {
                h.injectAt += ":";
                h.injectAt += injectTarget;
            }
            std::string candArr = jsonExtractArrayInner(obj, "candidates");
            size_t cpos = 0, cs, ce;
            while (jsonNextObject(candArr, cpos, &cs, &ce)) {
                std::string cobj = candArr.substr(cs, ce - cs + 1);
                HookCandidate c;
                c.methodName = jsonExtractString(cobj, "methodName");
                c.paramDesc  = jsonExtractString(cobj, "paramDesc");
                h.candidates.push_back(std::move(c));
                cpos = ce + 1;
            }
            hooks.push_back(std::move(h));
            pos = e + 1;
        }
    }

    std::vector<HookOutcome> outcomes;
    int rc = commitClassPlan(targetClassName, hooks,
                             includeSubclasses != 0,
                             deferDeopt != 0,
                             &outcomes);

    // Serialize outcomes.
    if (resultJsonBuf != nullptr && resultJsonBufSize > 0) {
        std::string out;
        out += '[';
        for (size_t i = 0; i < outcomes.size(); i++) {
            if (i > 0) out += ',';
            const HookOutcome& o = outcomes[i];
            out += '{';
            if (o.matched) {
                out += "\"matched\":true,\"methodName\":\"";
                out += jsonEscape(o.methodName);
                out += "\",\"paramDesc\":\"";
                out += jsonEscape(o.paramDesc);
                out += "\"";
            } else {
                out += "\"matched\":false,\"reason\":\"";
                out += jsonEscape(o.reason);
                out += "\"";
            }
            out += '}';
        }
        out += ']';
        if ((int)out.size() + 1 <= resultJsonBufSize) {
            memcpy(resultJsonBuf, out.data(), out.size() + 1);
        } else {
            // Truncate gracefully — caller should provide a generous buffer.
            int n = resultJsonBufSize - 1;
            if (n > 0) memcpy(resultJsonBuf, out.data(), (size_t)n);
            resultJsonBuf[resultJsonBufSize - 1] = '\0';
        }
    }
    return rc;
}

extern "C" __declspec(dllexport) int forgevm_forge_class_unload(
    const char* targetClassName,
    int includeSubclasses) {
    return unloadClassPlan(targetClassName, includeSubclasses != 0);
}
