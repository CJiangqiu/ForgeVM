#include "forgevm_internal.h"

#include <tlhelp32.h>
#include <algorithm>

// ============================================================
// Global transform state
// ============================================================

std::unordered_map<uint64_t, ClassTransformPlan> g_plans;

// ============================================================
// Klass / Method address cache
//
// findInstanceKlassByName traverses the entire ClassLoaderDataGraph (every
// loaded class, every Symbol read via RPM) on each call. In a batch transform
// (~169 transforms × 3-4 lookups each = 500+ full scans) this dominates wall
// time: each scan is O(class count) RPM reads, and the JVM has ~22000 loaded
// classes by the time mod loading finishes.
//
// Cached entries are stable for the lifetime of the target JVM as long as the
// class isn't unloaded — the classes we cache (FvmCallback, java.lang.* boxes,
// Object, ingot hook classes, MC target classes) are all strong-referenced and
// never unloaded.
//
// Caches are cleared on Agent restart (process boundary), not within a session.
static std::unordered_map<std::string, uint64_t> g_klassNameCache;

// Method cache key: "klassAddr#methodName#paramDesc". paramDesc may be empty
// (matches any descriptor — first-overload-wins, same as findMethodInKlass).
static std::unordered_map<std::string, uint64_t> g_methodCache;

// Set of klass addresses whose entire _methods array has been scanned and
// fully populated into g_methodCache. Once a klass is here, any cache miss
// on that klass means the method genuinely doesn't exist (only the methods
// the klass declares itself live in _methods — inherited methods are not
// in the array). Avoids redundant rescans when the same subclass is queried
// for different methods by N ingots in batch.
static std::unordered_set<uint64_t> g_klassMethodsScanned;

// Hit-rate counters (logged opportunistically in applyTransform).
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

// ============================================================
// Parameter type parsing for argument capture
// ============================================================

struct ParamSlotInfo {
    int slot;    // local variable slot index
    bool isRef;  // true if reference type (L...; or [...), false if primitive
};

// Parse JVM method signature to extract parameter slot info.
// fullSig format: "(Ljava/lang/String;I)V"
// isStatic: if true, params start at slot 0; otherwise slot 0 = this, params start at slot 1.
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

// ============================================================
// Locate Java Method* in target process
//
// Path: SystemDictionary -> ClassLoaderData -> Klass chain
//       -> InstanceKlass -> methods array -> Method*
//
// All done via ReadProcessMemory, no JVMTI.
// ============================================================

// Read a Symbol body from a HotSpot Symbol* (length at offset 0, body at offset 8 for 64-bit)
// Already declared in forgevm_internal.h

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

    // Get SystemDictionary via gHotSpotVMStructs
    // SystemDictionary::_loader_data is the head of ClassLoaderData linked list
    // But the actual path depends on JDK version. Let's try multiple approaches.

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

    // Cache hit: skip Method array scan and Symbol reads. The combination of
    // (klassAddr, methodName, paramDesc) uniquely identifies a Method* until
    // the class is unloaded — which we don't expect during a transform batch.
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
    // Cache miss but the klass's full _methods array has already been scanned
    // — the method genuinely is not declared on this klass (might exist on
    // an ancestor, but findMethodInKlass intentionally only inspects the
    // klass's own _methods, not inherited ones). Skip the rescan.
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

    // Array<Method*> layout: _length (int32 at offset 0, or after metadata pointer)
    // In HotSpot, Array<T> has: int _length at a known offset, then T _data[]
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

    // Scan the entire methods array exactly once. For every method we read,
    // populate the method cache so subsequent queries of any method on this
    // klass hit the cache (avoiding a re-scan). This dominates batch
    // performance when includeSubclasses is on (e.g. Entity has 164 subclasses
    // and EpicBlade has 10 includeSubclasses ingots → 1640 misses, each a
    // full scan, before this optimization).
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

        // Read name and signature via ConstantPool indices (for caching the
        // signature key — we want every method individually addressable by
        // (klass, name, paramDesc) for future lookups).
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

        // Cache by signature (full match) and by empty desc (any-overload-wins,
        // first method with this name in the array). Both forms used by
        // findMethodInKlass / findJavaMethod call sites.
        if (!mSig.empty()) {
            std::string sigKey = methodCacheKey(klassAddr, mName.c_str(), mSig.c_str());
            if (g_methodCache.find(sigKey) == g_methodCache.end()) {
                g_methodCache[sigKey] = methodAddr;
            }
            // Also cache "params" prefix form (e.g. "(F)") — the paramDesc
            // arg in our API is typically the parameter list portion, not full sig.
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

    // Mark this klass as fully scanned so any subsequent miss on it can
    // short-circuit to "not found" without rescanning the methods array.
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

// ============================================================
// Force deoptimization of all compiled methods
//
// JIT may inline the target method into callers. Modifying the
// target Method*'s ConstMethod does NOT affect inlined copies.
// We must mark all nmethods as "not_entrant" so the JVM
// deoptimizes them at the next safepoint and re-interprets
// (picking up our new bytecodes on re-compilation).
// ============================================================

// forceDeoptimizeAll — §17.11: only clear Method::_code, no c2i adapter probing.
// Callers use the normal interpreted entry after JIT deopt; the JVM re-adapts via
// the interpreter stub. c2i redirect is not needed for same-user, same-session targets.
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

// ============================================================
// Read ConstMethod bytecode
// ============================================================

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

// ============================================================
// Read ConstantPool
// ============================================================

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

// ============================================================
// Build expanded ConstantPool with hook MethodRef
//
// We append new entries to the constant pool:
//   [origLength]     = CONSTANT_Class(hookClass)  -> name_index = origLength+2
//   [origLength+1]   = CONSTANT_NameAndType(hookMethod, hookDesc) -> name = origLength+3, desc = origLength+4
//   [origLength+2]   = CONSTANT_Utf8(hookClass internal name)
//   [origLength+3]   = CONSTANT_Utf8(hookMethod name)
//   [origLength+4]   = CONSTANT_Utf8(hookDesc)
//   [origLength+5]   = CONSTANT_Methodref -> class = origLength, nat = origLength+1
//
// But HotSpot ConstantPool entries are pointer-sized slots with tag array separate.
// The "entries" in HotSpot's ConstantPool are NOT the same as classfile cp_info.
// They are resolved at load time into raw pointers/values.
//
// For an unresolved Methodref, HotSpot stores it as indices packed into a single slot.
// We need to create entries that the interpreter can resolve.
//
// CRITICAL: HotSpot resolves methods by comparing Symbol* POINTERS, not string content.
// We MUST use the JVM's existing interned Symbol* pointers, not freshly allocated ones.
// Read them from the Klass/Method metadata that already exists in the target process.
// ============================================================

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

// ============================================================
// Phase 1 invalidation: clear stale profiling state on Method*
//
// After replacing ConstMethod, the existing MDO is keyed against the
// OLD bytecode's BCIs. If C1/C2 reads it during recompile, ciMethodData
// hits ShouldNotReachHere(). Counters likewise reflect the old shape.
//
//   _method_data     = NULL  -> fresh MDO allocated on next compile
//   _method_counters = NULL  -> invocation count restarts
//   _flags |= 0x4 (_dont_inline) -> blocks stale inlines until callers
//                                   are deopted (Phase 2)
//
// _flags is not always in VMStructs; skip silently if absent.
// ============================================================
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
    }
}

// ============================================================
// Apply transform
// ============================================================

int applyTransform(const char* className, const char* methodName, const char* paramDesc,
                   const char* injectAt, const char* hookClass, const char* hookMethod,
                   const char* hookDesc, bool deferDeopt) {
    HANDLE proc = g_target.handle;
    std::string key = makeTransformKey(className, methodName, paramDesc);

    FVM_LOG("=== TRANSFORM BEGIN ===");
    FVM_LOG("target: %s.%s(%s) @ %s%s", className, methodName, paramDesc, injectAt,
            deferDeopt ? " [defer-deopt]" : "");
    FVM_LOG("hook:   %s.%s%s", hookClass, hookMethod, hookDesc);

    // Per-class plan: hasPlan/klassAddr/truOldCPAddr are resolved after step 5.

    // 1. Find the target Method*
    uint64_t methodAddr = 0;
    if (!findJavaMethod(className, methodName, paramDesc, &methodAddr)) {
        FVM_LOG("TRANSFORM FAILED: method not found");
        return 0;
    }
    FVM_LOG("Method* = 0x%llX", (unsigned long long)methodAddr);

    // 2. Read Method -> ConstMethod*
    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t origConstMethodAddr = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &origConstMethodAddr) || origConstMethodAddr == 0) {
        setError("cannot_read_constmethod_ptr");
        return 0;
    }
    FVM_LOG("ConstMethod* = 0x%llX (offset %lld from Method)", (unsigned long long)origConstMethodAddr, (long long)constMethodOff);

    // 3. Read ConstMethod -> ConstantPool*
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;

    uint64_t origConstPoolAddr = 0;
    if (!readRemotePointer(proc, origConstMethodAddr + (uint64_t)cmConstsOff, &origConstPoolAddr) || origConstPoolAddr == 0) {
        setError("cannot_read_constpool_ptr");
        return 0;
    }
    FVM_LOG("ConstantPool* = 0x%llX", (unsigned long long)origConstPoolAddr);

    // 4. Read original bytecode
    std::vector<uint8_t> origBytecode;
    uint64_t bcStartAddr = 0;
    uint32_t codeSize = 0;
    if (!readConstMethodBytecode(origConstMethodAddr, &origBytecode, &bcStartAddr, &codeSize)) {
        FVM_LOG("TRANSFORM FAILED: cannot read bytecode");
        return 0;
    }
    FVM_LOG("original bytecode: %u bytes at 0x%llX", codeSize, (unsigned long long)bcStartAddr);

    // 5. Read original constant pool
    std::vector<uint8_t> origPoolBytes;
    uint32_t poolLength = 0;
    size_t poolByteSize = 0;
    if (!readConstantPool(origConstPoolAddr, &origPoolBytes, &poolLength, &poolByteSize)) {
        FVM_LOG("TRANSFORM FAILED: cannot read constpool");
        return 0;
    }
    FVM_LOG("original constpool: length=%u, byteSize=%zu", poolLength, poolByteSize);

    // Resolve klassAddr from pool's _pool_holder field (needed for per-class plan).
    uint64_t klassAddr = 0;
    {
        int64_t phOff = structOffset("ConstantPool", "_pool_holder");
        if (phOff >= 0 && (size_t)(phOff + 8) <= origPoolBytes.size()) {
            memcpy(&klassAddr, origPoolBytes.data() + phOff, 8);
        }
        if (klassAddr == 0) {
            std::string clsInternal = std::string(className);
            for (char& c : clsInternal) { if (c == '.') c = '/'; }
            findInstanceKlassByName(clsInternal, &klassAddr);
        }
    }
    bool hasPlan = (klassAddr != 0 && g_plans.count(klassAddr) > 0);
    uint64_t truOldCPAddr = hasPlan ? g_plans[klassAddr].oldCPAddr : origConstPoolAddr;
    FVM_LOG("klassAddr=0x%llX hasPlan=%d truOldCPAddr=0x%llX",
            (unsigned long long)klassAddr, (int)hasPlan, (unsigned long long)truOldCPAddr);

    // 6. Find the hook class's InstanceKlass to verify it exists
    std::string hookClassInternal = toInternalName(hookClass);
    uint64_t hookKlassAddr = 0;
    if (!findInstanceKlassByName(hookClassInternal, &hookKlassAddr)) {
        setError("hook_class_not_loaded:" + hookClassInternal);
        return 0;
    }
    FVM_LOG("hookKlass (%s) = 0x%llX", hookClassInternal.c_str(), (unsigned long long)hookKlassAddr);

    // Verify hook method exists
    uint64_t hookMethodAddr = 0;
    if (!findMethodInKlass(hookKlassAddr, hookMethod, hookDesc, &hookMethodAddr)) {
        setError("hook_method_not_found:" + std::string(hookMethod));
        return 0;
    }
    FVM_LOG("hookMethod (%s%s) = 0x%llX", hookMethod, hookDesc, (unsigned long long)hookMethodAddr);

    // 7. Read target method's signature and access flags
    std::string targetReturnDesc = "V"; // default void
    std::string targetFullSig;          // full signature e.g. "(Ljava/lang/String;Ljava/lang/String;)V"
    bool targetIsStatic = false;
    {
        // Read access flags from Method to detect static
        int64_t accessFlagsOff = structOffset("Method", "_access_flags");
        if (accessFlagsOff >= 0) {
            int32_t flags = 0;
            readRemoteI32(proc, methodAddr + (uint64_t)accessFlagsOff, &flags);
            targetIsStatic = (flags & 0x0008) != 0; // ACC_STATIC
            FVM_LOG("target access_flags=0x%X, isStatic=%d", flags, (int)targetIsStatic);
        } else {
            FVM_LOG("WARN: cannot read Method::_access_flags, assuming instance method");
        }

        int64_t sigIdxOff = structOffset("ConstMethod", "_signature_index");
        if (sigIdxOff >= 0) {
            uint16_t sigIndex = 0;
            if (readRemoteU16(proc, origConstMethodAddr + (uint64_t)sigIdxOff, &sigIndex) && sigIndex > 0) {
                int64_t cpHdrSize0 = typeSize("ConstantPool");
                if (cpHdrSize0 < 0) cpHdrSize0 = 0x138;
                uint64_t sigEntryAddr = origConstPoolAddr + (uint64_t)cpHdrSize0 + (uint64_t)sigIndex * 8;
                uint64_t sigSymbol = 0;
                if (readRemotePointer(proc, sigEntryAddr, &sigSymbol) && sigSymbol != 0) {
                    std::string fullSig;
                    if (readSymbolBody(proc, sigSymbol, &fullSig)) {
                        targetFullSig = fullSig;
                        size_t closeParen = fullSig.find(')');
                        if (closeParen != std::string::npos && closeParen + 1 < fullSig.size()) {
                            targetReturnDesc = fullSig.substr(closeParen + 1);
                        }
                    }
                }
            }
        }
    }

    // Parse target method's parameters for argument capture
    std::vector<ParamSlotInfo> targetParams = parseParamSlots(targetFullSig, targetIsStatic);
    FVM_LOG("target params: %zu (sig=%s, static=%d)", targetParams.size(),
            targetFullSig.c_str(), (int)targetIsStatic);

    // Determine return type category and unboxing info
    struct UnboxInfo {
        bool needsUnbox;
        std::string wrapperClass;
        std::string unboxMethod;
        std::string unboxDesc;
        uint8_t returnOp;
    };
    UnboxInfo unbox = { false, "", "", "", 0xB0 };

    if (targetReturnDesc == "V") {
        unbox.returnOp = 0xB1;
    } else if (targetReturnDesc == "Z") {
        unbox = { true, "java/lang/Boolean",   "booleanValue", "()Z", 0xAC };
    } else if (targetReturnDesc == "B") {
        unbox = { true, "java/lang/Byte",      "byteValue",    "()B", 0xAC };
    } else if (targetReturnDesc == "C") {
        unbox = { true, "java/lang/Character", "charValue",    "()C", 0xAC };
    } else if (targetReturnDesc == "S") {
        unbox = { true, "java/lang/Short",     "shortValue",   "()S", 0xAC };
    } else if (targetReturnDesc == "I") {
        unbox = { true, "java/lang/Integer",   "intValue",     "()I", 0xAC };
    } else if (targetReturnDesc == "F") {
        unbox = { true, "java/lang/Float",     "floatValue",   "()F", 0xAE };
    } else if (targetReturnDesc == "J") {
        unbox = { true, "java/lang/Long",      "longValue",    "()J", 0xAD };
    } else if (targetReturnDesc == "D") {
        unbox = { true, "java/lang/Double",    "doubleValue",  "()D", 0xAF };
    } else {
        unbox.returnOp = 0xB0; // areturn for Object/array
    }

    // Find unbox class + method if needed
    uint64_t unboxKlassAddr = 0;
    uint64_t unboxMethodAddr = 0;
    if (unbox.needsUnbox) {
        if (!findInstanceKlassByName(unbox.wrapperClass, &unboxKlassAddr)) {
            setError("unbox_class_not_loaded:" + unbox.wrapperClass); return 0;
        }
        if (!findMethodInKlass(unboxKlassAddr, unbox.unboxMethod.c_str(),
                               unbox.unboxDesc.c_str(), &unboxMethodAddr)) {
            setError("unbox_method_not_found:" + unbox.unboxMethod); return 0;
        }
    }

    FVM_LOG("targetReturnDesc=%s, needsUnbox=%d, returnOp=0x%02X",
            targetReturnDesc.c_str(), (int)unbox.needsUnbox, unbox.returnOp);

    // Find FvmCallback class and methods
    uint64_t cbKlassAddr = 0;
    if (!findInstanceKlassByName("forgevm/forge/FvmCallback", &cbKlassAddr)) {
        setError("FvmCallback_class_not_loaded"); return 0;
    }
    uint64_t cbInitMethodAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "<init>", "(Ljava/lang/Object;[Ljava/lang/Object;)V", &cbInitMethodAddr)) {
        setError("FvmCallback_init_not_found"); return 0;
    }
    uint64_t cbIsCancelledAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "isCancelled", "()Z", &cbIsCancelledAddr)) {
        setError("FvmCallback_isCancelled_not_found"); return 0;
    }
    uint64_t cbGetReturnAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "getReturnValue", "()Ljava/lang/Object;", &cbGetReturnAddr)) {
        setError("FvmCallback_getReturnValue_not_found"); return 0;
    }

    // Find java/lang/Object klass (needed for anewarray to build Object[] args)
    uint64_t objectKlassAddr = 0;
    bool hasArgCapture = !targetParams.empty();
    if (hasArgCapture) {
        if (!findInstanceKlassByName("java/lang/Object", &objectKlassAddr)) {
            FVM_LOG("WARN: java/lang/Object klass not found, disabling arg capture");
            hasArgCapture = false;
        }
    }

    // 8. Read EXISTING interned Symbol* pointers from target JVM metadata
    //
    // CRITICAL: HotSpot resolves methods by comparing Symbol* POINTERS, not string content.
    // We must use the same interned Symbol* that the JVM already has, NOT freshly allocated copies.
    // Read them from the Klass/Method objects we already located.

    // Hook class/method/descriptor symbols
    uint64_t symHookClass = readKlassNameSymbol(hookKlassAddr);
    uint64_t symHookMethod = 0, symHookDesc = 0;
    if (!readMethodSymbols(hookMethodAddr, &symHookMethod, &symHookDesc)) {
        setError("cannot_read_hook_method_symbols"); return 0;
    }

    // FvmCallback class name symbol
    uint64_t symCbClass = readKlassNameSymbol(cbKlassAddr);

    // FvmCallback.<init> name and descriptor symbols
    uint64_t symInit = 0, symInitDesc = 0;
    if (!readMethodSymbols(cbInitMethodAddr, &symInit, &symInitDesc)) {
        setError("cannot_read_cbInit_symbols"); return 0;
    }

    // FvmCallback.isCancelled name and descriptor symbols
    uint64_t symIsCancelled = 0, symIsCancelledD = 0;
    if (!readMethodSymbols(cbIsCancelledAddr, &symIsCancelled, &symIsCancelledD)) {
        setError("cannot_read_cbIsCancelled_symbols"); return 0;
    }

    // FvmCallback.getReturnValue name and descriptor symbols
    uint64_t symGetRetVal = 0, symGetRetValD = 0;
    if (!readMethodSymbols(cbGetReturnAddr, &symGetRetVal, &symGetRetValD)) {
        setError("cannot_read_cbGetReturnValue_symbols"); return 0;
    }

    FVM_LOG("interned symbols: hookClass=0x%llX hookMethod=0x%llX hookDesc=0x%llX",
            (unsigned long long)symHookClass, (unsigned long long)symHookMethod, (unsigned long long)symHookDesc);
    FVM_LOG("  cbClass=0x%llX init=0x%llX initDesc=0x%llX",
            (unsigned long long)symCbClass, (unsigned long long)symInit, (unsigned long long)symInitDesc);
    FVM_LOG("  isCancelled=0x%llX isCancelledD=0x%llX getRetVal=0x%llX getRetValD=0x%llX",
            (unsigned long long)symIsCancelled, (unsigned long long)symIsCancelledD,
            (unsigned long long)symGetRetVal, (unsigned long long)symGetRetValD);

    if (symHookClass == 0 || symHookMethod == 0 || symHookDesc == 0 ||
        symCbClass == 0 || symInit == 0 || symInitDesc == 0 ||
        symIsCancelled == 0 || symIsCancelledD == 0 ||
        symGetRetVal == 0 || symGetRetValD == 0) {
        setError("failed_to_read_interned_symbols"); return 0;
    }

    // java/lang/Object class name symbol (for anewarray Object[])
    uint64_t symObjectClass = 0;
    if (hasArgCapture) {
        symObjectClass = readKlassNameSymbol(objectKlassAddr);
        if (symObjectClass == 0) {
            FVM_LOG("WARN: cannot read java/lang/Object name symbol, disabling arg capture");
            hasArgCapture = false;
        }
    }

    uint64_t symUnboxClass = 0, symUnboxMethod = 0, symUnboxDesc = 0;
    if (unbox.needsUnbox) {
        symUnboxClass = readKlassNameSymbol(unboxKlassAddr);
        if (!readMethodSymbols(unboxMethodAddr, &symUnboxMethod, &symUnboxDesc)) {
            setError("cannot_read_unbox_method_symbols"); return 0;
        }
        if (symUnboxClass == 0 || symUnboxMethod == 0 || symUnboxDesc == 0) {
            setError("failed_to_read_unbox_symbols"); return 0;
        }
        FVM_LOG("unbox symbols: class=0x%llX method=0x%llX desc=0x%llX",
                (unsigned long long)symUnboxClass, (unsigned long long)symUnboxMethod, (unsigned long long)symUnboxDesc);
    }

    // 9. Expand _resolved_klasses (needed for 'new' and 'checkcast' to find Klass*)
    int64_t resolvedKlassesOff = structOffset("ConstantPool", "_resolved_klasses");
    int numNewClasses = 2 + (hasArgCapture ? 1 : 0) + (unbox.needsUnbox ? 1 : 0);
    int hookClassRKIdx = 0, cbClassRKIdx = 0, objectClassRKIdx = 0, unboxClassRKIdx = 0;
    uint64_t newRKAddr = 0;

    if (resolvedKlassesOff >= 0) {
        uint64_t origRK = 0;
        memcpy(&origRK, origPoolBytes.data() + resolvedKlassesOff, 8);

        if (origRK != 0) {
            int64_t rkLenOff = 0, rkDataOff = 8;
            { int64_t v = structOffset("Array<Klass*>", "_length"); if (v >= 0) rkLenOff = v; }
            { int64_t v = structOffset("Array<Klass*>", "_data");   if (v >= 0) rkDataOff = v; }

            int32_t origRKLen = 0;
            readRemoteI32(proc, origRK + (uint64_t)rkLenOff, &origRKLen);

            hookClassRKIdx = origRKLen;
            cbClassRKIdx   = origRKLen + 1;
            int nextRKIdx  = origRKLen + 2;
            if (hasArgCapture) objectClassRKIdx = nextRKIdx++;
            if (unbox.needsUnbox) unboxClassRKIdx = nextRKIdx++;

            int32_t newRKLen = origRKLen + numNewClasses;
            size_t origRKSize = (size_t)rkDataOff + origRKLen * 8;
            size_t newRKSize  = (size_t)rkDataOff + newRKLen * 8;
            newRKSize = (newRKSize + 7) & ~7;

            std::vector<uint8_t> origRKBytes(origRKSize);
            readRemoteMem(proc, origRK, origRKBytes.data(), origRKSize);

            std::vector<uint8_t> newRKBytes(newRKSize, 0);
            memcpy(newRKBytes.data(), origRKBytes.data(), origRKSize);
            memcpy(newRKBytes.data() + rkLenOff, &newRKLen, 4);

            uint64_t* rkData = (uint64_t*)(newRKBytes.data() + rkDataOff);
            rkData[hookClassRKIdx] = hookKlassAddr;
            rkData[cbClassRKIdx]   = cbKlassAddr;
            if (hasArgCapture) rkData[objectClassRKIdx] = objectKlassAddr;
            if (unbox.needsUnbox) rkData[unboxClassRKIdx] = unboxKlassAddr;

            newRKAddr = (uint64_t)VirtualAllocEx(proc, NULL, newRKSize,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (newRKAddr == 0) { setError("VirtualAllocEx_resolved_klasses_failed"); return 0; }
            writeRemoteMem(proc, newRKAddr, newRKBytes.data(), newRKSize);
            FVM_LOG("resolved_klasses: origLen=%d, newLen=%d, newAddr=0x%llX",
                    origRKLen, newRKLen, (unsigned long long)newRKAddr);
            FVM_LOG("  hookClassRKIdx=%d (Klass=0x%llX), cbClassRKIdx=%d (Klass=0x%llX)",
                    hookClassRKIdx, (unsigned long long)hookKlassAddr,
                    cbClassRKIdx, (unsigned long long)cbKlassAddr);
        }
    }

    // 10. Build expanded constant pool (proper symbolic format for JDK 17+)
    //
    // CP layout (P = poolLength):
    //   P+0..P+9:   Utf8 entries (tag=1, slot=Symbol*)
    //   P+10,P+11:  Class entries (tag=7, slot=(name_idx<<16)|resolved_klass_idx)
    //   P+12..P+15: NameAndType entries (tag=12, slot=(desc_idx<<16)|name_idx)
    //   P+16..P+19: Methodref entries (tag=10, slot=(nat_idx<<16)|class_idx)
    //   [If argCapture]: +1 Utf8 (Object name), +1 Class (Object)
    //   [If unbox]:      +3 Utf8, +1 Class, +1 NameAndType, +1 Methodref
    //
    // HotSpot extract helpers:
    //   extract_low_short(val)  = val & 0xFFFF        (low 16 bits)
    //   extract_high_short(val) = (val >> 16) & 0xFFFF (high 16 bits)

    uint32_t argCaptureEntries = hasArgCapture ? 2 : 0;  // 1 Utf8 + 1 Class
    uint32_t unboxEntries = unbox.needsUnbox ? 6 : 0;
    uint32_t totalNewEntries = 20 + argCaptureEntries + unboxEntries;
    uint32_t newPoolLength = poolLength + totalNewEntries;
    size_t newPoolByteSize = poolByteSize + totalNewEntries * 8;

    std::vector<uint8_t> newPoolBytes(newPoolByteSize, 0);
    memcpy(newPoolBytes.data(), origPoolBytes.data(), poolByteSize);

    int64_t lengthOff = structOffset("ConstantPool", "_length");
    if (lengthOff >= 0) {
        int32_t newLen32 = (int32_t)newPoolLength;
        memcpy(newPoolBytes.data() + lengthOff, &newLen32, 4);
    }

    // Update _resolved_klasses pointer in pool
    if (resolvedKlassesOff >= 0 && newRKAddr != 0) {
        memcpy(newPoolBytes.data() + resolvedKlassesOff, &newRKAddr, 8);
    }

    int64_t cpHeaderSize = typeSize("ConstantPool");
    if (cpHeaderSize < 0) cpHeaderSize = 0x138;

    uint64_t* newSlots = (uint64_t*)(newPoolBytes.data() + cpHeaderSize);
    uint32_t P = poolLength;

    // Utf8 entries (tag=1, slot=Symbol*)
    newSlots[P+0]  = symHookClass;
    newSlots[P+1]  = symHookMethod;
    newSlots[P+2]  = symHookDesc;
    newSlots[P+3]  = symCbClass;
    newSlots[P+4]  = symInit;
    newSlots[P+5]  = symInitDesc;
    newSlots[P+6]  = symIsCancelled;
    newSlots[P+7]  = symIsCancelledD;
    newSlots[P+8]  = symGetRetVal;
    newSlots[P+9]  = symGetRetValD;

    // Class entries (tag=7): slot = (name_utf8_idx << 16) | resolved_klass_idx
    newSlots[P+10] = (uint64_t)(((uint32_t)(P+0) << 16) | (uint32_t)hookClassRKIdx);
    newSlots[P+11] = (uint64_t)(((uint32_t)(P+3) << 16) | (uint32_t)cbClassRKIdx);

    // NameAndType entries (tag=12): slot = (desc_idx << 16) | name_idx
    newSlots[P+12] = (uint64_t)(((uint32_t)(P+2) << 16) | (uint32_t)(P+1));   // hookDesc<<16 | hookMethod
    newSlots[P+13] = (uint64_t)(((uint32_t)(P+5) << 16) | (uint32_t)(P+4));   // initDesc<<16 | <init>
    newSlots[P+14] = (uint64_t)(((uint32_t)(P+7) << 16) | (uint32_t)(P+6));   // ()Z<<16 | isCancelled
    newSlots[P+15] = (uint64_t)(((uint32_t)(P+9) << 16) | (uint32_t)(P+8));   // ()Object<<16 | getReturnValue

    // Methodref entries (tag=10): slot = (nat_idx << 16) | class_idx
    newSlots[P+16] = (uint64_t)(((uint32_t)(P+12) << 16) | (uint32_t)(P+10)); // hook invokestatic
    newSlots[P+17] = (uint64_t)(((uint32_t)(P+13) << 16) | (uint32_t)(P+11)); // FvmCallback.<init>
    newSlots[P+18] = (uint64_t)(((uint32_t)(P+14) << 16) | (uint32_t)(P+11)); // FvmCallback.isCancelled
    newSlots[P+19] = (uint64_t)(((uint32_t)(P+15) << 16) | (uint32_t)(P+11)); // FvmCallback.getReturnValue

    // Dynamic extension point — optional entries use running index E
    uint32_t E = 20;

    // [arg capture] Object class for anewarray
    uint32_t objClassCpIdx = 0; // CP index of java/lang/Object Class entry (for anewarray bytecode)
    if (hasArgCapture) {
        newSlots[P+E]   = symObjectClass;  // Utf8: "java/lang/Object"
        newSlots[P+E+1] = (uint64_t)(((uint32_t)(P+E) << 16) | (uint32_t)objectClassRKIdx); // Class
        objClassCpIdx = P + E + 1;
        FVM_LOG("  argCapture: Object Utf8=P+%u, Class=P+%u (cpIdx=%u)", E, E+1, objClassCpIdx);
        E += 2;
    }

    // [unbox] wrapper class + valueOf method
    uint32_t unboxMethodrefCpOff = 0; // relative offset from P for unbox Methodref
    if (unbox.needsUnbox) {
        newSlots[P+E]   = symUnboxClass;
        newSlots[P+E+1] = symUnboxMethod;
        newSlots[P+E+2] = symUnboxDesc;
        // Class: (name_idx << 16) | resolved_klass_idx
        newSlots[P+E+3] = (uint64_t)(((uint32_t)(P+E) << 16) | (uint32_t)unboxClassRKIdx);
        // NameAndType: (desc_idx << 16) | name_idx
        newSlots[P+E+4] = (uint64_t)(((uint32_t)(P+E+2) << 16) | (uint32_t)(P+E+1));
        // Methodref: (nat_idx << 16) | class_idx
        newSlots[P+E+5] = (uint64_t)(((uint32_t)(P+E+4) << 16) | (uint32_t)(P+E+3));
        unboxMethodrefCpOff = E + 5;
        E += 6;
    }

    FVM_LOG("new CP entries (P=%u, newPoolLength=%u, totalNew=%u):", P, newPoolLength, totalNewEntries);

    // Update tags array
    int64_t tagsOff = structOffset("ConstantPool", "_tags");
    if (tagsOff >= 0) {
        uint64_t tagsArrayAddr = 0;
        memcpy(&tagsArrayAddr, newPoolBytes.data() + tagsOff, 8);

        if (tagsArrayAddr != 0) {
            int64_t tagArrayLenOff = structOffset("Array<u1>", "_length");
            if (tagArrayLenOff < 0) tagArrayLenOff = 0;
            int64_t tagArrayDataOff = structOffset("Array<u1>", "_data");
            if (tagArrayDataOff < 0) tagArrayDataOff = 4;

            int32_t tagLen = 0;
            readRemoteI32(proc, tagsArrayAddr + (uint64_t)tagArrayLenOff, &tagLen);

            size_t newTagSize = (size_t)tagArrayDataOff + newPoolLength;
            newTagSize = (newTagSize + 7) & ~7;

            uint64_t newTagsAddr = (uint64_t)VirtualAllocEx(proc, NULL, newTagSize,
                                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (newTagsAddr != 0) {
                std::vector<uint8_t> oldTags((size_t)tagArrayDataOff + tagLen);
                readRemoteMem(proc, tagsArrayAddr, oldTags.data(), oldTags.size());

                std::vector<uint8_t> newTags(newTagSize, 0);
                memcpy(newTags.data(), oldTags.data(), oldTags.size());

                int32_t newTagLen = (int32_t)newPoolLength;
                memcpy(newTags.data() + tagArrayLenOff, &newTagLen, 4);

                uint8_t* td = newTags.data() + tagArrayDataOff;
                // Base 20 entries: 10 Utf8, 2 Class, 4 NameAndType, 4 Methodref
                for (int i = 0; i < 10; i++) td[P+i] = 1;   // Utf8
                td[P+10] = 7;  td[P+11] = 7;                 // Class
                td[P+12] = 12; td[P+13] = 12; td[P+14] = 12; td[P+15] = 12; // NameAndType
                td[P+16] = 10; td[P+17] = 10; td[P+18] = 10; td[P+19] = 10; // Methodref

                // Tag optional entries using the same running offset logic
                uint32_t tagE = 20;
                if (hasArgCapture) {
                    td[P+tagE] = 1;     // Utf8 (Object name)
                    td[P+tagE+1] = 7;   // Class (Object)
                    tagE += 2;
                }
                if (unbox.needsUnbox) {
                    td[P+tagE] = 1;  td[P+tagE+1] = 1;  td[P+tagE+2] = 1;  // Utf8
                    td[P+tagE+3] = 7;  // Class
                    td[P+tagE+4] = 12; // NameAndType
                    td[P+tagE+5] = 10; // Methodref
                    tagE += 6;
                }

                writeRemoteMem(proc, newTagsAddr, newTags.data(), newTagSize);
                memcpy(newPoolBytes.data() + tagsOff, &newTagsAddr, 8);
            }
        }
    }

    // 11. Expand ConstantPoolCache
    //
    // In JDK 17+, invoke bytecodes use CP cache indices (not CP indices).
    // We must add cache entries for our new Methodref entries.
    // Unresolved entries: _indices = cp_index, _f1 = 0, _f2 = 0, _flags = 0.
    // The JVM will resolve them on first use from our symbolic CP entries.

    int64_t cacheOff = structOffset("ConstantPool", "_cache");
    int32_t origCacheLen = 0;
    int numNewCacheEntries = unbox.needsUnbox ? 5 : 4;
    int hookCacheIdx = 0, initCacheIdx = 0, cancelCacheIdx = 0, retValCacheIdx = 0, unboxCacheIdx = 0;
    uint64_t newCacheAddr = 0;
    int64_t cacheCpOff = -1;
    std::vector<uint8_t> newCacheBytes;

    // Hoisted: post-suspend snapshot needs these. See "snapshot CPCache (post-suspend)"
    // section near suspendTargetThreads.
    uint64_t origCacheAddr = 0;
    int64_t cacheHdrSize = 16;
    int64_t cacheEntrySize = 32;
    int64_t cacheLenOff = 0;
    int32_t newCacheLen = 0;
    size_t origCacheSize = 0;

    if (cacheOff >= 0) {
        memcpy(&origCacheAddr, origPoolBytes.data() + cacheOff, 8);

        if (origCacheAddr != 0) {
            cacheHdrSize = typeSize("ConstantPoolCache");
            if (cacheHdrSize < 0) cacheHdrSize = 16;
            cacheLenOff = structOffset("ConstantPoolCache", "_length");
            if (cacheLenOff < 0) cacheLenOff = 0;
            cacheEntrySize = typeSize("ConstantPoolCacheEntry");
            if (cacheEntrySize < 0) cacheEntrySize = 32;
            cacheCpOff = structOffset("ConstantPoolCache", "_constant_pool");
            if (cacheCpOff < 0) cacheCpOff = 8;

            readRemoteI32(proc, origCacheAddr + (uint64_t)cacheLenOff, &origCacheLen);

            hookCacheIdx   = origCacheLen;
            initCacheIdx   = origCacheLen + 1;
            cancelCacheIdx = origCacheLen + 2;
            retValCacheIdx = origCacheLen + 3;
            if (unbox.needsUnbox) unboxCacheIdx = origCacheLen + 4;

            newCacheLen = origCacheLen + numNewCacheEntries;
            origCacheSize = (size_t)cacheHdrSize + origCacheLen * cacheEntrySize;
            size_t newCacheSize  = (size_t)cacheHdrSize + newCacheLen * cacheEntrySize;

            // RACE FIX: do NOT snapshot origCache here (threads still running, CPCache
            // entries may be undergoing lazy resolve → torn read). The snapshot+memcpy
            // is deferred to AFTER suspendTargetThreads. We allocate newCacheBytes at
            // full size now (zero-init) so the pre-resolved tail entries (1277-1280)
            // can be filled into the suffix region [origCacheSize, newCacheSize) below.
            // The prefix [0, origCacheSize) stays zero here and is filled post-suspend.
            // §17.3: new CPCache entries are all-zero (unresolved). HotSpot lazy-resolves on
            // first use. This eliminates complex pre-resolve logic that was brittle across
            // class loader boundaries (modular Forge loaders).
            newCacheBytes.resize(newCacheSize, 0);

            newCacheAddr = (uint64_t)VirtualAllocEx(proc, NULL, newCacheSize,
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (newCacheAddr == 0) { setError("VirtualAllocEx_cache_failed"); return 0; }

            // Update new pool's _cache pointer (back-pointer fixed post-suspend)
            memcpy(newPoolBytes.data() + cacheOff, &newCacheAddr, 8);

            FVM_LOG("CPCache: origLen=%d, newLen=%d, entrySize=%lld, newAddr=0x%llX (new entries zeroed/unresolved)",
                    origCacheLen, newCacheLen, (long long)cacheEntrySize, (unsigned long long)newCacheAddr);
        }
    }

    // Guard: if resolved_klasses or CP cache expansion failed, the class is likely loaded
    // but not yet linked. Injecting bytecode with index 0 would cause VerifyError
    // when the JVM later verifies/interprets the method. Abort this transform.
    if (newRKAddr == 0) {
        FVM_LOG("TRANSFORM ABORTED: resolved_klasses expansion failed (class may not be linked yet)");
        setError("resolved_klasses_not_available");
        return 0;
    }
    if (newCacheAddr == 0) {
        FVM_LOG("TRANSFORM ABORTED: ConstantPoolCache expansion failed (class may not be linked yet)");
        setError("cache_not_available");
        return 0;
    }

    // 12. Build new bytecode
    //
    // IMPORTANT: invoke operands = CP CACHE indices (not CP indices)
    //            new/checkcast operands = CP indices
    uint16_t cbClassCpIdx     = (uint16_t)(P + 11);           // FvmCallback class (for 'new')
    uint16_t hookCacheIdx16   = (uint16_t)hookCacheIdx;        // invokestatic hook
    uint16_t initCacheIdx16   = (uint16_t)initCacheIdx;        // invokespecial <init>
    uint16_t cancelCacheIdx16 = (uint16_t)cancelCacheIdx;      // invokespecial isCancelled
    uint16_t retValCacheIdx16 = (uint16_t)retValCacheIdx;      // invokespecial getReturnValue
    uint16_t unboxClassCpIdx  = unbox.needsUnbox ? (uint16_t)(P + unboxMethodrefCpOff - 2) : 0; // wrapper Class (for checkcast)
    uint16_t unboxCacheIdx16  = unbox.needsUnbox ? (uint16_t)unboxCacheIdx : 0;

    FVM_LOG("bytecode operand indices:");
    FVM_LOG("  new FvmCallback CP idx = %u (big-endian)", (unsigned)cbClassCpIdx);
    FVM_LOG("  invokespecial <init>     cache idx = %u (native-endian)", (unsigned)initCacheIdx16);
    FVM_LOG("  invokestatic hook        cache idx = %u (native-endian)", (unsigned)hookCacheIdx16);
    FVM_LOG("  invokespecial isCancelled cache idx = %u (native-endian)", (unsigned)cancelCacheIdx16);
    FVM_LOG("  invokespecial getRetVal   cache idx = %u (native-endian)", (unsigned)retValCacheIdx16);
    if (unbox.needsUnbox) {
        FVM_LOG("  checkcast unbox CP idx = %u, invokespecial unbox cache idx = %u",
                (unsigned)unboxClassCpIdx, (unsigned)unboxCacheIdx16);
    }

    // Big-endian: for CP indices used by new/checkcast/ifeq (standard Java bytecode format)
    auto emitIdx = [](std::vector<uint8_t>& bc, uint16_t idx) {
        bc.push_back((uint8_t)(idx >> 8));
        bc.push_back((uint8_t)(idx & 0xFF));
    };

    // Native byte order (little-endian on x86): for CP cache indices used by
    // invoke bytecodes (invokestatic/invokespecial/invokevirtual).
    // HotSpot's bytecode rewriter converts invoke operands from big-endian CP indices
    // to native-endian cache indices. Since our bytecodes bypass the rewriter,
    // we must emit cache indices in native byte order directly.
    auto emitNativeIdx = [](std::vector<uint8_t>& bc, uint16_t idx) {
        bc.push_back((uint8_t)(idx & 0xFF));        // low byte first
        bc.push_back((uint8_t)((idx >> 8) & 0xFF)); // high byte second
    };

    // Build cancel branch return sequence
    std::vector<uint8_t> cancelReturn;
    if (unbox.returnOp == 0xB1) {
        // void: pop callback ref and return
        cancelReturn.push_back(0x57); // pop
        cancelReturn.push_back(0xB1); // return
    } else {
        // invokespecial getReturnValue (cache index, native byte order) → [Object]
        // Using invokespecial instead of invokevirtual to enable CP cache pre-resolution
        // (bypasses class loader constraints in modular class loader environments)
        cancelReturn.push_back(0xB7);
        cancelReturn.push_back((uint8_t)(retValCacheIdx16 & 0xFF));
        cancelReturn.push_back((uint8_t)((retValCacheIdx16 >> 8) & 0xFF));

        if (unbox.needsUnbox) {
            // checkcast WrapperClass (CP index, big-endian) → [WrapperClass]
            cancelReturn.push_back(0xC0);
            cancelReturn.push_back((uint8_t)(unboxClassCpIdx >> 8));
            cancelReturn.push_back((uint8_t)(unboxClassCpIdx & 0xFF));
            // invokespecial unboxMethod (cache index, native byte order) → [primitive]
            cancelReturn.push_back(0xB7);
            cancelReturn.push_back((uint8_t)(unboxCacheIdx16 & 0xFF));
            cancelReturn.push_back((uint8_t)((unboxCacheIdx16 >> 8) & 0xFF));
        }

        cancelReturn.push_back(unbox.returnOp);
    }

    int16_t ifeqOffset = (int16_t)(3 + (int)cancelReturn.size());

    std::vector<uint8_t> newBytecode;
    std::string injectAtStr(injectAt);

    auto emitCallbackPrologue = [&](std::vector<uint8_t>& bc) {
        // new FvmCallback(instance, args)
        bc.push_back(0xBB); emitIdx(bc, cbClassCpIdx);           // new FvmCallback → [cbU]
        bc.push_back(0x59);                                        // dup → [cbU, cbU]

        // Push instance: this for instance methods, null for static
        if (targetIsStatic) {
            bc.push_back(0x01);                                    // aconst_null → [cbU, cbU, null]
        } else {
            bc.push_back(0x2A);                                    // aload_0 → [cbU, cbU, this]
        }

        // Build Object[] args (or null if no params / arg capture disabled)
        if (!hasArgCapture || targetParams.empty()) {
            bc.push_back(0x01);                                    // aconst_null → [cbU, cbU, inst, null]
        } else {
            int n = (int)targetParams.size();
            // Push array size
            if (n <= 5) {
                bc.push_back((uint8_t)(0x03 + n));                 // iconst_0..iconst_5
            } else {
                bc.push_back(0x10); bc.push_back((uint8_t)n);     // bipush N
            }
            // anewarray java/lang/Object (CP idx, big-endian)
            bc.push_back(0xBD); emitIdx(bc, (uint16_t)objClassCpIdx);
            // Fill array with method arguments
            for (int i = 0; i < n; i++) {
                bc.push_back(0x59);                                // dup array ref
                // Push array index
                if (i <= 5) {
                    bc.push_back((uint8_t)(0x03 + i));             // iconst_0..iconst_5
                } else {
                    bc.push_back(0x10); bc.push_back((uint8_t)i); // bipush
                }
                // Load parameter value
                if (targetParams[i].isRef) {
                    int slot = targetParams[i].slot;
                    if (slot <= 3) {
                        bc.push_back((uint8_t)(0x2A + slot));      // aload_0..aload_3
                    } else {
                        bc.push_back(0x19); bc.push_back((uint8_t)slot); // aload N
                    }
                } else {
                    bc.push_back(0x01);                            // aconst_null (primitive, boxing TODO)
                }
                bc.push_back(0x53);                                // aastore
            }
        }

        bc.push_back(0xB7); emitNativeIdx(bc, initCacheIdx16);    // invokespecial <init>(Object, Object[]) → [cb]
        bc.push_back(0x59);                                        // dup → [cb, cb]
        bc.push_back(0x59);                                        // dup → [cb, cb, cb]
        bc.push_back(0xB8); emitNativeIdx(bc, hookCacheIdx16);    // invokestatic hook → [cb, cb]
        bc.push_back(0xB7); emitNativeIdx(bc, cancelCacheIdx16);  // invokespecial isCancelled → [cb, int]
        bc.push_back(0x99);                                        // ifeq (branch offset, big-endian)
        bc.push_back((uint8_t)(ifeqOffset >> 8));
        bc.push_back((uint8_t)(ifeqOffset & 0xFF));
        // Cancel branch: stack = [cb]
        bc.insert(bc.end(), cancelReturn.begin(), cancelReturn.end());
        // CONTINUE: stack = [cb], pop it
        bc.push_back(0x57); // pop → []
    };

    // Bytecode instruction length table (per JVM Specification §6.5).
    // -1 = variable length, handled separately in getInsnLength below
    //      (0xAA tableswitch, 0xAB lookupswitch, 0xC4 wide).
    static const int8_t bcLengths[256] = {
        // 0x00-0x0F: nop, aconst_null, iconst_m1..5, lconst_0/1, fconst_0..2, dconst_0/1
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x10-0x1F: bipush(2), sipush(3), ldc(2), ldc_w(3), ldc2_w(3),
        //            iload/lload/fload/dload/aload(2 each), iload_0..3(1 each)
        2,3,2,3,3,2,2,2,2,2,1,1,1,1,1,1,
        // 0x20-0x2F: lload_2/3, fload_0..3, dload_0..3, aload_0..3
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x30-0x3F: iaload..baload(1), istore/lstore/fstore/dstore/astore(2 each), istore_0..3(1)
        1,1,1,1,1,1,2,2,2,2,2,1,1,1,1,1,
        // 0x40-0x4F: lstore_1..3, fstore_0..3, dstore_0..3, astore_0..3
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x50-0x5F: lastore..sastore, pop, pop2, dup, dup_x1/x2, dup2, dup2_x1/x2, swap
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x60-0x6F: iadd..ineg
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x70-0x7F: lneg..lxor
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        // 0x80-0x8F: ior, lor, ixor, lxor, iinc(3), conversions...
        1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,
        // 0x90-0x9F: conversions (1) and if_eq..if_le start of branch ops (3)
        1,1,1,1,1,1,1,1,1,3,3,3,3,3,3,3,
        // 0xA0-0xAF: if_icmp*..if_acmpne(3), goto(3), jsr(3), ret(2),
        //            tableswitch(-1), lookupswitch(-1), ireturn..dreturn(1)
        3,3,3,3,3,3,3,3,3,2,-1,-1,1,1,1,1,
        // 0xB0-0xBF: areturn(1), return(1),
        //            getstatic..invokestatic(3), invokeinterface(5), invokedynamic(5),
        //            new(3), newarray(2), anewarray(3), arraylength(1), athrow(1)
        1,1,3,3,3,3,3,3,3,5,5,3,2,3,1,1,
        // 0xC0-0xCF: checkcast(3), instanceof(3), monitorenter(1), monitorexit(1),
        //            wide(-1), multianewarray(4), ifnull(3), ifnonnull(3),
        //            goto_w(5), jsr_w(5), breakpoint(1),
        //            then HotSpot fast bytecodes start at 0xCB:
        //            0xCB fast_agetfield(3), 0xCC fast_bgetfield(3), 0xCD fast_cgetfield(3),
        //            0xCE fast_dgetfield(3), 0xCF fast_fgetfield(3)
        3,3,1,1,-1,4,3,3,5,5,1,3,3,3,3,3,
        // 0xD0-0xDF: more HotSpot fast bytecodes (rewritten in-place by HotSpot link).
        //   0xD0 fast_igetfield(3), 0xD1 fast_lgetfield(3), 0xD2 fast_sgetfield(3),
        //   0xD3 fast_aputfield(3), 0xD4 fast_bputfield(3), 0xD5 fast_zputfield(3),
        //   0xD6 fast_cputfield(3), 0xD7 fast_dputfield(3), 0xD8 fast_fputfield(3),
        //   0xD9 fast_iputfield(3), 0xDA fast_lputfield(3), 0xDB fast_sputfield(3),
        //   0xDC fast_aload_0(1),
        //   0xDD fast_iaccess_0(4), 0xDE fast_aaccess_0(4), 0xDF fast_faccess_0(4)
        3,3,3,3,3,3,3,3,3,3,3,3,1,4,4,4,
        // 0xE0-0xEF:
        //   0xE0 fast_iload(2), 0xE1 fast_iload2(4), 0xE2 fast_icaload(3),
        //   0xE3 fast_invokevfinal(3),
        //   0xE4 fast_linearswitch(-1), 0xE5 fast_binaryswitch(-1),
        //   0xE6 fast_aldc(2), 0xE7 fast_aldc_w(3),
        //   0xE8 return_register_finalizer(1),
        //   0xE9 invokehandle(3),
        //   0xEA nofast_getfield(3), 0xEB nofast_putfield(3),
        //   0xEC nofast_aload_0(1), 0xED nofast_iload(2),
        //   0xEE shouldnotreachhere(1), 0xEF reserved(1)
        2,4,3,3,-1,-1,2,3,1,3,3,3,1,2,1,1,
        // 0xF0-0xFF: reserved, treat as 1
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    };

    // Helper: get instruction length at a given offset
    auto getInsnLength = [&](size_t off) -> int {
        uint8_t op = origBytecode[off];
        if (op == 0xAA) { // tableswitch
            int pad = (4 - ((off + 1) % 4)) % 4;
            if (off + 1 + pad + 12 > origBytecode.size()) return -1;
            int32_t lo, hi;
            memcpy(&lo, &origBytecode[off + 1 + pad + 4], 4); lo = _byteswap_ulong(lo);
            memcpy(&hi, &origBytecode[off + 1 + pad + 8], 4); hi = _byteswap_ulong(hi);
            return 1 + pad + 12 + (hi - lo + 1) * 4;
        }
        if (op == 0xAB || op == 0xE4 || op == 0xE5) {
            // lookupswitch (0xAB), fast_linearswitch (0xE4), fast_binaryswitch (0xE5)
            // — fast_*switch are HotSpot rewrites of lookupswitch, same layout
            int pad = (4 - ((off + 1) % 4)) % 4;
            if (off + 1 + pad + 8 > origBytecode.size()) return -1;
            int32_t npairs;
            memcpy(&npairs, &origBytecode[off + 1 + pad + 4], 4); npairs = _byteswap_ulong(npairs);
            return 1 + pad + 8 + npairs * 8;
        }
        if (op == 0xC4) { // wide
            if (off + 1 >= origBytecode.size()) return -1;
            uint8_t wideOp = origBytecode[off + 1];
            return (wideOp == 0x84) ? 6 : 4; // wide iinc = 6, others = 4
        }
        int len = bcLengths[op];
        return len > 0 ? len : 1;
    };

    // Helper: resolve method name from a CP cache index in bytecode (invoke instructions)
    // invoke bytecodes use native-endian CP cache indices in rewritten bytecode,
    // but in original bytecode they use big-endian CP indices.
    auto resolveInvokeMethodName = [&](size_t invokeOff) -> std::string {
        if (invokeOff + 2 >= origBytecode.size()) return "";
        // Original bytecode: big-endian CP index
        uint16_t cpIdx = ((uint16_t)origBytecode[invokeOff + 1] << 8) | origBytecode[invokeOff + 2];
        // CP entry at cpIdx is a Methodref: hi16 = class, lo16 = NameAndType
        // Read the CP slot
        int64_t cpHeaderSize_ = typeSize("ConstantPool");
        if (cpHeaderSize_ < 0) cpHeaderSize_ = 0x138;
        uint64_t cpSlotAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)cpIdx * 8;
        uint64_t methodrefSlot = 0;
        if (!readRemotePointer(proc, cpSlotAddr, &methodrefSlot)) return "";
        // NameAndType index is in the low 16 bits
        uint16_t natIdx = (uint16_t)(methodrefSlot & 0xFFFF);
        // Read NameAndType slot: hi16 = descriptor, lo16 = name
        uint64_t natSlotAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)natIdx * 8;
        uint64_t natSlot = 0;
        if (!readRemotePointer(proc, natSlotAddr, &natSlot)) return "";
        uint16_t nameIdx = (uint16_t)(natSlot & 0xFFFF);
        // Read name symbol
        uint64_t nameSymAddr = 0;
        uint64_t nameEntryAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)nameIdx * 8;
        if (!readRemotePointer(proc, nameEntryAddr, &nameSymAddr) || nameSymAddr == 0) return "";
        std::string name;
        readSymbolBody(proc, nameSymAddr, &name);
        return name;
    };

    // Helper: resolve field name from CP index (getfield/putfield/getstatic/putstatic)
    auto resolveFieldName = [&](size_t fieldOff) -> std::string {
        if (fieldOff + 2 >= origBytecode.size()) return "";
        uint16_t cpIdx = ((uint16_t)origBytecode[fieldOff + 1] << 8) | origBytecode[fieldOff + 2];
        int64_t cpHeaderSize_ = typeSize("ConstantPool");
        if (cpHeaderSize_ < 0) cpHeaderSize_ = 0x138;
        uint64_t cpSlotAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)cpIdx * 8;
        uint64_t fieldrefSlot = 0;
        if (!readRemotePointer(proc, cpSlotAddr, &fieldrefSlot)) return "";
        uint16_t natIdx = (uint16_t)(fieldrefSlot & 0xFFFF);
        uint64_t natSlotAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)natIdx * 8;
        uint64_t natSlot = 0;
        if (!readRemotePointer(proc, natSlotAddr, &natSlot)) return "";
        uint16_t nameIdx = (uint16_t)(natSlot & 0xFFFF);
        uint64_t nameSymAddr = 0;
        uint64_t nameEntryAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)nameIdx * 8;
        if (!readRemotePointer(proc, nameEntryAddr, &nameSymAddr) || nameSymAddr == 0) return "";
        std::string name;
        readSymbolBody(proc, nameSymAddr, &name);
        return name;
    };

    // Helper: resolve class name from CP index (new instruction)
    auto resolveNewClassName = [&](size_t newOff) -> std::string {
        if (newOff + 2 >= origBytecode.size()) return "";
        uint16_t cpIdx = ((uint16_t)origBytecode[newOff + 1] << 8) | origBytecode[newOff + 2];
        int64_t cpHeaderSize_ = typeSize("ConstantPool");
        if (cpHeaderSize_ < 0) cpHeaderSize_ = 0x138;
        uint64_t cpSlotAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)cpIdx * 8;
        uint64_t classSlot = 0;
        if (!readRemotePointer(proc, cpSlotAddr, &classSlot)) return "";
        // Class entry: name index in low 16 bits
        uint16_t nameIdx = (uint16_t)(classSlot & 0xFFFF);
        uint64_t nameSymAddr = 0;
        uint64_t nameEntryAddr = origConstPoolAddr + (uint64_t)cpHeaderSize_ + (uint64_t)nameIdx * 8;
        if (!readRemotePointer(proc, nameEntryAddr, &nameSymAddr) || nameSymAddr == 0) return "";
        std::string name;
        readSymbolBody(proc, nameSymAddr, &name);
        return name;
    };

    // Parse injectAt — may be "HEAD", "RETURN", or "INVOKE:methodName", "FIELD_GET:fieldName", etc.
    std::string injectType = injectAtStr;
    std::string injectTargetName;
    size_t colonPos = injectAtStr.find(':');
    if (colonPos != std::string::npos) {
        injectType = injectAtStr.substr(0, colonPos);
        injectTargetName = injectAtStr.substr(colonPos + 1);
    }

    // ---------------------------------------------------------------
    // Zero-displacement trampoline injection (§17.3 / §17.4)
    //
    // For any injection point BCI X:
    //   1. Copy BCI 0..X-1 verbatim into newBytecode.
    //   2. At BCI X, write goto_w <tail_offset> (5 bytes).
    //   3. Fill BCI X+5..K-1 with nop (K = next instruction boundary >= X+5).
    //   4. Copy BCI K..N verbatim — all BCI values preserved, no alignment shift.
    //   5. Append tail: prologue + rescued bytes (BCI X..K-1) + goto_w K (or return for RETURN).
    //
    // This guarantees tableswitch/lookupswitch padding, jump targets,
    // exception table ranges, and StackMapTable BCI entries are all untouched.
    // ---------------------------------------------------------------

    // Emit goto_w targeting an absolute BCI within newBytecode.
    // We write a placeholder offset and fix it up once we know the tail position.
    // Returns the index in newBytecode where the 4-byte signed offset lives.
    // JVM goto_w offset is big-endian; write directly via byte shifts (no byteswap needed).
    auto emitGotoW = [&](std::vector<uint8_t>& bc, int32_t offsetPlaceholder) -> size_t {
        bc.push_back(0xC8); // goto_w opcode
        size_t fixupIdx = bc.size();
        uint32_t v = (uint32_t)offsetPlaceholder;
        bc.push_back((uint8_t)(v >> 24));
        bc.push_back((uint8_t)(v >> 16));
        bc.push_back((uint8_t)(v >> 8));
        bc.push_back((uint8_t)(v));
        return fixupIdx;
    };

    // Patch a previously emitted goto_w offset.
    // fixupIdx: index of first offset byte in bc.
    // instrBCI: BCI of the goto_w instruction itself within newBytecode.
    // targetBCI: desired destination BCI within newBytecode.
    auto patchGotoW = [&](std::vector<uint8_t>& bc, size_t fixupIdx, size_t instrBCI, size_t targetBCI) {
        int32_t rel = (int32_t)targetBCI - (int32_t)instrBCI;
        uint32_t v = (uint32_t)rel;
        bc[fixupIdx + 0] = (uint8_t)(v >> 24);
        bc[fixupIdx + 1] = (uint8_t)(v >> 16);
        bc[fixupIdx + 2] = (uint8_t)(v >> 8);
        bc[fixupIdx + 3] = (uint8_t)(v);
    };

    // Find K: the first instruction boundary at or after BCI X+5.
    // Scans forward from X until we reach a boundary >= X+5.
    auto findCoverageEnd = [&](size_t x) -> size_t {
        size_t k = x;
        while (k < x + 5 && k < origBytecode.size()) {
            int len = getInsnLength(k);
            if (len <= 0) len = 1;
            k += (size_t)len;
        }
        // k is now >= x+5 and on an instruction boundary
        return k;
    };

    // Core trampoline builder for a single injection point X.
    // Writes BCI X..K-1 as goto_w+nops in newBytecode, appends tail at end.
    // Returns false on error (sets error string).
    // rescued: bytes from BCI X..K-1 to replay in tail.
    // tailReturnOp: if != 0, tail ends with this return opcode instead of goto_w K.
    auto buildTrampoline = [&](size_t x, uint8_t tailReturnOp) -> bool {
        size_t k = findCoverageEnd(x);
        if (k > origBytecode.size()) k = origBytecode.size();

        // 1. BCI 0..X-1: already copied by caller before calling us (or X==0, nothing to copy).
        // 2. At BCI X: emit goto_w with placeholder, record instrBCI.
        size_t gotoWInstrBCI = newBytecode.size(); // = X in the output stream (same as input, since 0..X-1 copied verbatim)
        size_t fixupIdx = emitGotoW(newBytecode, 0);

        // 3. Fill BCI X+5..K-1 with nop.
        for (size_t b = x + 5; b < k; b++) {
            newBytecode.push_back(0x00); // nop
        }

        // 4. BCI K..N: copy verbatim — caller is responsible for this after we return.
        //    We just record k so the caller knows where to resume copying.
        //    (We can't copy here because RETURN mode needs to scan for more return ops.)

        // 5. Record tail start position — will be filled after caller appends BCI K..N.
        //    We store fixup info and do the patch in a second pass.
        //    For simplicity: store the rescued bytes and the fixup info in captured locals,
        //    and the caller drives the tail append.

        // Collect rescued bytes (BCI X..K-1 from original).
        std::vector<uint8_t> rescued(origBytecode.begin() + x, origBytecode.begin() + k);

        // Sanity check: rescued bytes must not contain switch, wide, jsr/ret, or other
        // alignment- or context-sensitive instructions. tableswitch/lookupswitch padding
        // depends on absolute BCI and would break in the tail. Reject these for now.
        // (In practice, the coverage zone is at most ~5 bytes from the inject point, so
        // it's extremely unlikely to contain a switch.)
        for (size_t off = 0; off < rescued.size();) {
            uint8_t op = rescued[off];
            // Reject opcodes that depend on absolute BCI alignment or method-local context:
            //   0xAA tableswitch, 0xAB lookupswitch, 0xC4 wide,
            //   0xA8 jsr, 0xA9 ret, 0xC9 jsr_w,
            //   0xE4 fast_linearswitch, 0xE5 fast_binaryswitch
            if (op == 0xAA || op == 0xAB || op == 0xC4 ||
                op == 0xA8 || op == 0xA9 || op == 0xC9 ||
                op == 0xE4 || op == 0xE5) {
                setError("rescue_zone_contains_unsupported_opcode");
                return false;
            }
            int rlen = bcLengths[op];
            if (rlen <= 0) rlen = 1;
            off += (size_t)rlen;
        }

        // Copy BCI K..N verbatim.
        for (size_t b = k; b < origBytecode.size(); b++) {
            newBytecode.push_back(origBytecode[b]);
        }

        // Tail: record start BCI.
        size_t tailBCI = newBytecode.size();

        // Patch the goto_w to point to tail.
        patchGotoW(newBytecode, fixupIdx, gotoWInstrBCI, tailBCI);

        // Emit prologue.
        emitCallbackPrologue(newBytecode);

        // Record where rescued bytes will start in newBytecode (= after prologue).
        size_t rescuedStartBCI = newBytecode.size();

        // Emit rescued bytes, fixing up relative-jump offsets so they target the same
        // original BCI they used to. A jump at original BCI (x + off) with relative
        // offset R targets (x + off + R). After moving to (rescuedStartBCI + off), the
        // new relative offset must be (x + off + R) - (rescuedStartBCI + off) = x + R - rescuedStartBCI.
        // We patch the offset in-place before pushing.
        int32_t shift = (int32_t)x - (int32_t)rescuedStartBCI;
        for (size_t off = 0; off < rescued.size();) {
            uint8_t op = rescued[off];
            int rlen = bcLengths[op];
            if (rlen <= 0) rlen = 1;

            // 2-byte signed offset branches: ifeq..if_acmpne (0x99..0xA6), goto (0xA7), ifnull (0xC6), ifnonnull (0xC7)
            bool is2ByteBranch = (op >= 0x99 && op <= 0xA7) || op == 0xC6 || op == 0xC7;
            // 4-byte signed offset branches: goto_w (0xC8), jsr_w (0xC9 — already rejected above)
            bool is4ByteBranch = (op == 0xC8);

            if (is2ByteBranch && off + 2 < rescued.size()) {
                int16_t origRel = (int16_t)(((uint16_t)rescued[off + 1] << 8) | rescued[off + 2]);
                int32_t newRel = (int32_t)origRel + shift;
                // If the new offset overflows int16, we'd need to widen to goto_w.
                // For now, fail explicitly — rescued zones are tiny so this is rare.
                if (newRel > 32767 || newRel < -32768) {
                    setError("rescue_branch_offset_overflow_int16");
                    return false;
                }
                rescued[off + 1] = (uint8_t)((uint16_t)newRel >> 8);
                rescued[off + 2] = (uint8_t)((uint16_t)newRel & 0xFF);
            } else if (is4ByteBranch && off + 4 < rescued.size()) {
                int32_t origRel = (int32_t)(((uint32_t)rescued[off + 1] << 24) |
                                            ((uint32_t)rescued[off + 2] << 16) |
                                            ((uint32_t)rescued[off + 3] << 8) |
                                            ((uint32_t)rescued[off + 4]));
                int32_t newRel = origRel + shift;
                rescued[off + 1] = (uint8_t)((uint32_t)newRel >> 24);
                rescued[off + 2] = (uint8_t)((uint32_t)newRel >> 16);
                rescued[off + 3] = (uint8_t)((uint32_t)newRel >> 8);
                rescued[off + 4] = (uint8_t)((uint32_t)newRel & 0xFF);
            }

            off += (size_t)rlen;
        }

        newBytecode.insert(newBytecode.end(), rescued.begin(), rescued.end());

        if (tailReturnOp != 0) {
            // RETURN variant: tail ends with the return opcode, no jump back.
            newBytecode.push_back(tailReturnOp);
        } else {
            // Normal variant: jump back to BCI K (original instruction after coverage).
            size_t gotoBackInstrBCI = newBytecode.size();
            size_t fixupBack = emitGotoW(newBytecode, 0);
            // Target is BCI K in original == same offset in newBytecode (since 0..K-1 copied verbatim before tail).
            patchGotoW(newBytecode, fixupBack, gotoBackInstrBCI, k);
        }

        return true;
    };

    if (injectType == "HEAD") {
        // X = 0: trampoline from the very first instruction.
        // buildTrampoline copies the entire original body, so newBytecode is complete after this.
        newBytecode.reserve(origBytecode.size() + 128);
        if (!buildTrampoline(0, 0)) return 0;

    } else if (injectType == "RETURN") {
        // Single-exit trampoline: replace all return opcodes (0xAC..0xB1) with goto_w to a
        // shared tail. The tail contains prologue + one return opcode.
        // We scan the original bytecode, copy non-return instructions verbatim, and for the
        // first return op we encounter we pick the opcode. All return ops get goto_w to the
        // same tail offset (patched in a second pass).
        newBytecode.reserve(origBytecode.size() + 128);

        uint8_t returnOp = 0xB1; // default: return (void)
        std::vector<size_t> returnFixups;  // fixupIdx list
        std::vector<size_t> returnInstrBCIs; // instrBCI list

        for (size_t i = 0; i < origBytecode.size(); ) {
            uint8_t op = origBytecode[i];
            if (op >= 0xAC && op <= 0xB1) {
                returnOp = op;
                // Emit goto_w placeholder at this BCI.
                size_t instrBCI = newBytecode.size();
                size_t fixupIdx = emitGotoW(newBytecode, 0);
                returnFixups.push_back(fixupIdx);
                returnInstrBCIs.push_back(instrBCI);
                // Fill remaining bytes of the coverage window with nop.
                // A return opcode is 1 byte; goto_w is 5 bytes; need 4 nops.
                // But we must also respect instruction boundaries: find K for this return.
                size_t k = findCoverageEnd(i);
                for (size_t b = i + 5; b < k; b++) newBytecode.push_back(0x00);
                i = k;
            } else {
                int len = getInsnLength(i);
                if (len <= 0) len = 1;
                for (int j = 0; j < len; j++) newBytecode.push_back(origBytecode[i + j]);
                i += (size_t)len;
            }
        }

        // Append shared tail: prologue + return opcode.
        size_t tailBCI = newBytecode.size();
        emitCallbackPrologue(newBytecode);
        newBytecode.push_back(returnOp);

        // Patch all goto_w instructions to point to tailBCI.
        for (size_t r = 0; r < returnFixups.size(); r++) {
            patchGotoW(newBytecode, returnFixups[r], returnInstrBCIs[r], tailBCI);
        }

        FVM_LOG("RETURN trampoline: %zu return point(s) → shared tail at BCI %zu",
                returnFixups.size(), tailBCI);

    } else if (injectType == "INVOKE") {
        newBytecode.reserve(origBytecode.size() + 128);
        bool found = false;
        for (size_t i = 0; i < origBytecode.size(); ) {
            uint8_t op = origBytecode[i];
            int len = getInsnLength(i);
            if (len <= 0) len = 1;

            // invokevirtual=0xB6, invokespecial=0xB7, invokestatic=0xB8, invokeinterface=0xB9
            if (!found && op >= 0xB6 && op <= 0xB9) {
                std::string mName = resolveInvokeMethodName(i);
                if (mName == injectTargetName) {
                    FVM_LOG("INVOKE trampoline: found %s at BCI %zu", mName.c_str(), i);
                    // Copy BCI 0..i-1 (already in newBytecode from loop), then trampoline from i.
                    if (!buildTrampoline(i, 0)) return 0;
                    found = true;
                    break; // buildTrampoline already copied BCI i..N and appended tail
                }
            }

            for (int j = 0; j < len; j++) newBytecode.push_back(origBytecode[i + j]);
            i += (size_t)len;
        }
        if (!found) { setError("invoke_target_not_found:" + injectTargetName); return 0; }

    } else if (injectType == "FIELD_GET") {
        newBytecode.reserve(origBytecode.size() + 128);
        bool found = false;
        for (size_t i = 0; i < origBytecode.size(); ) {
            uint8_t op = origBytecode[i];
            int len = getInsnLength(i);
            if (len <= 0) len = 1;

            // getfield=0xB4, getstatic=0xB2
            if (!found && (op == 0xB4 || op == 0xB2)) {
                std::string fName = resolveFieldName(i);
                if (fName == injectTargetName) {
                    FVM_LOG("FIELD_GET trampoline: found %s at BCI %zu", fName.c_str(), i);
                    if (!buildTrampoline(i, 0)) return 0;
                    found = true;
                    break;
                }
            }

            for (int j = 0; j < len; j++) newBytecode.push_back(origBytecode[i + j]);
            i += (size_t)len;
        }
        if (!found) { setError("field_get_target_not_found:" + injectTargetName); return 0; }

    } else if (injectType == "FIELD_PUT") {
        newBytecode.reserve(origBytecode.size() + 128);
        bool found = false;
        for (size_t i = 0; i < origBytecode.size(); ) {
            uint8_t op = origBytecode[i];
            int len = getInsnLength(i);
            if (len <= 0) len = 1;

            // putfield=0xB5, putstatic=0xB3
            if (!found && (op == 0xB5 || op == 0xB3)) {
                std::string fName = resolveFieldName(i);
                if (fName == injectTargetName) {
                    FVM_LOG("FIELD_PUT trampoline: found %s at BCI %zu", fName.c_str(), i);
                    if (!buildTrampoline(i, 0)) return 0;
                    found = true;
                    break;
                }
            }

            for (int j = 0; j < len; j++) newBytecode.push_back(origBytecode[i + j]);
            i += (size_t)len;
        }
        if (!found) { setError("field_put_target_not_found:" + injectTargetName); return 0; }

    } else if (injectType == "NEW") {
        std::string internalTarget = injectTargetName;
        for (char& c : internalTarget) { if (c == '.') c = '/'; }

        newBytecode.reserve(origBytecode.size() + 128);
        bool found = false;
        for (size_t i = 0; i < origBytecode.size(); ) {
            uint8_t op = origBytecode[i];
            int len = getInsnLength(i);
            if (len <= 0) len = 1;

            // new=0xBB
            if (!found && op == 0xBB) {
                std::string cName = resolveNewClassName(i);
                if (cName == internalTarget) {
                    FVM_LOG("NEW trampoline: found %s at BCI %zu", cName.c_str(), i);
                    if (!buildTrampoline(i, 0)) return 0;
                    found = true;
                    break;
                }
            }

            for (int j = 0; j < len; j++) newBytecode.push_back(origBytecode[i + j]);
            i += (size_t)len;
        }
        if (!found) { setError("new_target_not_found:" + internalTarget); return 0; }

    } else {
        setError("unknown_inject_point:" + injectAtStr);
        return 0;
    }

    FVM_LOG("new bytecode built: %zu bytes (orig %u, delta +%zu)",
            newBytecode.size(), codeSize, newBytecode.size() - codeSize);


    // 13. Build new ConstMethod with updated bytecode
    // Read entire original ConstMethod
    int64_t constMethodTypeSize = typeSize("ConstMethod");
    if (constMethodTypeSize < 0) {
        setError("cannot_determine_ConstMethod_size");
        return 0;
    }

    size_t origTotalConstMethodSize = (size_t)constMethodTypeSize + codeSize;
    // There may be additional data after bytecode (exception table, etc.)
    // Read _constMethod_size if available, otherwise estimate
    int64_t cmSizeOff = structOffset("ConstMethod", "_constMethod_size");
    if (cmSizeOff >= 0) {
        int32_t cmFullSize = 0;
        readRemoteI32(proc, origConstMethodAddr + (uint64_t)cmSizeOff, &cmFullSize);
        if (cmFullSize > 0) {
            // _constMethod_size is in words (8 bytes each)
            origTotalConstMethodSize = (size_t)cmFullSize * 8;
        }
    }

    // New ConstMethod total size: header + new bytecode + any trailing data
    size_t trailingDataSize = 0;
    if (origTotalConstMethodSize > (size_t)constMethodTypeSize + codeSize) {
        trailingDataSize = origTotalConstMethodSize - (size_t)constMethodTypeSize - codeSize;
    }
    size_t newConstMethodSize = (size_t)constMethodTypeSize + newBytecode.size() + trailingDataSize;
    // Align to 8
    newConstMethodSize = (newConstMethodSize + 7) & ~7;

    // Read original ConstMethod fully
    std::vector<uint8_t> origConstMethodBytes(origTotalConstMethodSize);
    if (!readRemoteMem(proc, origConstMethodAddr, origConstMethodBytes.data(), origTotalConstMethodSize)) {
        setError("cannot_read_full_constmethod");
        return 0;
    }

    // Build new ConstMethod
    std::vector<uint8_t> newConstMethodBytes(newConstMethodSize, 0);
    // Copy header
    memcpy(newConstMethodBytes.data(), origConstMethodBytes.data(), (size_t)constMethodTypeSize);
    // Write new bytecode
    memcpy(newConstMethodBytes.data() + constMethodTypeSize, newBytecode.data(), newBytecode.size());
    // Copy trailing data (exception tables, etc.)
    if (trailingDataSize > 0) {
        memcpy(newConstMethodBytes.data() + constMethodTypeSize + newBytecode.size(),
               origConstMethodBytes.data() + constMethodTypeSize + codeSize,
               trailingDataSize);
    }

    // Update _code_size in new ConstMethod
    int64_t codeSizeOff = structOffset("ConstMethod", "_code_size");
    if (codeSizeOff >= 0) {
        uint16_t newCodeSize = (uint16_t)newBytecode.size();
        memcpy(newConstMethodBytes.data() + codeSizeOff, &newCodeSize, 2);
    }

    // Update _max_stack: our prologue needs stack slots for FvmCallback + args array construction.
    // Without args: peak 4 (cbU, cbU, inst, null → init consumed).
    // With args:    peak 7 during aastore (cbU, cbU, inst, arr, arr, idx, val).
    int64_t maxStackOff = structOffset("ConstMethod", "_max_stack");
    if (maxStackOff >= 0) {
        uint16_t origMaxStack = 0;
        memcpy(&origMaxStack, newConstMethodBytes.data() + maxStackOff, 2);
        uint16_t needed = (hasArgCapture && !targetParams.empty()) ? 7 : 4;
        if (origMaxStack < needed) {
            FVM_LOG("max_stack: %u -> %u (bumped)", origMaxStack, needed);
            memcpy(newConstMethodBytes.data() + maxStackOff, &needed, 2);
        } else {
            FVM_LOG("max_stack: %u (unchanged)", origMaxStack);
        }
    }

    // Update _constMethod_size if present
    if (cmSizeOff >= 0) {
        int32_t newCmWords = (int32_t)((newConstMethodSize + 7) / 8);
        memcpy(newConstMethodBytes.data() + cmSizeOff, &newCmWords, 4);
    }

    // 14. Allocate and write new ConstantPool + Cache + ConstMethod in target process
    FVM_LOG("ConstMethod sizes: origTotal=%zu, newTotal=%zu (hdr=%lld, bc=%zu, trailing=%zu)",
            origTotalConstMethodSize, newConstMethodSize,
            (long long)constMethodTypeSize, newBytecode.size(), trailingDataSize);

    uint64_t newPoolAddr = (uint64_t)VirtualAllocEx(proc, NULL, newPoolByteSize,
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (newPoolAddr == 0) {
        setError("VirtualAllocEx_failed_for_constpool");
        return 0;
    }

    uint64_t newConstMethodAlloc = (uint64_t)VirtualAllocEx(proc, NULL, newConstMethodSize,
                                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (newConstMethodAlloc == 0) {
        VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
        setError("VirtualAllocEx_failed_for_constmethod");
        return 0;
    }
    FVM_LOG("allocated in target: newPool=0x%llX (%zu bytes), newConstMethod=0x%llX (%zu bytes)",
            (unsigned long long)newPoolAddr, newPoolByteSize,
            (unsigned long long)newConstMethodAlloc, newConstMethodSize);

    // Update _constants pointer in new ConstMethod to point to new pool
    if (cmConstsOff >= 0) {
        memcpy(newConstMethodBytes.data() + cmConstsOff, &newPoolAddr, 8);
    }

    // ConstantPoolCache write is DEFERRED to after suspendTargetThreads. The prefix
    // [0, origCacheSize) must be snapshotted from origCache while threads are frozen
    // to avoid torn reads of in-flight lazy-resolve writes (which manifested as
    // corrupt receiver oops at invokeinterface, e.g. hs_err_pid64432.log).
    // See "snapshot CPCache (post-suspend)" block below.

    // Write new ConstantPool
    if (!writeRemoteMem(proc, newPoolAddr, newPoolBytes.data(), newPoolByteSize)) {
        setError("write_new_constpool_failed");
        VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
        VirtualFreeEx(proc, (LPVOID)newConstMethodAlloc, 0, MEM_RELEASE);
        return 0;
    }

    // Write new ConstMethod
    if (!writeRemoteMem(proc, newConstMethodAlloc, newConstMethodBytes.data(), newConstMethodSize)) {
        setError("write_new_constmethod_failed");
        VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
        VirtualFreeEx(proc, (LPVOID)newConstMethodAlloc, 0, MEM_RELEASE);
        return 0;
    }

    // §17.5 Phase A: read all class methods for the per-class CM._constants sweep.
    std::vector<uint64_t> allClassMethods;
    if (klassAddr != 0) {
        int64_t methodsOff = structOffset("InstanceKlass", "_methods");
        if (methodsOff >= 0) {
            uint64_t mArr = 0;
            readRemotePointer(proc, klassAddr + (uint64_t)methodsOff, &mArr);
            if (mArr != 0) {
                int64_t arrLenOff = structOffset("Array<int>", "_length");
                if (arrLenOff < 0) arrLenOff = 0;
                int64_t arrDataOff = structOffset("Array<int>", "_data");
                if (arrDataOff < 0) arrDataOff = arrLenOff + 4;
                if (arrDataOff < 8) arrDataOff = 8;
                int32_t mc = 0;
                readRemoteI32(proc, mArr + (uint64_t)arrLenOff, &mc);
                if (mc > 0 && mc < 10000) {
                    allClassMethods.resize(mc);
                    readRemoteMem(proc, mArr + (uint64_t)arrDataOff, allClassMethods.data(), mc * 8);
                }
            }
        }
    }
    FVM_LOG("allClassMethods: %zu method(s) in class", allClassMethods.size());

    // 12. Suspend all threads, swap pointers, clear JIT code, resume
    FVM_LOG("suspending target threads (pid=%lu)...", (unsigned long)g_target.pid);
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("suspended %zu threads", threadIds.size());

    // Snapshot CPCache (post-suspend) — race-free copy of origCache prefix into
    // newCacheBytes, then write the assembled cache to remote. The pre-resolved
    // tail entries (1277-1280) were already filled into newCacheBytes earlier;
    // memcpy of prefix [0, origCacheSize) does NOT overwrite them.
    if (newCacheAddr != 0 && !newCacheBytes.empty() && origCacheAddr != 0) {
        std::vector<uint8_t> origCacheBytes(origCacheSize);
        if (!readRemoteMem(proc, origCacheAddr, origCacheBytes.data(), origCacheSize)) {
            FVM_LOG("ERROR: post-suspend readRemoteMem(origCache) failed");
            resumeTargetThreads(threadIds);
            setError("read_orig_cache_failed");
            VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newConstMethodAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newCacheAddr, 0, MEM_RELEASE);
            return 0;
        }
        memcpy(newCacheBytes.data(), origCacheBytes.data(), origCacheSize);
        // Restore fields that the prefix copy overwrote.
        memcpy(newCacheBytes.data() + cacheLenOff, &newCacheLen, 4);
        if (cacheCpOff >= 0) {
            memcpy(newCacheBytes.data() + cacheCpOff, &newPoolAddr, 8);
        }
        if (!writeRemoteMem(proc, newCacheAddr, newCacheBytes.data(), newCacheBytes.size())) {
            FVM_LOG("ERROR: post-suspend writeRemoteMem(newCache) failed");
            resumeTargetThreads(threadIds);
            setError("write_new_cache_failed");
            VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newConstMethodAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newCacheAddr, 0, MEM_RELEASE);
            return 0;
        }
        FVM_LOG("CPCache snapshot+write done post-suspend (origCacheSize=%zu, newSize=%zu)",
                origCacheSize, newCacheBytes.size());
    }

    // §17.5 Phase C — per-class commit (threads are suspended above).

    int64_t codeOff  = structOffset("Method", "_code");
    int64_t mdoOff   = structOffset("Method", "_method_data");
    int64_t mctrOff  = structOffset("Method", "_method_counters");

    // Step 6: Capture all class method backups on first patch (before any writes).
    if (!hasPlan && klassAddr != 0) {
        ClassTransformPlan& plan = g_plans[klassAddr];
        plan.className = std::string(className);
        plan.klassAddr = klassAddr;
        plan.oldCPAddr = origConstPoolAddr;
        for (uint64_t mAddr : allClassMethods) {
            if (mAddr == 0) continue;
            MethodCMBackup b;
            b.methodAddr = mAddr;
            uint64_t cm = 0;
            readRemotePointer(proc, mAddr + (uint64_t)constMethodOff, &cm);
            b.origConstMethodAddr = cm;
            uint64_t csts = 0;
            if (cm != 0) readRemotePointer(proc, cm + (uint64_t)cmConstsOff, &csts);
            b.origConstantsPtr = csts;
            plan.methodBackups.push_back(b);
        }
        FVM_LOG("Phase C: captured %zu method backups (first patch)", plan.methodBackups.size());
    }

    // Step 7a: Update all unpatched class methods' CM._constants → newPoolAddr.
    FVM_LOG("Phase C: updating all class CM._constants -> newPool=0x%llX", (unsigned long long)newPoolAddr);
    for (uint64_t mAddr : allClassMethods) {
        if (mAddr == 0 || mAddr == methodAddr) continue;
        uint64_t cm = 0;
        if (!readRemotePointer(proc, mAddr + (uint64_t)constMethodOff, &cm) || cm == 0) continue;
        writeRemoteMem(proc, cm + (uint64_t)cmConstsOff, &newPoolAddr, 8);
    }

    // Step 7b: Swap patched method's _constMethod → newCM, clear _code/_method_data/_method_counters.
    FVM_LOG("Phase C: swap patched method _constMethod 0x%llX -> 0x%llX",
            (unsigned long long)origConstMethodAddr, (unsigned long long)newConstMethodAlloc);
    writeRemoteMem(proc, methodAddr + (uint64_t)constMethodOff, &newConstMethodAlloc, 8);
    if (codeOff >= 0) {
        uint64_t zero = 0;
        writeRemoteMem(proc, methodAddr + (uint64_t)codeOff, &zero, 8);
    }
    clearMethodProfilingState(methodAddr, /*setDontInline=*/true, "TRANSFORM");

    // Step 7c: Commit barrier — update InstanceKlass._constants → newPoolAddr.
    if (klassAddr != 0) {
        int64_t ikConstsOff = structOffset("InstanceKlass", "_constants");
        if (ikConstsOff < 0) {
            // Scan first 256 bytes of InstanceKlass for the known-previous CP address.
            uint64_t expectedCP = hasPlan ? g_plans[klassAddr].newCPAddr : origConstPoolAddr;
            std::vector<uint8_t> ikHdr(256, 0);
            if (readRemoteMem(proc, klassAddr, ikHdr.data(), 256)) {
                for (int off = 0; off + 8 <= 256; off += 8) {
                    uint64_t v = 0; memcpy(&v, ikHdr.data() + off, 8);
                    if (v == expectedCP) { ikConstsOff = off; break; }
                }
            }
            if (ikConstsOff >= 0)
                FVM_LOG("Phase C: found InstanceKlass._constants via scan @offset %lld", (long long)ikConstsOff);
        }
        if (ikConstsOff >= 0) {
            writeRemoteMem(proc, klassAddr + (uint64_t)ikConstsOff, &newPoolAddr, 8);
            FVM_LOG("Phase C: committed InstanceKlass._constants=0x%llX (barrier)", (unsigned long long)newPoolAddr);
        } else {
            FVM_LOG("WARN: cannot find InstanceKlass._constants offset, skipping barrier");
        }
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("resumed %zu threads", threadIds.size());

    // §17.5 Phase C: update plan record.
    // (Per §17.7: no VirtualFreeEx — in-flight frames may still reference old allocations.)
    {
        ClassTransformPlan& plan = g_plans[klassAddr];
        plan.newCPAddr      = newPoolAddr;
        plan.newCPCacheAddr = newCacheAddr;
        plan.newRKAddr      = newRKAddr;
        PatchedMethodInfo pmi;
        pmi.methodAddr = methodAddr;
        pmi.newCMAddr  = newConstMethodAlloc;
        pmi.hook = HookSpec{ std::string(hookClass), std::string(hookMethod),
                             std::string(hookDesc), std::string(injectAt) };
        plan.patchedMethods.push_back(pmi);
        FVM_LOG("Plan updated: %zu patched method(s) in class %s",
                plan.patchedMethods.size(), className);
    }

    // 14. Force deoptimization of ALL compiled methods (unless caller defers it
    //     for batch transforms — then deopt happens once at end of batch).
    if (deferDeopt) {
        FVM_LOG("deferring global deoptimization sweep (batch mode)");
    } else {
        FVM_LOG("starting global deoptimization sweep (force JIT to pick up new bytecodes)...");
        forceDeoptimizeAll();
    }

    // 15. Readback verification: confirm the swap is intact after deopt sweep
    {
        uint64_t readbackCM = 0;
        if (readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &readbackCM)) {
            if (readbackCM == newConstMethodAlloc) {
                FVM_LOG("VERIFY: Method::_constMethod = 0x%llX (OK, matches new)",
                        (unsigned long long)readbackCM);
            } else {
                FVM_LOG("VERIFY FAIL: Method::_constMethod = 0x%llX, expected 0x%llX",
                        (unsigned long long)readbackCM, (unsigned long long)newConstMethodAlloc);
            }
        }
        // Read first 8 bytes of bytecodes from new ConstMethod
        uint8_t bcCheck[8] = {0};
        if (readRemoteMem(proc, newConstMethodAlloc + (uint64_t)constMethodTypeSize, bcCheck, 8)) {
            FVM_LOG("VERIFY bytecodes at ConstMethod+%lld: %02X %02X %02X %02X %02X %02X %02X %02X (expect BB 13 A6 59 2A B7 ...)",
                    (long long)constMethodTypeSize,
                    bcCheck[0], bcCheck[1], bcCheck[2], bcCheck[3],
                    bcCheck[4], bcCheck[5], bcCheck[6], bcCheck[7]);
        }
        // Read _constants pointer from new ConstMethod
        int64_t cmcOff = structOffset("ConstMethod", "_constants");
        if (cmcOff >= 0) {
            uint64_t readbackCP = 0;
            if (readRemotePointer(proc, newConstMethodAlloc + (uint64_t)cmcOff, &readbackCP)) {
                FVM_LOG("VERIFY: ConstMethod::_constants = 0x%llX (expected newPool=0x%llX) %s",
                        (unsigned long long)readbackCP, (unsigned long long)newPoolAddr,
                        readbackCP == newPoolAddr ? "OK" : "MISMATCH!");
            }
        }
    }

    FVM_LOG("=== TRANSFORM SUCCESS: %s ===", key.c_str());
    setError("ok");
    return 1;
}

// ============================================================
// Restore original method
// ============================================================

int restoreTransform(const char* className, const char* methodName, const char* paramDesc) {
    HANDLE proc = g_target.handle;

    FVM_LOG("=== RESTORE BEGIN: %s.%s(%s) ===", className, methodName, paramDesc);

    // Resolve klassAddr from class name.
    std::string clsInternal = std::string(className);
    for (char& c : clsInternal) { if (c == '.') c = '/'; }
    uint64_t klassAddr = 0;
    if (!findInstanceKlassByName(clsInternal, &klassAddr) || klassAddr == 0) {
        setError("restore_class_not_found:" + clsInternal);
        return 0;
    }

    auto it = g_plans.find(klassAddr);
    if (it == g_plans.end()) {
        setError("not_transformed:" + clsInternal);
        return 0;
    }

    ClassTransformPlan& plan = it->second;
    FVM_LOG("RESTORE: plan has %zu patched method(s), %zu total backups",
            plan.patchedMethods.size(), plan.methodBackups.size());

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;
    int64_t codeOff  = structOffset("Method", "_code");
    int64_t mdoOff   = structOffset("Method", "_method_data");
    int64_t mctrOff  = structOffset("Method", "_method_counters");

    // Suspend threads.
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("suspended %zu threads for restore", threadIds.size());

    // §17.7 Unload: restore in reverse commit order.

    // Step 1: Commit barrier — restore InstanceKlass._constants → plan.oldCPAddr.
    {
        int64_t ikConstsOff = structOffset("InstanceKlass", "_constants");
        if (ikConstsOff < 0) {
            // Scan first 256 bytes of InstanceKlass for the last-committed newCPAddr.
            std::vector<uint8_t> ikHdr(256, 0);
            if (readRemoteMem(proc, klassAddr, ikHdr.data(), 256)) {
                for (int off = 0; off + 8 <= 256; off += 8) {
                    uint64_t v = 0; memcpy(&v, ikHdr.data() + off, 8);
                    if (v == plan.newCPAddr) { ikConstsOff = off; break; }
                }
            }
            if (ikConstsOff >= 0)
                FVM_LOG("RESTORE: found InstanceKlass._constants via scan @offset %lld", (long long)ikConstsOff);
        }
        if (ikConstsOff >= 0) {
            writeRemoteMem(proc, klassAddr + (uint64_t)ikConstsOff, &plan.oldCPAddr, 8);
            FVM_LOG("RESTORE: InstanceKlass._constants -> oldCP=0x%llX (barrier)", (unsigned long long)plan.oldCPAddr);
        } else {
            FVM_LOG("WARN: cannot find InstanceKlass._constants offset, skipping barrier");
        }
    }

    // Step 2: Restore all class methods from backups.
    for (const MethodCMBackup& b : plan.methodBackups) {
        if (b.methodAddr == 0) continue;
        // Restore _constMethod pointer.
        if (b.origConstMethodAddr != 0) {
            writeRemoteMem(proc, b.methodAddr + (uint64_t)constMethodOff, &b.origConstMethodAddr, 8);
        }
        // Restore CM._constants pointer in the original ConstMethod.
        if (b.origConstMethodAddr != 0 && b.origConstantsPtr != 0) {
            writeRemoteMem(proc, b.origConstMethodAddr + (uint64_t)cmConstsOff, &b.origConstantsPtr, 8);
        }
    }
    FVM_LOG("RESTORE: wrote back %zu method backups", plan.methodBackups.size());

    // Step 3: For each patched method, additionally clear _code/_method_data/_method_counters.
    for (const PatchedMethodInfo& pmi : plan.patchedMethods) {
        if (pmi.methodAddr == 0) continue;
        if (codeOff >= 0) {
            uint64_t zero = 0;
            writeRemoteMem(proc, pmi.methodAddr + (uint64_t)codeOff, &zero, 8);
        }
        if (mdoOff >= 0) {
            uint64_t zero = 0;
            writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mdoOff, &zero, 8);
        }
        if (mctrOff >= 0) {
            uint64_t zero = 0;
            writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mctrOff, &zero, 8);
        }
        clearMethodProfilingState(pmi.methodAddr, /*setDontInline=*/false, "RESTORE");
        FVM_LOG("RESTORE: cleared JIT state for patched method 0x%llX", (unsigned long long)pmi.methodAddr);
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("resumed %zu threads", threadIds.size());

    // §17.7: Do NOT VirtualFreeEx — in-flight frames may still reference new allocations.
    // Process exit will reclaim them.

    g_plans.erase(it);

    FVM_LOG("starting global deoptimization sweep (restore)...");
    forceDeoptimizeAll();

    FVM_LOG("=== RESTORE SUCCESS: %s.%s(%s) ===", className, methodName, paramDesc);
    setError("ok");
    return 1;
}

// ============================================================
// Exported DLL functions
// ============================================================

// ============================================================
// Purge Agent — disable a loaded Java agent entirely
//
// 1. Find agent Klass, locate its static Instrumentation field
// 2. Read the InstrumentationImpl OOP
// 3. Null the mTransformerManager field (stops future transforms)
// 4. Null the agent's static instrumentation field
// 5. Overwrite agentmain/premain bytecode with bare return (0xB1)
// ============================================================

static bool nullifyStaticField(uint64_t klassAddr, const std::string& fieldName) {
    HANDLE proc = g_target.handle;

    ResolvedField rf = {};
    // Try common descriptor for object references
    if (!resolveFieldInKlass(klassAddr, fieldName, "", &rf)) {
        return false;
    }
    if (!rf.isStatic || rf.staticAddress == 0) {
        setError("field_not_static:" + fieldName);
        return false;
    }

    // Write null (zero) to the static field
    uint64_t zero = 0;
    size_t writeSize = g_target.useCompressedOops ? 4 : 8;
    if (!writeRemoteMem(proc, rf.staticAddress, &zero, writeSize)) {
        setError("write_null_failed:" + fieldName);
        return false;
    }
    FVM_LOG("purge_agent: nullified static field '%s' at 0x%llX", fieldName.c_str(), rf.staticAddress);
    return true;
}

static bool readStaticOop(uint64_t klassAddr, const std::string& fieldName, uint64_t* outOop) {
    HANDLE proc = g_target.handle;

    ResolvedField rf = {};
    if (!resolveFieldInKlass(klassAddr, fieldName, "", &rf)) {
        return false;
    }
    if (!rf.isStatic || rf.staticAddress == 0) {
        setError("field_not_static:" + fieldName);
        return false;
    }

    *outOop = readOop(proc, rf.staticAddress, g_target.useCompressedOops);
    return (*outOop != 0);
}

static bool clearMethodBody(uint64_t klassAddr, const char* methodName) {
    HANDLE proc = g_target.handle;
    uint64_t methodAddr = 0;
    // Try to find the method — empty paramDesc matches any signature
    if (!findMethodInKlass(klassAddr, methodName, "", &methodAddr) || methodAddr == 0) {
        FVM_LOG("purge_agent: method '%s' not found (may not exist)", methodName);
        return false; // not an error — method may not exist in this agent
    }

    // Read ConstMethod* from Method
    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t constMethodAddr = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &constMethodAddr) || constMethodAddr == 0) {
        setError("constmethod_read_failed");
        return false;
    }

    // Read bytecode size
    uint32_t codeSize = 0;
    std::vector<uint8_t> bytecode;
    uint64_t bytecodeStart = 0;
    if (!readConstMethodBytecode(constMethodAddr, &bytecode, &bytecodeStart, &codeSize)) {
        setError("bytecode_read_failed");
        return false;
    }

    if (codeSize == 0 || bytecodeStart == 0) {
        setError("bytecode_empty");
        return false;
    }

    // Write a single 'return' (0xB1) at the start, fill rest with nop (0x00)
    std::vector<uint8_t> cleared(codeSize, 0x00);
    cleared[0] = 0xB1; // return void

    if (!writeRemoteMem(proc, bytecodeStart, cleared.data(), codeSize)) {
        setError("bytecode_write_failed");
        return false;
    }

    FVM_LOG("purge_agent: cleared method '%s' bytecode (%u bytes) at 0x%llX",
            methodName, codeSize, bytecodeStart);
    return true;
}

static int doPurgeAgent(const char* agentClassName) {
    HANDLE proc = g_target.handle;
    if (proc == NULL) {
        setError("no_target_process");
        return 0;
    }

    std::string internalName = std::string(agentClassName);
    for (char& c : internalName) { if (c == '.') c = '/'; }

    FVM_LOG("=== PURGE AGENT: %s ===", internalName.c_str());

    // Step 1: Find the agent Klass
    uint64_t agentKlass = 0;
    if (!findInstanceKlassByName(internalName, &agentKlass)) {
        setError("agent_class_not_found:" + internalName);
        return 0;
    }
    FVM_LOG("purge_agent: found agent Klass at 0x%llX", agentKlass);

    // Step 2: Suspend all threads for safe memory writes
    std::vector<DWORD> threads;
    suspendTargetThreads(g_target.pid, threads);

    bool success = true;
    int steps = 0;

    // Step 3: Read the static Instrumentation field OOP from the agent class
    // Common field names used by Java agents for their Instrumentation reference
    static const char* instFieldNames[] = {
        "instrumentation", "inst", "INST", "INSTRUMENTATION",
        "sInstrumentation", "sInst", nullptr
    };

    uint64_t instOop = 0;
    const char* foundFieldName = nullptr;
    for (int i = 0; instFieldNames[i] != nullptr; i++) {
        if (readStaticOop(agentKlass, instFieldNames[i], &instOop)) {
            foundFieldName = instFieldNames[i];
            FVM_LOG("purge_agent: found Instrumentation OOP=0x%llX in field '%s'",
                    instOop, foundFieldName);
            break;
        }
    }

    // Step 4: If we found an Instrumentation OOP, null the TransformerManager inside it
    if (instOop != 0 && foundFieldName != nullptr) {
        // Read the Klass of the InstrumentationImpl object
        int64_t oopKlassOff = 0; // object header offset for klass
        uint64_t instKlass = readKlass(proc, instOop + oopKlassOff,
                                        g_target.useCompressedClassPointers);

        if (instKlass != 0) {
            FVM_LOG("purge_agent: InstrumentationImpl Klass at 0x%llX", instKlass);

            // Null the mTransformerManager field
            ResolvedField tmField = {};
            if (resolveFieldInKlass(instKlass, "mTransformerManager", "", &tmField)) {
                if (!tmField.isStatic && tmField.offset > 0) {
                    uint64_t tmAddr = instOop + tmField.offset;
                    uint64_t zero = 0;
                    size_t writeSize = g_target.useCompressedOops ? 4 : 8;
                    if (writeRemoteMem(proc, tmAddr, &zero, writeSize)) {
                        FVM_LOG("purge_agent: nullified mTransformerManager at OOP+%d", tmField.offset);
                        steps++;
                    }
                }
            }

            // Also null mRetransfomerManager (yes, JDK has this typo in some versions)
            ResolvedField rtmField = {};
            if (resolveFieldInKlass(instKlass, "mRetransfomerManager", "", &rtmField)) {
                if (!rtmField.isStatic && rtmField.offset > 0) {
                    uint64_t rtmAddr = instOop + rtmField.offset;
                    uint64_t zero = 0;
                    size_t writeSize = g_target.useCompressedOops ? 4 : 8;
                    if (writeRemoteMem(proc, rtmAddr, &zero, writeSize)) {
                        FVM_LOG("purge_agent: nullified mRetransfomerManager at OOP+%d", rtmField.offset);
                        steps++;
                    }
                }
            }
        }

        // Step 5: Null the agent's static instrumentation field
        if (nullifyStaticField(agentKlass, foundFieldName)) {
            steps++;
        }
    } else {
        FVM_LOG("purge_agent: no Instrumentation field found — skipping Instrumentation cleanup");
    }

    // Step 6: Clear agentmain and premain method bodies
    if (clearMethodBody(agentKlass, "agentmain")) steps++;
    if (clearMethodBody(agentKlass, "premain")) steps++;

    // Resume threads
    resumeTargetThreads(threads);

    // Force deoptimization so JIT-compiled code picks up the changes
    FVM_LOG("purge_agent: starting deoptimization sweep...");
    forceDeoptimizeAll();

    if (steps > 0) {
        FVM_LOG("=== PURGE AGENT SUCCESS: %s (%d steps) ===", internalName.c_str(), steps);
        setError("ok");
        return 1;
    } else {
        FVM_LOG("=== PURGE AGENT: no operations succeeded for %s ===", internalName.c_str());
        setError("no_operations_succeeded");
        return 0;
    }
}

extern "C" __declspec(dllexport) int forgevm_purge_agent(const char* agentClassName) {
    return doPurgeAgent(agentClassName);
}

extern "C" __declspec(dllexport) int forgevm_transform_load(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc) {
    return applyTransform(className, methodName, paramDesc, injectAt,
                          hookClass, hookMethod, hookDesc, false);
}

// Same as forgevm_transform_load, but skips the global deopt sweep.
// Caller is responsible for invoking forgevm_force_deopt_now() once after a batch.
extern "C" __declspec(dllexport) int forgevm_transform_load_v2(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc, int deferDeopt) {
    return applyTransform(className, methodName, paramDesc, injectAt,
                          hookClass, hookMethod, hookDesc, deferDeopt != 0);
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

extern "C" __declspec(dllexport) int forgevm_transform_unload(
    const char* className, const char* methodName, const char* paramDesc) {
    return restoreTransform(className, methodName, paramDesc);
}

// ============================================================
// Subclass-aware forge: find all subclasses and apply transform
// ============================================================

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

    int64_t cldNextOff = structOffset("ClassLoaderData", "_next");
    if (cldNextOff < 0) cldNextOff = 8;
    int64_t cldKlassesOff = structOffset("ClassLoaderData", "_klasses");
    if (cldKlassesOff < 0) cldKlassesOff = 16;
    int64_t klassNextOff = structOffset("Klass", "_next_link");
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

static int forgeLoadSubclassesImpl(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc, bool deferDeopt) {

    // First, apply to the target class itself (always defer per-call, since we
    // also need to transform subclasses; one global deopt covers everything).
    int result = applyTransform(className, methodName, paramDesc, injectAt,
                                hookClass, hookMethod, hookDesc, true);

    // Find the target Klass
    std::string internalName = toInternalName(className);
    uint64_t targetKlassAddr = 0;
    if (!findInstanceKlassByName(internalName, &targetKlassAddr)) {
        FVM_LOG("forge_subclasses: target class not found, skipping subclass scan");
        return result;
    }

    // Find and forge all subclasses
    std::vector<uint64_t> subclasses = findAllSubclasses(targetKlassAddr);
    FVM_LOG("forge_subclasses: found %zu subclasses of %s", subclasses.size(), className);

    int forgedCount = result == 1 ? 1 : 0;
    for (uint64_t subKlass : subclasses) {
        // Read subclass name
        std::string subName;
        if (!readKlassName(g_target.handle, subKlass, &subName)) continue;

        // Check if this subclass has the target method (i.e., overrides it)
        uint64_t subMethodAddr = 0;
        if (!findMethodInKlass(subKlass, methodName, paramDesc, &subMethodAddr)) {
            continue; // no override, parent's forged method applies via vtable
        }

        // Convert internal name back to dot-separated for applyTransform
        std::string dotName = subName;
        for (char& c : dotName) { if (c == '/') c = '.'; }

        FVM_LOG("forge_subclasses: forging override in %s", dotName.c_str());
        int subResult = applyTransform(dotName.c_str(), methodName, paramDesc,
                                        injectAt, hookClass, hookMethod, hookDesc, true);
        if (subResult == 1) forgedCount++;
    }

    FVM_LOG("forge_subclasses: total forged = %d (target + %d subclasses)", forgedCount, forgedCount - (result == 1 ? 1 : 0));

    // Single deopt sweep covers target + all subclasses (and any callers)
    if (!deferDeopt) {
        FVM_LOG("forge_subclasses: running global deopt sweep for batch");
        forceDeoptimizeAll();
    }

    if (forgedCount > 0) {
        setError("ok");
        return 1;
    }
    return result;
}

extern "C" __declspec(dllexport) int forgevm_forge_load_subclasses(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc) {
    return forgeLoadSubclassesImpl(className, methodName, paramDesc, injectAt,
                                    hookClass, hookMethod, hookDesc, false);
}

// Same as forgevm_forge_load_subclasses but skips the final deopt sweep.
extern "C" __declspec(dllexport) int forgevm_forge_load_subclasses_v2(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc, int deferDeopt) {
    return forgeLoadSubclassesImpl(className, methodName, paramDesc, injectAt,
                                    hookClass, hookMethod, hookDesc, deferDeopt != 0);
}

extern "C" __declspec(dllexport) int forgevm_forge_unload_subclasses(
    const char* className, const char* methodName, const char* paramDesc) {

    // Restore the target class
    int result = restoreTransform(className, methodName, paramDesc);

    // Find the target Klass
    std::string internalName = toInternalName(className);
    uint64_t targetKlassAddr = 0;
    if (!findInstanceKlassByName(internalName, &targetKlassAddr)) {
        return result;
    }

    // Restore all subclasses
    std::vector<uint64_t> subclasses = findAllSubclasses(targetKlassAddr);
    for (uint64_t subKlass : subclasses) {
        std::string subName;
        if (!readKlassName(g_target.handle, subKlass, &subName)) continue;

        std::string dotName = subName;
        for (char& c : dotName) { if (c == '/') c = '.'; }

        restoreTransform(dotName.c_str(), methodName, paramDesc);
    }

    setError("ok");
    return 1;
}

// ============================================================
// §17 Per-class plan-once-commit-once API
//
// commitClassPlan / unloadClassPlan implement the per-class transform model
// described in CLAUDE.md §17. Every commit on a class first rolls back any
// existing plan to oldCP, then replays the full hook set (existing + new)
// in a single batch. This guarantees:
//
//   * Every method in the class shares a CP whose contents are consistent
//     with every other patched method's bytecode (class-coherence).
//   * Re-commit never accumulates stale cross-layer references (the §17.14.5
//     root cause): we always start from oldCP.
//   * Class-level rollback is one atomic restore operation.
//
// Implementation note: this Stage-3.0 implementation reuses applyTransform
// per hook within commitClassPlan (one applyTransform call per active hook).
// Each applyTransform internally performs the §17.5 Phase A→C steps
// (allocate, suspend, leaf-then-root swap, resume) and §17.10 ("oldCP not
// freed"). Stage 3.1 may further consolidate the per-hook allocations into
// a single merged newCP for memory-efficiency, but the class-coherence
// guarantees and crash safety are already provided here.
// ============================================================

// Read a Method*'s declared name (e.g. "tick") and full signature (e.g. "(F)V").
// Used to replay an existing plan's hooks: when commitClassPlan re-commits an
// existing patched method, we recover the method's identity from its Method*
// (which is stable until class unload).
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

// Internal class-level rollback (§17.7). Reverts the plan for klassAddr
// atomically: suspend → write back InstanceKlass._constants → write back each
// method's _constMethod and CM._constants → resume → forceDeoptimizeAll.
// Does not touch g_plans for OTHER klasses. Returns true on success, false
// if no plan exists for this klass.
static bool unloadClassPlanForKlass(uint64_t klassAddr) {
    HANDLE proc = g_target.handle;

    auto it = g_plans.find(klassAddr);
    if (it == g_plans.end()) return false;

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

    // Step 3: clear JIT state on patched methods.
    for (const PatchedMethodInfo& pmi : plan.patchedMethods) {
        if (pmi.methodAddr == 0) continue;
        uint64_t zero = 0;
        if (codeOff >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)codeOff, &zero, 8);
        if (mdoOff  >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mdoOff,  &zero, 8);
        if (mctrOff >= 0) writeRemoteMem(proc, pmi.methodAddr + (uint64_t)mctrOff, &zero, 8);
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("UNLOAD_CLASS_PLAN: resumed %zu threads", threadIds.size());

    // §17.10: do NOT VirtualFreeEx newCP/newCPCache/newRK/newCM allocations.
    // Mid-frame execution may still reference them; process exit reclaims.

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

// Re-apply a single hook to a klass via applyTransform. The className passed
// to applyTransform must match the *runtime* klass we're targeting, since
// applyTransform looks up klass + method by name. For subclass replay we
// translate the subclass's internal name back to dot form.
static bool applyOneHookToKlass(uint64_t klassAddr,
                                const std::string& methodName,
                                const std::string& paramDesc,
                                const HookSpecExtended& spec,
                                bool deferDeopt) {
    std::string internal;
    if (!readKlassName(g_target.handle, klassAddr, &internal)) return false;
    std::string dotName = internal;
    for (char& c : dotName) { if (c == '/') c = '.'; }

    int r = applyTransform(dotName.c_str(), methodName.c_str(), paramDesc.c_str(),
                           spec.injectAt.c_str(),
                           spec.hookClass.c_str(),
                           spec.hookMethod.c_str(),
                           spec.hookDesc.c_str(),
                           deferDeopt);
    return r == 1;
}

// Replay every existing hook in a class plan via applyTransform. Each method's
// (name, paramDesc) is re-derived from the Method*'s metadata, since g_plans
// stores the patched Method* but not the original (name, desc) strings.
static int replayExistingPlan(uint64_t klassAddr,
                              const std::vector<PatchedMethodInfo>& patches) {
    int replayed = 0;
    for (const PatchedMethodInfo& pmi : patches) {
        std::string mName, mSig;
        if (!readMethodNameAndSig(pmi.methodAddr, &mName, &mSig)) {
            FVM_LOG("CLASS_PLAN replay: cannot read name/sig for Method*=0x%llX, skipping",
                    (unsigned long long)pmi.methodAddr);
            continue;
        }
        // applyTransform's paramDesc match accepts either the params-only "(...)"
        // prefix or the full signature; pass the full sig for an exact match.
        HookSpecExtended ext;
        ext.hookClass  = pmi.hook.hookClass;
        ext.hookMethod = pmi.hook.hookMethod;
        ext.hookDesc   = pmi.hook.hookDesc;
        ext.injectAt   = pmi.hook.injectAt;

        if (applyOneHookToKlass(klassAddr, mName, mSig, ext, /*deferDeopt=*/true)) {
            replayed++;
        } else {
            FVM_LOG("CLASS_PLAN replay: applyTransform FAILED for %s%s reason=%s",
                    mName.c_str(), mSig.c_str(), g_lastError.c_str());
        }
    }
    return replayed;
}

// Apply one new hook (with candidates) to a class — tries candidates in order,
// returns the matched one in `out`. Returns true on match.
static bool applyHookWithCandidates(uint64_t klassAddr,
                                    const HookSpecExtended& spec,
                                    bool deferDeopt,
                                    HookOutcome* out) {
    out->reason = spec.candidates.empty() ? "no_candidates" : "method_not_found";
    for (const HookCandidate& cand : spec.candidates) {
        if (applyOneHookToKlass(klassAddr, cand.methodName, cand.paramDesc, spec, deferDeopt)) {
            out->matched    = true;
            out->methodName = cand.methodName;
            out->paramDesc  = cand.paramDesc;
            // Recover methodAddr from the plan we just appended to.
            auto it = g_plans.find(klassAddr);
            if (it != g_plans.end() && !it->second.patchedMethods.empty()) {
                out->methodAddr = it->second.patchedMethods.back().methodAddr;
            }
            return true;
        }
        if (!g_lastError.empty()) out->reason = g_lastError;
    }
    return false;
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

    FVM_LOG("=== CLASS_PLAN BEGIN: %s (klass=0x%llX, +%zu new hook(s), subs=%d) ===",
            internal.c_str(), (unsigned long long)klassAddr,
            additionalHooks.size(), (int)includeSubclasses);

    // Phase 1: capture existing patches per klass (target + optional subclasses),
    // then unload them so the next commit starts from each klass's oldCP.
    struct SavedPlan {
        uint64_t klass;
        std::vector<PatchedMethodInfo> patches;
    };
    std::vector<SavedPlan> saved;

    auto stash = [&](uint64_t k) {
        auto it = g_plans.find(k);
        if (it != g_plans.end()) {
            SavedPlan sp;
            sp.klass = k;
            sp.patches = it->second.patchedMethods;   // copy so unload erases safely
            saved.push_back(std::move(sp));
        }
    };
    stash(klassAddr);

    std::vector<uint64_t> subKlasses;
    if (includeSubclasses) {
        subKlasses = findAllSubclasses(klassAddr);
        for (uint64_t s : subKlasses) stash(s);
    }

    if (!saved.empty()) {
        FVM_LOG("CLASS_PLAN: stashing %zu existing plan(s) for re-commit", saved.size());
        for (auto& sp : saved) unloadClassPlanForKlass(sp.klass);
    }

    // Phase 2: replay all stashed (existing) hooks on each klass with deferDeopt=true.
    for (auto& sp : saved) {
        replayExistingPlan(sp.klass, sp.patches);
    }

    // Phase 3: apply new hooks with deferDeopt=true. Each hook is a separate
    // applyTransform call that internally suspends/swaps/resumes (small window
    // per call) and updates IK._constants + every class method's CM._constants.
    if (outResults) outResults->resize(additionalHooks.size());

    for (size_t i = 0; i < additionalHooks.size(); i++) {
        const HookSpecExtended& spec = additionalHooks[i];
        HookOutcome& out = outResults ? (*outResults)[i] : *(new HookOutcome);

        bool matchedAny = false;

        // Target class first.
        if (applyHookWithCandidates(klassAddr, spec, /*deferDeopt=*/true, &out)) {
            matchedAny = true;
        }

        // If includeSubclasses, also apply to every subclass that DECLARES (overrides)
        // the matched method. Subclass overrides have their own Method*; we patch
        // each individually so the per-subclass nmethod gets retransformed too.
        if (includeSubclasses && matchedAny) {
            for (uint64_t s : subKlasses) {
                uint64_t subMethodAddr = 0;
                if (findMethodInKlass(s, out.methodName.c_str(), out.paramDesc.c_str(),
                                      &subMethodAddr)) {
                    applyOneHookToKlass(s, out.methodName, out.paramDesc, spec, /*deferDeopt=*/true);
                }
            }
        }

        if (!matchedAny) {
            // applyHookWithCandidates already populated out.reason from g_lastError.
            FVM_LOG("CLASS_PLAN: hook[%zu] NO MATCH (%s.%s%s) reason=%s",
                    i, spec.hookClass.c_str(), spec.hookMethod.c_str(),
                    spec.hookDesc.c_str(), out.reason.c_str());
        }
    }

    // Phase 4: single global deopt sweep at the end of the batch.
    if (!deferDeopt) {
        FVM_LOG("CLASS_PLAN: running single deopt sweep at end of batch");
        forceDeoptimizeAll();
    }

    FVM_LOG("=== CLASS_PLAN END: %s ===", internal.c_str());
    setError("ok");
    return 1;
}

// ============================================================
// Exports for the per-class plan API
// ============================================================

namespace {

// Tiny single-pass JSON helpers used to decode the hooksJson array passed in
// via the DLL ABI. JSON is well-formed (emitted by the Agent) so we can rely
// on simple "key":"value" / "key":bool searches without a real parser.

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

// Find the next outer JSON object [start..end) inside arr, returning its bounds
// in [outStart, outEnd]. Returns false when no more objects.
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

// Public DLL export: per-class plan-once-commit-once.
//
// hooksJson format:
//   [{"hookClass":"...","hookMethod":"...","hookDesc":"...",
//     "injectAt":"...",
//     "candidates":[{"methodName":"...","paramDesc":"..."}, ...]}, ...]
//
// resultJsonBuf receives a JSON array (same length / order as input):
//   [{"matched":true,"methodName":"...","paramDesc":"..."}, ...]
// or {"matched":false,"reason":"..."} per entry.
//
// Returns 1 on commit success, 0 on commit failure (e.g. class not found).
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
