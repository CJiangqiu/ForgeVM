#include "forgevm_internal.h"

#include <tlhelp32.h>
#include <algorithm>

// ============================================================
// Global transform state
// ============================================================

std::unordered_map<std::string, TransformBackup> g_transformBackups;

static std::string makeTransformKey(const char* className, const char* methodName, const char* paramDesc) {
    return std::string(className) + "#" + methodName + "#" + paramDesc;
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
static bool findInstanceKlassByName(const std::string& internalName, uint64_t* outKlassAddr) {
    HANDLE proc = g_target.handle;

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
    if (cmNameOff < 0) {
        // ConstMethod stores name index into constant pool, not a direct pointer
        // We need to read the name from the constant pool
        // For now, try _name field first
    }

    int64_t cmSignatureOff = structOffset("ConstMethod", "_signature");

    std::string targetName(methodName);

    for (int i = 0; i < methodCount; i++) {
        uint64_t methodAddr = methodPtrs[i];
        if (methodAddr == 0) continue;

        // Method -> ConstMethod
        uint64_t constMethodAddr = 0;
        if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &constMethodAddr) || constMethodAddr == 0) {
            continue;
        }

        // Try reading method name
        std::string mName;
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

        // If direct name not found, try via ConstantPool
        if (!nameFound) {
            // ConstMethod has _constants (ConstantPool*) and name_index/signature_index
            int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
            if (cmConstsOff < 0) cmConstsOff = 8;

            uint64_t constPoolAddr = 0;
            if (!readRemotePointer(proc, constMethodAddr + (uint64_t)cmConstsOff, &constPoolAddr) || constPoolAddr == 0) {
                continue;
            }

            // ConstMethod has _name_index (u2) and _signature_index (u2)
            // These are typically after the fixed fields
            int64_t nameIdxOff = structOffset("ConstMethod", "_name_index");
            int64_t sigIdxOff = structOffset("ConstMethod", "_signature_index");

            if (nameIdxOff < 0 || sigIdxOff < 0) {
                // Common layout: _name_index and _signature_index are u2 fields
                // Their exact position depends on JDK version
                // Skip this method if we can't find them
                continue;
            }

            uint16_t nameIndex = 0, sigIndex = 0;
            if (!readRemoteU16(proc, constMethodAddr + (uint64_t)nameIdxOff, &nameIndex)) continue;
            if (!readRemoteU16(proc, constMethodAddr + (uint64_t)sigIdxOff, &sigIndex)) continue;

            // Read from ConstantPool: each entry is a pointer at offset (header + index * 8)
            int64_t cpHeaderSize = typeSize("ConstantPool");
            if (cpHeaderSize < 0) cpHeaderSize = 0x138; // typical

            // ConstantPool entries are at: cpAddr + headerSize + index * sizeof(intptr_t)
            uint64_t nameEntryAddr = constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)nameIndex * 8;
            uint64_t nameSymbol = 0;
            if (!readRemotePointer(proc, nameEntryAddr, &nameSymbol) || nameSymbol == 0) continue;

            if (!readSymbolBody(proc, nameSymbol, &mName)) continue;
            nameFound = true;

            // Also read signature for param matching
            if (paramDesc != nullptr && paramDesc[0] != '\0') {
                uint64_t sigEntryAddr = constPoolAddr + (uint64_t)cpHeaderSize + (uint64_t)sigIndex * 8;
                uint64_t sigSymbol = 0;
                if (readRemotePointer(proc, sigEntryAddr, &sigSymbol) && sigSymbol != 0) {
                    std::string sig;
                    if (readSymbolBody(proc, sigSymbol, &sig)) {
                        // paramDesc is like "()" or "(I)" — match against the params part of signature
                        if (sig.find(paramDesc) != 0 && sig != paramDesc) {
                            // Signature doesn't match params
                            continue;
                        }
                    }
                }
            }
        }

        if (nameFound && mName == targetName) {
            *outMethodAddr = methodAddr;
            return true;
        }
    }

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

// Allocate a HotSpot Symbol in target process memory (ONLY for symbols not already interned)
static uint64_t allocateSymbolInTarget(const std::string& str) {
    HANDLE proc = g_target.handle;

    // JDK 17 Symbol layout:
    //   offset 0: _hash_and_refcount (u4) — bits 0-15 = refcount, bits 16-31 = hash
    //   offset 4: _length (u2)
    //   offset 6: _body[0] (u1[])  — VMStructs names it "_body[0]"
    // Total: 6 bytes header + body length

    // Resolve _length offset from VMStructs (should be 4)
    int64_t lenOff = structOffset("Symbol", "_length");
    if (lenOff < 0) lenOff = 4;

    // Resolve _body offset: VMStructs names it "_body[0]", not "_body"
    int64_t bodyOff = structOffset("Symbol", "_body[0]");
    if (bodyOff < 0) bodyOff = structOffset("Symbol", "_body");
    if (bodyOff < 0) bodyOff = lenOff + 2;  // body always follows _length (u2)

    size_t totalSize = (size_t)bodyOff + str.size() + 1; // +1 for safety
    // Align to 8
    totalSize = (totalSize + 7) & ~7;

    uint64_t addr = (uint64_t)VirtualAllocEx(proc, NULL, totalSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (addr == 0) return 0;

    // Write the symbol data
    std::vector<uint8_t> symData(totalSize, 0);

    // _hash_and_refcount at offset 0: set refcount=0x7FFF (prevent GC), hash=0
    // In JDK 17, _refcount is not a separate field — it's packed into _hash_and_refcount
    int64_t hashRefOff = structOffset("Symbol", "_hash_and_refcount");
    if (hashRefOff < 0) hashRefOff = 0;
    uint32_t hashAndRef = 0x7FFF; // low 16 bits = refcount, high 16 bits = hash (0)
    memcpy(symData.data() + hashRefOff, &hashAndRef, 4);

    // _length
    uint16_t len16 = (uint16_t)str.size();
    memcpy(symData.data() + lenOff, &len16, 2);

    // _body
    memcpy(symData.data() + bodyOff, str.c_str(), str.size());

    FVM_LOG("allocateSymbol: \"%s\" len=%u bodyOff=%lld totalSize=%zu addr=0x%llX",
            str.c_str(), (unsigned)str.size(), (long long)bodyOff, totalSize, addr);

    if (!writeRemoteMem(proc, addr, symData.data(), totalSize)) {
        VirtualFreeEx(proc, (LPVOID)addr, 0, MEM_RELEASE);
        return 0;
    }

    return addr;
}

// ============================================================
// Apply transform
// ============================================================

int applyTransform(const char* className, const char* methodName, const char* paramDesc,
                   const char* injectAt, const char* hookClass, const char* hookMethod,
                   const char* hookDesc) {
    HANDLE proc = g_target.handle;
    std::string key = makeTransformKey(className, methodName, paramDesc);

    FVM_LOG("=== TRANSFORM BEGIN ===");
    FVM_LOG("target: %s.%s(%s) @ %s", className, methodName, paramDesc, injectAt);
    FVM_LOG("hook:   %s.%s%s", hookClass, hookMethod, hookDesc);

    // Check if already transformed
    if (g_transformBackups.find(key) != g_transformBackups.end()) {
        setError("already_transformed:" + key);
        return 0;
    }

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
    FVM_LOG_HEX("orig bytecode", origBytecode.data(), origBytecode.size());

    // 5. Read original constant pool
    std::vector<uint8_t> origPoolBytes;
    uint32_t poolLength = 0;
    size_t poolByteSize = 0;
    if (!readConstantPool(origConstPoolAddr, &origPoolBytes, &poolLength, &poolByteSize)) {
        FVM_LOG("TRANSFORM FAILED: cannot read constpool");
        return 0;
    }
    FVM_LOG("original constpool: length=%u, byteSize=%zu", poolLength, poolByteSize);

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

    // 7. Read target method's return type from its signature descriptor
    std::string targetReturnDesc = "V"; // default void
    {
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
                        size_t closeParen = fullSig.find(')');
                        if (closeParen != std::string::npos && closeParen + 1 < fullSig.size()) {
                            targetReturnDesc = fullSig.substr(closeParen + 1);
                        }
                    }
                }
            }
        }
    }

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
    if (!findInstanceKlassByName("forgevm/transform/FvmCallback", &cbKlassAddr)) {
        setError("FvmCallback_class_not_loaded"); return 0;
    }
    uint64_t cbInitMethodAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "<init>", "(Ljava/lang/Object;)V", &cbInitMethodAddr)) {
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
    int numNewClasses = unbox.needsUnbox ? 3 : 2;
    int hookClassRKIdx = 0, cbClassRKIdx = 0, unboxClassRKIdx = 0;
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
            if (unbox.needsUnbox) unboxClassRKIdx = origRKLen + 2;

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
    //   [If unbox]: P+20..P+22 Utf8, P+23 Class, P+24 NameAndType, P+25 Methodref
    //
    // HotSpot extract helpers:
    //   extract_low_short(val)  = val & 0xFFFF        (low 16 bits)
    //   extract_high_short(val) = (val >> 16) & 0xFFFF (high 16 bits)

    uint32_t baseEntries = 20;
    uint32_t unboxEntries = unbox.needsUnbox ? 6 : 0;
    uint32_t totalNewEntries = baseEntries + unboxEntries;
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
    // HotSpot: klass_slot_at() → high=name_index, low=resolved_klass_index
    newSlots[P+10] = (uint64_t)(((uint32_t)(P+0) << 16) | (uint32_t)hookClassRKIdx);
    newSlots[P+11] = (uint64_t)(((uint32_t)(P+3) << 16) | (uint32_t)cbClassRKIdx);

    // NameAndType entries (tag=12): slot = (desc_idx << 16) | name_idx
    // HotSpot: name_ref_index_at() = extract_low_short = name_idx
    //          signature_ref_index_at() = extract_high_short = desc_idx
    newSlots[P+12] = (uint64_t)(((uint32_t)(P+2) << 16) | (uint32_t)(P+1));   // hookDesc<<16 | hookMethod
    newSlots[P+13] = (uint64_t)(((uint32_t)(P+5) << 16) | (uint32_t)(P+4));   // (Object)V<<16 | <init>
    newSlots[P+14] = (uint64_t)(((uint32_t)(P+7) << 16) | (uint32_t)(P+6));   // ()Z<<16 | isCancelled
    newSlots[P+15] = (uint64_t)(((uint32_t)(P+9) << 16) | (uint32_t)(P+8));   // ()Object<<16 | getReturnValue

    // Methodref entries (tag=10): slot = (nat_idx << 16) | class_idx
    // HotSpot: klass_ref_index_at() = extract_low_short = class_idx
    //          name_and_type_ref_index_at() = extract_high_short = nat_idx
    newSlots[P+16] = (uint64_t)(((uint32_t)(P+12) << 16) | (uint32_t)(P+10)); // hook invokestatic
    newSlots[P+17] = (uint64_t)(((uint32_t)(P+13) << 16) | (uint32_t)(P+11)); // FvmCallback.<init>
    newSlots[P+18] = (uint64_t)(((uint32_t)(P+14) << 16) | (uint32_t)(P+11)); // FvmCallback.isCancelled
    newSlots[P+19] = (uint64_t)(((uint32_t)(P+15) << 16) | (uint32_t)(P+11)); // FvmCallback.getReturnValue

    if (unbox.needsUnbox) {
        newSlots[P+20] = symUnboxClass;
        newSlots[P+21] = symUnboxMethod;
        newSlots[P+22] = symUnboxDesc;
        // Class: (name_idx << 16) | resolved_klass_idx
        newSlots[P+23] = (uint64_t)(((uint32_t)(P+20) << 16) | (uint32_t)unboxClassRKIdx);
        // NameAndType: (desc_idx << 16) | name_idx
        newSlots[P+24] = (uint64_t)(((uint32_t)(P+22) << 16) | (uint32_t)(P+21));
        // Methodref: (nat_idx << 16) | class_idx
        newSlots[P+25] = (uint64_t)(((uint32_t)(P+24) << 16) | (uint32_t)(P+23));
    }

    FVM_LOG("new CP entries (P=%u, newPoolLength=%u):", P, newPoolLength);
    FVM_LOG("  Class[P+10]=0x%llX Class[P+11]=0x%llX", (unsigned long long)newSlots[P+10], (unsigned long long)newSlots[P+11]);
    FVM_LOG("  NAT[P+12]=0x%llX NAT[P+13]=0x%llX NAT[P+14]=0x%llX NAT[P+15]=0x%llX",
            (unsigned long long)newSlots[P+12], (unsigned long long)newSlots[P+13],
            (unsigned long long)newSlots[P+14], (unsigned long long)newSlots[P+15]);
    FVM_LOG("  MRef[P+16]=0x%llX MRef[P+17]=0x%llX MRef[P+18]=0x%llX MRef[P+19]=0x%llX",
            (unsigned long long)newSlots[P+16], (unsigned long long)newSlots[P+17],
            (unsigned long long)newSlots[P+18], (unsigned long long)newSlots[P+19]);

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
                for (int i = 0; i < 10; i++) td[P+i] = 1;   // Utf8
                td[P+10] = 7;  td[P+11] = 7;                 // Class (pre-resolved)
                td[P+12] = 12; td[P+13] = 12; td[P+14] = 12; td[P+15] = 12; // NameAndType
                td[P+16] = 10; td[P+17] = 10; td[P+18] = 10; td[P+19] = 10; // Methodref

                if (unbox.needsUnbox) {
                    td[P+20] = 1;  td[P+21] = 1;  td[P+22] = 1;  // Utf8
                    td[P+23] = 7;  // Class
                    td[P+24] = 12; // NameAndType
                    td[P+25] = 10; // Methodref
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

    if (cacheOff >= 0) {
        uint64_t origCacheAddr = 0;
        memcpy(&origCacheAddr, origPoolBytes.data() + cacheOff, 8);

        if (origCacheAddr != 0) {
            int64_t cacheHdrSize = typeSize("ConstantPoolCache");
            if (cacheHdrSize < 0) cacheHdrSize = 16;
            int64_t cacheLenOff = structOffset("ConstantPoolCache", "_length");
            if (cacheLenOff < 0) cacheLenOff = 0;
            int64_t cacheEntrySize = typeSize("ConstantPoolCacheEntry");
            if (cacheEntrySize < 0) cacheEntrySize = 32;
            cacheCpOff = structOffset("ConstantPoolCache", "_constant_pool");
            if (cacheCpOff < 0) cacheCpOff = 8;

            readRemoteI32(proc, origCacheAddr + (uint64_t)cacheLenOff, &origCacheLen);

            hookCacheIdx   = origCacheLen;
            initCacheIdx   = origCacheLen + 1;
            cancelCacheIdx = origCacheLen + 2;
            retValCacheIdx = origCacheLen + 3;
            if (unbox.needsUnbox) unboxCacheIdx = origCacheLen + 4;

            int32_t newCacheLen = origCacheLen + numNewCacheEntries;
            size_t origCacheSize = (size_t)cacheHdrSize + origCacheLen * cacheEntrySize;
            size_t newCacheSize  = (size_t)cacheHdrSize + newCacheLen * cacheEntrySize;

            std::vector<uint8_t> origCacheBytes(origCacheSize);
            readRemoteMem(proc, origCacheAddr, origCacheBytes.data(), origCacheSize);

            newCacheBytes.resize(newCacheSize, 0);
            memcpy(newCacheBytes.data(), origCacheBytes.data(), origCacheSize);
            memcpy(newCacheBytes.data() + cacheLenOff, &newCacheLen, 4);

            // Initialize new cache entries: _indices = CP index of Methodref
            int64_t indicesFieldOff = structOffset("ConstantPoolCacheEntry", "_indices");
            if (indicesFieldOff < 0) indicesFieldOff = 0;

            int cpIdxTable[] = { (int)(P+16), (int)(P+17), (int)(P+18), (int)(P+19), (int)(P+25) };
            for (int i = 0; i < numNewCacheEntries; i++) {
                uint8_t* entry = newCacheBytes.data() + cacheHdrSize + (origCacheLen + i) * cacheEntrySize;
                int32_t cpIdx = cpIdxTable[i];
                memcpy(entry + indicesFieldOff, &cpIdx, 4);
            }

            newCacheAddr = (uint64_t)VirtualAllocEx(proc, NULL, newCacheSize,
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (newCacheAddr == 0) { setError("VirtualAllocEx_cache_failed"); return 0; }

            // Update new pool's _cache pointer (will fix cache's back-pointer after pool allocation)
            memcpy(newPoolBytes.data() + cacheOff, &newCacheAddr, 8);

            FVM_LOG("CPCache: origLen=%d, newLen=%d, entrySize=%lld, newAddr=0x%llX",
                    origCacheLen, newCacheLen, (long long)cacheEntrySize, (unsigned long long)newCacheAddr);
            for (int i = 0; i < numNewCacheEntries; i++) {
                FVM_LOG("  cache[%d] -> _indices CP idx = %d", origCacheLen + i, cpIdxTable[i]);
            }
        }
    }

    // 12. Build new bytecode
    //
    // IMPORTANT: invoke operands = CP CACHE indices (not CP indices)
    //            new/checkcast operands = CP indices
    uint16_t cbClassCpIdx     = (uint16_t)(P + 11);           // FvmCallback class (for 'new')
    uint16_t hookCacheIdx16   = (uint16_t)hookCacheIdx;        // invokestatic hook
    uint16_t initCacheIdx16   = (uint16_t)initCacheIdx;        // invokespecial <init>
    uint16_t cancelCacheIdx16 = (uint16_t)cancelCacheIdx;      // invokevirtual isCancelled
    uint16_t retValCacheIdx16 = (uint16_t)retValCacheIdx;      // invokevirtual getReturnValue
    uint16_t unboxClassCpIdx  = unbox.needsUnbox ? (uint16_t)(P + 23) : 0; // wrapper Class (for checkcast)
    uint16_t unboxCacheIdx16  = unbox.needsUnbox ? (uint16_t)unboxCacheIdx : 0;

    FVM_LOG("bytecode operand indices:");
    FVM_LOG("  new FvmCallback CP idx = %u (big-endian)", (unsigned)cbClassCpIdx);
    FVM_LOG("  invokespecial <init>     cache idx = %u (native-endian)", (unsigned)initCacheIdx16);
    FVM_LOG("  invokestatic hook        cache idx = %u (native-endian)", (unsigned)hookCacheIdx16);
    FVM_LOG("  invokevirtual isCancelled cache idx = %u (native-endian)", (unsigned)cancelCacheIdx16);
    FVM_LOG("  invokevirtual getRetVal   cache idx = %u (native-endian)", (unsigned)retValCacheIdx16);
    if (unbox.needsUnbox) {
        FVM_LOG("  checkcast unbox CP idx = %u, invokevirtual unbox cache idx = %u",
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
        // invokevirtual getReturnValue (cache index, native byte order) → [Object]
        cancelReturn.push_back(0xB6);
        cancelReturn.push_back((uint8_t)(retValCacheIdx16 & 0xFF));
        cancelReturn.push_back((uint8_t)((retValCacheIdx16 >> 8) & 0xFF));

        if (unbox.needsUnbox) {
            // checkcast WrapperClass (CP index, big-endian) → [WrapperClass]
            cancelReturn.push_back(0xC0);
            cancelReturn.push_back((uint8_t)(unboxClassCpIdx >> 8));
            cancelReturn.push_back((uint8_t)(unboxClassCpIdx & 0xFF));
            // invokevirtual unboxMethod (cache index, native byte order) → [primitive]
            cancelReturn.push_back(0xB6);
            cancelReturn.push_back((uint8_t)(unboxCacheIdx16 & 0xFF));
            cancelReturn.push_back((uint8_t)((unboxCacheIdx16 >> 8) & 0xFF));
        }

        cancelReturn.push_back(unbox.returnOp);
    }

    int16_t ifeqOffset = (int16_t)(3 + (int)cancelReturn.size());

    std::vector<uint8_t> newBytecode;
    std::string injectAtStr(injectAt);

    auto emitCallbackPrologue = [&](std::vector<uint8_t>& bc) {
        // Stack trace:
        bc.push_back(0xBB); emitIdx(bc, cbClassCpIdx);           // new FvmCallback (CP idx, big-endian) → [cbU]
        bc.push_back(0x59);                                        // dup → [cbU, cbU]
        bc.push_back(0x2A);                                        // aload_0 → [cbU, cbU, this]
        bc.push_back(0xB7); emitNativeIdx(bc, initCacheIdx16);    // invokespecial <init> (cache idx, native) → [cb]
        bc.push_back(0x59);                                        // dup → [cb, cb]
        bc.push_back(0x59);                                        // dup → [cb, cb, cb]
        bc.push_back(0xB8); emitNativeIdx(bc, hookCacheIdx16);    // invokestatic hook (cache idx, native) → [cb, cb]
        bc.push_back(0xB6); emitNativeIdx(bc, cancelCacheIdx16);  // invokevirtual isCancelled (cache idx, native) → [cb, int]
        bc.push_back(0x99);                                        // ifeq (branch offset, big-endian)
        bc.push_back((uint8_t)(ifeqOffset >> 8));
        bc.push_back((uint8_t)(ifeqOffset & 0xFF));
        // Cancel branch: stack = [cb]
        bc.insert(bc.end(), cancelReturn.begin(), cancelReturn.end());
        // CONTINUE: stack = [cb], pop it
        bc.push_back(0x57); // pop → []
    };

    if (injectAtStr == "HEAD") {
        newBytecode.reserve(origBytecode.size() + 50);
        emitCallbackPrologue(newBytecode);
        newBytecode.insert(newBytecode.end(), origBytecode.begin(), origBytecode.end());
    } else if (injectAtStr == "RETURN") {
        newBytecode.reserve(origBytecode.size() + 50);
        for (size_t i = 0; i < origBytecode.size(); i++) {
            uint8_t op = origBytecode[i];
            if (op >= 0xAC && op <= 0xB1) {
                emitCallbackPrologue(newBytecode);
            }
            newBytecode.push_back(op);
        }
    } else {
        setError("unknown_inject_point:" + injectAtStr);
        return 0;
    }

    FVM_LOG("new bytecode built: %zu bytes (orig %u, delta +%zu)",
            newBytecode.size(), codeSize, newBytecode.size() - codeSize);
    FVM_LOG_HEX("new bytecode", newBytecode.data(), newBytecode.size());

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

    // Update _max_stack: our prologue needs at least 4 stack slots
    // (new, dup, dup, dup = 3 copies + this = 4 max depth)
    // Ensure max_stack >= max(original, 4)
    int64_t maxStackOff = structOffset("ConstMethod", "_max_stack");
    if (maxStackOff >= 0) {
        uint16_t origMaxStack = 0;
        memcpy(&origMaxStack, newConstMethodBytes.data() + maxStackOff, 2);
        uint16_t needed = 4; // our prologue peak: [cb, cb, cb, this]
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

    // Write ConstantPoolCache (with back-pointer fixed to new pool)
    if (newCacheAddr != 0 && !newCacheBytes.empty()) {
        if (cacheCpOff >= 0) {
            memcpy(newCacheBytes.data() + cacheCpOff, &newPoolAddr, 8);
        }
        if (!writeRemoteMem(proc, newCacheAddr, newCacheBytes.data(), newCacheBytes.size())) {
            setError("write_new_cache_failed");
            VirtualFreeEx(proc, (LPVOID)newPoolAddr, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newConstMethodAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(proc, (LPVOID)newCacheAddr, 0, MEM_RELEASE);
            return 0;
        }
    }

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

    // 12. Suspend all threads, swap pointers, clear JIT code, resume
    FVM_LOG("suspending target threads (pid=%lu)...", (unsigned long)g_target.pid);
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("suspended %zu threads", threadIds.size());

    // Swap Method::_constMethod to point to new ConstMethod
    FVM_LOG("SWAP: Method[0x%llX]+%lld = 0x%llX -> 0x%llX",
            (unsigned long long)methodAddr, (long long)constMethodOff,
            (unsigned long long)origConstMethodAddr, (unsigned long long)newConstMethodAlloc);
    writeRemoteMem(proc, methodAddr + (uint64_t)constMethodOff, &newConstMethodAlloc, 8);

    // Clear Method::_code to force deoptimization (interpreter will use new bytecode)
    int64_t codeOff = structOffset("Method", "_code");
    if (codeOff >= 0) {
        uint64_t nullCode = 0;
        writeRemoteMem(proc, methodAddr + (uint64_t)codeOff, &nullCode, 8);
        FVM_LOG("cleared Method::_code (offset %lld)", (long long)codeOff);
    }

    // Clear Method::_from_compiled_entry and _from_interpreted_entry to force re-resolution
    int64_t fromCompiledOff = structOffset("Method", "_from_compiled_entry");
    int64_t fromInterpOff = structOffset("Method", "_from_interpreted_entry");
    if (fromCompiledOff >= 0) {
        uint64_t zero = 0;
        writeRemoteMem(proc, methodAddr + (uint64_t)fromCompiledOff, &zero, 8);
        FVM_LOG("cleared Method::_from_compiled_entry (offset %lld)", (long long)fromCompiledOff);
    }
    // Note: _from_interpreted_entry should point to the interpreter entry stub
    // Zeroing it may cause issues; the interpreter will re-resolve it on next call
    // For safety, we leave _from_interpreted_entry alone — clearing _code is sufficient
    // to force the JVM to re-enter the interpreter path.

    resumeTargetThreads(threadIds);
    FVM_LOG("resumed %zu threads", threadIds.size());

    // 13. Save backup for restore
    TransformBackup backup;
    backup.key = key;
    backup.methodAddr = methodAddr;
    backup.origConstMethodAddr = origConstMethodAddr;
    backup.origConstPoolAddr = origConstPoolAddr;
    backup.allocatedConstMethod = newConstMethodAlloc;
    backup.allocatedConstPool = newPoolAddr;
    backup.allocatedCache = newCacheAddr;
    backup.allocatedResolvedKlasses = newRKAddr;
    backup.allocatedConstMethodSize = newConstMethodSize;
    backup.allocatedConstPoolSize = newPoolByteSize;
    g_transformBackups[key] = backup;

    FVM_LOG("=== TRANSFORM SUCCESS: %s ===", key.c_str());
    setError("ok");
    return 1;
}

// ============================================================
// Restore original method
// ============================================================

int restoreTransform(const char* className, const char* methodName, const char* paramDesc) {
    HANDLE proc = g_target.handle;
    std::string key = makeTransformKey(className, methodName, paramDesc);

    FVM_LOG("=== RESTORE BEGIN: %s ===", key.c_str());

    auto it = g_transformBackups.find(key);
    if (it == g_transformBackups.end()) {
        setError("not_transformed:" + key);
        return 0;
    }

    TransformBackup& backup = it->second;

    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    // Suspend threads
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);
    FVM_LOG("suspended %zu threads for restore", threadIds.size());

    // Restore original ConstMethod pointer
    FVM_LOG("RESTORE: Method[0x%llX]+%lld = 0x%llX -> 0x%llX (original)",
            (unsigned long long)backup.methodAddr, (long long)constMethodOff,
            (unsigned long long)backup.allocatedConstMethod, (unsigned long long)backup.origConstMethodAddr);
    writeRemoteMem(proc, backup.methodAddr + (uint64_t)constMethodOff, &backup.origConstMethodAddr, 8);

    // Clear JIT code again
    int64_t codeOff = structOffset("Method", "_code");
    if (codeOff >= 0) {
        uint64_t nullCode = 0;
        writeRemoteMem(proc, backup.methodAddr + (uint64_t)codeOff, &nullCode, 8);
    }

    int64_t fromCompiledOff = structOffset("Method", "_from_compiled_entry");
    if (fromCompiledOff >= 0) {
        uint64_t zero = 0;
        writeRemoteMem(proc, backup.methodAddr + (uint64_t)fromCompiledOff, &zero, 8);
    }

    resumeTargetThreads(threadIds);
    FVM_LOG("resumed %zu threads", threadIds.size());

    // Free allocated memory
    if (backup.allocatedConstMethod != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedConstMethod, 0, MEM_RELEASE);
    }
    if (backup.allocatedConstPool != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedConstPool, 0, MEM_RELEASE);
    }
    if (backup.allocatedCache != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedCache, 0, MEM_RELEASE);
    }
    if (backup.allocatedResolvedKlasses != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedResolvedKlasses, 0, MEM_RELEASE);
    }
    FVM_LOG("freed allocated memory (constMethod/constPool/cache/resolvedKlasses)");

    g_transformBackups.erase(it);

    FVM_LOG("=== RESTORE SUCCESS: %s ===", key.c_str());
    setError("ok");
    return 1;
}

// ============================================================
// Exported DLL functions
// ============================================================

extern "C" __declspec(dllexport) int forgevm_transform_load(
    const char* className, const char* methodName, const char* paramDesc,
    const char* injectAt, const char* hookClass, const char* hookMethod,
    const char* hookDesc) {
    return applyTransform(className, methodName, paramDesc, injectAt,
                          hookClass, hookMethod, hookDesc);
}

extern "C" __declspec(dllexport) int forgevm_transform_unload(
    const char* className, const char* methodName, const char* paramDesc) {
    return restoreTransform(className, methodName, paramDesc);
}
