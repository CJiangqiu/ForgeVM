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

// ============================================================
// Thread suspend/resume (reuse existing infrastructure)
// ============================================================

bool suspendTargetThreads(DWORD pid, std::vector<DWORD>& threadIds) {
    threadIds.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread != NULL) {
                    SuspendThread(hThread);
                    threadIds.push_back(te.th32ThreadID);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return !threadIds.empty();
}

void resumeTargetThreads(const std::vector<DWORD>& threadIds) {
    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread != NULL) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
}

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
// Simpler approach: we create Symbol* for hook class/method/desc in target process,
// add them as Utf8 entries, then build Class + NameAndType + Methodref entries.
// ============================================================

// Allocate a HotSpot Symbol in target process memory
static uint64_t allocateSymbolInTarget(const std::string& str) {
    HANDLE proc = g_target.handle;

    // Symbol layout: _hash (u4), _length (u2), _refcount (u2), _body[] (char)
    // Total: 8 bytes header + body length
    // But _hash_and_refcount may be combined. Let's use structMap.

    int64_t symbolHeaderSize = typeSize("Symbol");
    if (symbolHeaderSize < 0) symbolHeaderSize = 8; // common: hash(4) + length(2) + refcount(2)

    size_t totalSize = (size_t)symbolHeaderSize + str.size() + 1; // +1 for safety
    // Align to 8
    totalSize = (totalSize + 7) & ~7;

    uint64_t addr = (uint64_t)VirtualAllocEx(proc, NULL, totalSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (addr == 0) return 0;

    // Write the symbol data
    std::vector<uint8_t> symData(totalSize, 0);

    // _length at offset 4 (after _hash which is u4)
    int64_t lenOff = structOffset("Symbol", "_length");
    if (lenOff < 0) lenOff = 4;
    uint16_t len16 = (uint16_t)str.size();
    memcpy(symData.data() + lenOff, &len16, 2);

    // _refcount - set high to prevent GC from collecting it
    int64_t refOff = structOffset("Symbol", "_refcount");
    if (refOff < 0) refOff = lenOff + 2;
    uint16_t refCount = 0x7FFF;
    memcpy(symData.data() + refOff, &refCount, 2);

    // _body starts after header
    int64_t bodyOff = structOffset("Symbol", "_body");
    if (bodyOff < 0) bodyOff = symbolHeaderSize;
    memcpy(symData.data() + bodyOff, str.c_str(), str.size());

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

    // Check if already transformed
    if (g_transformBackups.find(key) != g_transformBackups.end()) {
        setError("already_transformed:" + key);
        return 0;
    }

    // 1. Find the target Method*
    uint64_t methodAddr = 0;
    if (!findJavaMethod(className, methodName, paramDesc, &methodAddr)) {
        return 0;
    }

    // 2. Read Method -> ConstMethod*
    int64_t constMethodOff = structOffset("Method", "_constMethod");
    if (constMethodOff < 0) constMethodOff = 8;

    uint64_t origConstMethodAddr = 0;
    if (!readRemotePointer(proc, methodAddr + (uint64_t)constMethodOff, &origConstMethodAddr) || origConstMethodAddr == 0) {
        setError("cannot_read_constmethod_ptr");
        return 0;
    }

    // 3. Read ConstMethod -> ConstantPool*
    int64_t cmConstsOff = structOffset("ConstMethod", "_constants");
    if (cmConstsOff < 0) cmConstsOff = 8;

    uint64_t origConstPoolAddr = 0;
    if (!readRemotePointer(proc, origConstMethodAddr + (uint64_t)cmConstsOff, &origConstPoolAddr) || origConstPoolAddr == 0) {
        setError("cannot_read_constpool_ptr");
        return 0;
    }

    // 4. Read original bytecode
    std::vector<uint8_t> origBytecode;
    uint64_t bcStartAddr = 0;
    uint32_t codeSize = 0;
    if (!readConstMethodBytecode(origConstMethodAddr, &origBytecode, &bcStartAddr, &codeSize)) {
        return 0;
    }

    // 5. Read original constant pool
    std::vector<uint8_t> origPoolBytes;
    uint32_t poolLength = 0;
    size_t poolByteSize = 0;
    if (!readConstantPool(origConstPoolAddr, &origPoolBytes, &poolLength, &poolByteSize)) {
        return 0;
    }

    // 6. Find the hook class's InstanceKlass to verify it exists
    std::string hookClassInternal = toInternalName(hookClass);
    uint64_t hookKlassAddr = 0;
    if (!findInstanceKlassByName(hookClassInternal, &hookKlassAddr)) {
        setError("hook_class_not_loaded:" + hookClassInternal);
        return 0;
    }

    // Verify hook method exists
    uint64_t hookMethodAddr = 0;
    if (!findMethodInKlass(hookKlassAddr, hookMethod, hookDesc, &hookMethodAddr)) {
        setError("hook_method_not_found:" + std::string(hookMethod));
        return 0;
    }

    // 7. Create Symbol* for hook class, method name, and descriptor in target process
    uint64_t hookClassSymbol = allocateSymbolInTarget(hookClassInternal);
    uint64_t hookMethodSymbol = allocateSymbolInTarget(std::string(hookMethod));
    uint64_t hookDescSymbol = allocateSymbolInTarget(std::string(hookDesc));

    if (hookClassSymbol == 0 || hookMethodSymbol == 0 || hookDescSymbol == 0) {
        setError("failed_to_allocate_symbols_in_target");
        return 0;
    }

    // 8. Build expanded constant pool
    //
    // We need these additional entries for the FvmCallback flow:
    //   +0  Utf8: hookClass name (Symbol*)
    //   +1  Utf8: hookMethod name (Symbol*)
    //   +2  Utf8: hookDesc (Symbol*)
    //   +3  Class: hookKlass (resolved Klass*)
    //   +4  NameAndType: hookMethod name + desc
    //   +5  Methodref: hook method (resolved Method*)
    //   +6  Class: FvmCallback (resolved Klass*)
    //   +7  Methodref: FvmCallback.<init>()V (resolved Method*)
    //   +8  Methodref: FvmCallback.isCancelled()Z (resolved Method*)
    //   +9  Methodref: FvmCallback.getReturnValue()Ljava/lang/Object; (resolved Method*)

    // Find FvmCallback class and methods in target JVM
    uint64_t cbKlassAddr = 0;
    if (!findInstanceKlassByName("forgevm/transform/FvmCallback", &cbKlassAddr)) {
        setError("FvmCallback_class_not_loaded");
        return 0;
    }
    uint64_t cbInitMethodAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "<init>", "(Ljava/lang/Object;)V", &cbInitMethodAddr)) {
        setError("FvmCallback_init_not_found");
        return 0;
    }
    uint64_t cbIsCancelledAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "isCancelled", "()Z", &cbIsCancelledAddr)) {
        setError("FvmCallback_isCancelled_not_found");
        return 0;
    }
    uint64_t cbGetReturnAddr = 0;
    if (!findMethodInKlass(cbKlassAddr, "getReturnValue", "()Ljava/lang/Object;", &cbGetReturnAddr)) {
        setError("FvmCallback_getReturnValue_not_found");
        return 0;
    }

    uint32_t newPoolLength = poolLength + 10;
    size_t newPoolByteSize = poolByteSize + 10 * 8;

    std::vector<uint8_t> newPoolBytes(newPoolByteSize, 0);
    memcpy(newPoolBytes.data(), origPoolBytes.data(), poolByteSize);

    int64_t lengthOff = structOffset("ConstantPool", "_length");
    if (lengthOff >= 0) {
        int32_t newLen32 = (int32_t)newPoolLength;
        memcpy(newPoolBytes.data() + lengthOff, &newLen32, 4);
    }

    int64_t cpHeaderSize = typeSize("ConstantPool");
    if (cpHeaderSize < 0) cpHeaderSize = 0x138;

    uint64_t* newSlots = (uint64_t*)(newPoolBytes.data() + cpHeaderSize);

    // +0..+2: Utf8 symbols for hook
    newSlots[poolLength + 0] = hookClassSymbol;
    newSlots[poolLength + 1] = hookMethodSymbol;
    newSlots[poolLength + 2] = hookDescSymbol;
    // +3: Class -> hook Klass*
    newSlots[poolLength + 3] = hookKlassAddr;
    // +4: NameAndType (packed)
    uint32_t natPacked = ((uint32_t)(poolLength + 1) << 16) | (uint32_t)(poolLength + 2);
    newSlots[poolLength + 4] = (uint64_t)natPacked;
    // +5: Methodref -> hook Method* (resolved)
    newSlots[poolLength + 5] = hookMethodAddr;
    // +6: Class -> FvmCallback Klass*
    newSlots[poolLength + 6] = cbKlassAddr;
    // +7: Methodref -> FvmCallback.<init> (resolved)
    newSlots[poolLength + 7] = cbInitMethodAddr;
    // +8: Methodref -> FvmCallback.isCancelled (resolved)
    newSlots[poolLength + 8] = cbIsCancelledAddr;
    // +9: Methodref -> FvmCallback.getReturnValue (resolved)
    newSlots[poolLength + 9] = cbGetReturnAddr;

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

                uint8_t* tagData = newTags.data() + tagArrayDataOff;
                tagData[poolLength + 0] = 100; // Utf8
                tagData[poolLength + 1] = 100; // Utf8
                tagData[poolLength + 2] = 100; // Utf8
                tagData[poolLength + 3] = 7;   // Class
                tagData[poolLength + 4] = 12;  // NameAndType
                tagData[poolLength + 5] = 10;  // Methodref
                tagData[poolLength + 6] = 7;   // Class (FvmCallback)
                tagData[poolLength + 7] = 10;  // Methodref (<init>)
                tagData[poolLength + 8] = 10;  // Methodref (isCancelled)
                tagData[poolLength + 9] = 10;  // Methodref (getReturnValue)

                writeRemoteMem(proc, newTagsAddr, newTags.data(), newTagSize);
                memcpy(newPoolBytes.data() + tagsOff, &newTagsAddr, 8);
            }
        }
    }

    // 9. Build new bytecode
    //
    // CP indices for bytecode:
    uint16_t hookCpIndex = (uint16_t)(poolLength + 5);     // hook method
    uint16_t cbClassIdx  = (uint16_t)(poolLength + 6);     // FvmCallback class
    uint16_t cbInitIdx   = (uint16_t)(poolLength + 7);     // FvmCallback.<init>
    uint16_t cbCancelIdx = (uint16_t)(poolLength + 8);     // FvmCallback.isCancelled
    uint16_t cbRetValIdx = (uint16_t)(poolLength + 9);     // FvmCallback.getReturnValue
    //
    // Injected sequence (HEAD):
    //   new FvmCallback                    ; 3 bytes
    //   dup                                ; 1 byte
    //   invokespecial FvmCallback.<init>    ; 3 bytes
    //   dup                                ; 1 byte  (keep ref for isCancelled check)
    //   invokestatic hook.onXxx(FvmCallback) ; 3 bytes
    //   invokevirtual FvmCallback.isCancelled ; 3 bytes
    //   ifeq CONTINUE                      ; 3 bytes  (jump offset to skip return block)
    //   invokevirtual FvmCallback.getReturnValue ; 3 bytes
    //   areturn (or pop+return for void)    ; 1-2 bytes
    //   CONTINUE:
    //   ... original bytecode ...

    // Helper to emit 2-byte big-endian index
    auto emitIdx = [](std::vector<uint8_t>& bc, uint16_t idx) {
        bc.push_back((uint8_t)(idx >> 8));
        bc.push_back((uint8_t)(idx & 0xFF));
    };

    // Detect original return opcode for void vs non-void
    uint8_t origReturnOp = 0xB1; // default void
    if (!origBytecode.empty()) {
        origReturnOp = origBytecode.back();
        if (origReturnOp < 0xAC || origReturnOp > 0xB1) origReturnOp = 0xB0; // areturn
    }

    // Size of the return block after ifeq:
    //   getReturnValue(3) + areturn(1) = 4  OR  pop(1) + return(1) = 2 (void)
    int returnBlockSize = (origReturnOp == 0xB1) ? 2 : 4;
    // ifeq offset = 3 (ifeq instruction size) + returnBlockSize
    int16_t ifeqOffset = (int16_t)(3 + returnBlockSize);

    std::vector<uint8_t> newBytecode;
    std::string injectAtStr(injectAt);

    auto emitCallbackPrologue = [&](std::vector<uint8_t>& bc) {
        bc.push_back(0xBB); emitIdx(bc, cbClassIdx);       // new FvmCallback
        bc.push_back(0x59);                                  // dup
        bc.push_back(0x2A);                                  // aload_0 (push 'this')
        bc.push_back(0xB7); emitIdx(bc, cbInitIdx);         // invokespecial <init>(Object)
        bc.push_back(0x59);                                  // dup (keep ref)
        bc.push_back(0xB8); emitIdx(bc, hookCpIndex);       // invokestatic hook(FvmCallback)
        bc.push_back(0xB6); emitIdx(bc, cbCancelIdx);       // invokevirtual isCancelled
        bc.push_back(0x99);                                  // ifeq
        bc.push_back((uint8_t)(ifeqOffset >> 8));
        bc.push_back((uint8_t)(ifeqOffset & 0xFF));
        // Return block:
        if (origReturnOp == 0xB1) {
            // void: just pop callback ref and return
            bc.push_back(0x57); // pop (the callback ref left on stack)
            bc.push_back(0xB1); // return
        } else {
            // non-void: get return value and areturn
            bc.push_back(0xB6); emitIdx(bc, cbRetValIdx);   // invokevirtual getReturnValue
            bc.push_back(0xB0);                              // areturn
        }
        // CONTINUE: callback ref is still on stack from the dup, pop it
        bc.push_back(0x57); // pop
    };

    if (injectAtStr == "HEAD") {
        newBytecode.reserve(origBytecode.size() + 30);
        emitCallbackPrologue(newBytecode);
        newBytecode.insert(newBytecode.end(), origBytecode.begin(), origBytecode.end());
    } else if (injectAtStr == "RETURN") {
        newBytecode.reserve(origBytecode.size() + 30);
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

    // 10. Build new ConstMethod with updated bytecode
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

    // Update _constMethod_size if present
    if (cmSizeOff >= 0) {
        int32_t newCmWords = (int32_t)((newConstMethodSize + 7) / 8);
        memcpy(newConstMethodBytes.data() + cmSizeOff, &newCmWords, 4);
    }

    // 11. Allocate and write new ConstantPool + ConstMethod in target process
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

    // Update _constants pointer in new ConstMethod to point to new pool
    if (cmConstsOff >= 0) {
        memcpy(newConstMethodBytes.data() + cmConstsOff, &newPoolAddr, 8);
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
    std::vector<DWORD> threadIds;
    suspendTargetThreads(g_target.pid, threadIds);

    // Swap Method::_constMethod to point to new ConstMethod
    writeRemoteMem(proc, methodAddr + (uint64_t)constMethodOff, &newConstMethodAlloc, 8);

    // Clear Method::_code to force deoptimization (interpreter will use new bytecode)
    int64_t codeOff = structOffset("Method", "_code");
    if (codeOff >= 0) {
        uint64_t nullCode = 0;
        writeRemoteMem(proc, methodAddr + (uint64_t)codeOff, &nullCode, 8);
    }

    // Clear Method::_from_compiled_entry and _from_interpreted_entry to force re-resolution
    int64_t fromCompiledOff = structOffset("Method", "_from_compiled_entry");
    int64_t fromInterpOff = structOffset("Method", "_from_interpreted_entry");
    if (fromCompiledOff >= 0) {
        uint64_t zero = 0;
        writeRemoteMem(proc, methodAddr + (uint64_t)fromCompiledOff, &zero, 8);
    }
    // Note: _from_interpreted_entry should point to the interpreter entry stub
    // Zeroing it may cause issues; the interpreter will re-resolve it on next call
    // For safety, we leave _from_interpreted_entry alone — clearing _code is sufficient
    // to force the JVM to re-enter the interpreter path.

    resumeTargetThreads(threadIds);

    // 13. Save backup for restore
    TransformBackup backup;
    backup.key = key;
    backup.methodAddr = methodAddr;
    backup.origConstMethodAddr = origConstMethodAddr;
    backup.origConstPoolAddr = origConstPoolAddr;
    backup.allocatedConstMethod = newConstMethodAlloc;
    backup.allocatedConstPool = newPoolAddr;
    backup.allocatedConstMethodSize = newConstMethodSize;
    backup.allocatedConstPoolSize = newPoolByteSize;
    g_transformBackups[key] = backup;

    setError("ok");
    return 1;
}

// ============================================================
// Restore original method
// ============================================================

int restoreTransform(const char* className, const char* methodName, const char* paramDesc) {
    HANDLE proc = g_target.handle;
    std::string key = makeTransformKey(className, methodName, paramDesc);

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

    // Restore original ConstMethod pointer
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

    // Free allocated memory
    if (backup.allocatedConstMethod != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedConstMethod, 0, MEM_RELEASE);
    }
    if (backup.allocatedConstPool != 0) {
        VirtualFreeEx(proc, (LPVOID)backup.allocatedConstPool, 0, MEM_RELEASE);
    }

    g_transformBackups.erase(it);

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
