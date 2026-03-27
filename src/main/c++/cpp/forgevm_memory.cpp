#include "forgevm_internal.h"

#include <tlhelp32.h>
#include <cctype>

// ============================================================
// Compressed oop/klass helpers
// ============================================================

std::string g_compressionDetectLog;

void extractCompressionParams() {
    StructMapEntry e;
    g_compressionDetectLog.clear();

    // -- detect UseCompressedOops --
    auto coopIt = g_intConstants.find("UseCompressedOops");
    if (coopIt != g_intConstants.end()) {
        g_target.useCompressedOops = (coopIt->second != 0);
        g_compressionDetectLog += "coop_src=intConst(" + std::to_string(coopIt->second) + ")";
    } else {
        if (structLookup("CompressedOops", "_narrow_oop._base", &e)) {
            g_target.useCompressedOops = true;
            g_compressionDetectLog += "coop_src=structMap(CompressedOops)";
        } else if (structLookup("Universe", "_narrow_oop._base", &e)) {
            g_target.useCompressedOops = true;
            g_compressionDetectLog += "coop_src=structMap(Universe)";
        } else {
            g_target.useCompressedOops = false;
            g_compressionDetectLog += "coop_src=none";
        }
    }

    // -- detect UseCompressedClassPointers --
    auto cklsIt = g_intConstants.find("UseCompressedClassPointers");
    if (cklsIt != g_intConstants.end()) {
        g_target.useCompressedClassPointers = (cklsIt->second != 0);
        g_compressionDetectLog += ",ckls_src=intConst(" + std::to_string(cklsIt->second) + ")";
    } else {
        if (structLookup("CompressedKlassPointers", "_narrow_klass._base", &e)) {
            g_target.useCompressedClassPointers = true;
            g_compressionDetectLog += ",ckls_src=structMap(CompressedKlassPointers)";
        } else if (structLookup("Universe", "_narrow_klass._base", &e)) {
            g_target.useCompressedClassPointers = true;
            g_compressionDetectLog += ",ckls_src=structMap(Universe)";
        } else {
            g_target.useCompressedClassPointers = false;
            g_compressionDetectLog += ",ckls_src=none";
        }
    }

    // -- read narrow oop base/shift --
    if (g_target.useCompressedOops) {
        if (structLookup("CompressedOops", "_narrow_oop._base", &e) && e.isStatic && e.address != 0) {
            readRemotePointer(g_target.handle, e.address, &g_target.narrowOopBase);
        } else if (structLookup("Universe", "_narrow_oop._base", &e) && e.isStatic && e.address != 0) {
            readRemotePointer(g_target.handle, e.address, &g_target.narrowOopBase);
        }

        uint64_t shiftAddr = 0;
        if (structLookup("CompressedOops", "_narrow_oop._shift", &e) && e.isStatic && e.address != 0) {
            shiftAddr = e.address;
        } else if (structLookup("Universe", "_narrow_oop._shift", &e) && e.isStatic && e.address != 0) {
            shiftAddr = e.address;
        }
        if (shiftAddr != 0) {
            int32_t shift = 0;
            readRemoteI32(g_target.handle, shiftAddr, &shift);
            g_target.narrowOopShift = shift;
        }
    }

    // -- read narrow klass base/shift --
    if (g_target.useCompressedClassPointers) {
        if (structLookup("CompressedKlassPointers", "_narrow_klass._base", &e) && e.isStatic && e.address != 0) {
            readRemotePointer(g_target.handle, e.address, &g_target.narrowKlassBase);
        } else if (structLookup("Universe", "_narrow_klass._base", &e) && e.isStatic && e.address != 0) {
            readRemotePointer(g_target.handle, e.address, &g_target.narrowKlassBase);
        }

        uint64_t shiftAddr = 0;
        if (structLookup("CompressedKlassPointers", "_narrow_klass._shift", &e) && e.isStatic && e.address != 0) {
            shiftAddr = e.address;
        } else if (structLookup("Universe", "_narrow_klass._shift", &e) && e.isStatic && e.address != 0) {
            shiftAddr = e.address;
        }
        if (shiftAddr != 0) {
            int32_t shift = 0;
            readRemoteI32(g_target.handle, shiftAddr, &shift);
            g_target.narrowKlassShift = shift;
        }
    }

    g_compressionDetectLog +=
        ",oop=" + std::to_string(g_target.useCompressedOops ? 1 : 0) +
        "(base=" + std::to_string(g_target.narrowOopBase) +
        ",shift=" + std::to_string(g_target.narrowOopShift) + ")" +
        ",kls=" + std::to_string(g_target.useCompressedClassPointers ? 1 : 0) +
        "(base=" + std::to_string(g_target.narrowKlassBase) +
        ",shift=" + std::to_string(g_target.narrowKlassShift) + ")";
}

uint64_t decodeNarrowOop(uint32_t narrow) {
    if (narrow == 0) return 0;
    return g_target.narrowOopBase + ((uint64_t)narrow << g_target.narrowOopShift);
}

uint64_t decodeRawOop(uint64_t rawOop) {
    if (rawOop == 0) return 0;
    if (g_target.useCompressedOops) {
        return decodeNarrowOop(static_cast<uint32_t>(rawOop));
    }
    return rawOop;
}

uint64_t decodeRawOopWithMode(uint64_t rawOop, bool compressed) {
    if (rawOop == 0) return 0;
    if (compressed) {
        return decodeNarrowOop(static_cast<uint32_t>(rawOop));
    }
    return rawOop;
}

uint64_t decodeNarrowKlass(uint32_t narrow) {
    if (narrow == 0) return 0;
    return g_target.narrowKlassBase + ((uint64_t)narrow << g_target.narrowKlassShift);
}

uint64_t readOop(HANDLE proc, uint64_t addr, bool compressed) {
    if (compressed) {
        uint32_t narrow = 0;
        if (!readRemoteU32(proc, addr, &narrow)) return 0;
        return decodeNarrowOop(narrow);
    } else {
        uint64_t full = 0;
        if (!readRemotePointer(proc, addr, &full)) return 0;
        return full;
    }
}

uint64_t readKlass(HANDLE proc, uint64_t addr, bool compressed) {
    if (compressed) {
        uint32_t narrow = 0;
        if (!readRemoteU32(proc, addr, &narrow)) return 0;
        return decodeNarrowKlass(narrow);
    } else {
        uint64_t full = 0;
        if (!readRemotePointer(proc, addr, &full)) return 0;
        return full;
    }
}

// ============================================================
// OOP/Klass heuristic resolution
// ============================================================

static bool containsIgnoreCase(const std::string& text, const char* needle) {
    if (needle == nullptr || needle[0] == '\0') return false;
    std::string n(needle);
    for (char& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string t = text;
    for (char& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return t.find(n) != std::string::npos;
}

static void appendLikelyOopBases(std::vector<uint64_t>& bases) {
    auto pushBase = [&](uint64_t b) {
        if (b == 0) return;
        for (uint64_t v : bases) {
            if (v == b) return;
        }
        bases.push_back(b);
    };

    pushBase(g_target.narrowOopBase);
    for (const auto& kv : g_longConstants) {
        if (containsIgnoreCase(kv.first, "narrowoopbase") || containsIgnoreCase(kv.first, "heapbase")) {
            pushBase(static_cast<uint64_t>(kv.second));
        }
    }
}

static void appendLikelyKlassBases(std::vector<uint64_t>& bases) {
    auto pushBase = [&](uint64_t b) {
        if (b == 0) return;
        for (uint64_t v : bases) {
            if (v == b) return;
        }
        bases.push_back(b);
    };

    pushBase(g_target.narrowKlassBase);
    for (const auto& kv : g_longConstants) {
        if (containsIgnoreCase(kv.first, "narrowklassbase") || containsIgnoreCase(kv.first, "klassbase")) {
            pushBase(static_cast<uint64_t>(kv.second));
        }
    }
}

bool looksLikeValidKlass(HANDLE proc, uint64_t klassAddr) {
    if (klassAddr == 0) return false;
    int64_t superOff = structOffset("Klass", "_super");
    if (superOff < 0) superOff = 40;

    uint64_t superKlass = 0;
    return readRemotePointer(proc, klassAddr + static_cast<uint64_t>(superOff), &superKlass);
}

bool resolveObjectAndKlassFromRawOop(uint64_t rawOop, DecodedObjectInfo* out) {
    if (rawOop == 0 || out == nullptr) return false;

    HANDLE proc = g_target.handle;
    struct OopCandidate {
        uint64_t addr;
        bool oopCompressed;
    };
    OopCandidate candidates[8];
    int candidateCount = 0;

    auto pushUnique = [&](uint64_t addr, bool oopCompressed) {
        if (addr == 0) return;
        if (candidateCount >= static_cast<int>(sizeof(candidates) / sizeof(candidates[0]))) return;
        for (int i = 0; i < candidateCount; i++) {
            if (candidates[i].addr == addr) return;
        }
        candidates[candidateCount++] = OopCandidate{addr, oopCompressed};
    };

    uint32_t raw32 = static_cast<uint32_t>(rawOop);
    bool preferredCompressed = g_target.useCompressedOops;
    pushUnique(decodeRawOopWithMode(rawOop, preferredCompressed), preferredCompressed);
    pushUnique(decodeRawOopWithMode(rawOop, !preferredCompressed), !preferredCompressed);

    pushUnique(static_cast<uint64_t>(raw32), false);
    std::vector<uint64_t> oopBases;
    appendLikelyOopBases(oopBases);
    if (oopBases.empty()) oopBases.push_back(0ULL);

    for (int shift = 0; shift <= 8; shift++) {
        uint64_t shifted = static_cast<uint64_t>(raw32) << shift;
        pushUnique(shifted, true);
        for (uint64_t base : oopBases) {
            pushUnique(base + shifted, true);
        }
    }

    pushUnique(rawOop, false);

    bool klassModes[2] = {g_target.useCompressedClassPointers, !g_target.useCompressedClassPointers};

    for (int i = 0; i < candidateCount; i++) {
        uint64_t objAddr = candidates[i].addr;

        uint64_t markWord = 0;
        if (!readRemotePointer(proc, objAddr, &markWord)) {
            continue;
        }

        for (int m = 0; m < 2; m++) {
            bool klassCompressed = klassModes[m];
            uint64_t klassAddr = readKlass(proc, objAddr + 8, klassCompressed);
            if (!looksLikeValidKlass(proc, klassAddr)) {
                continue;
            }

            out->objAddr = objAddr;
            out->klassAddr = klassAddr;
            out->oopCompressed = candidates[i].oopCompressed;
            out->klassCompressed = klassCompressed;
            return true;
        }

        uint32_t narrowKlass = 0;
        if (readRemoteU32(proc, objAddr + 8, &narrowKlass) && narrowKlass != 0) {
            uint64_t klassCandidates[32];
            int kc = 0;
            auto pushKlass = [&](uint64_t v) {
                if (v == 0) return;
                if (kc >= static_cast<int>(sizeof(klassCandidates) / sizeof(klassCandidates[0]))) return;
                for (int k = 0; k < kc; k++) {
                    if (klassCandidates[k] == v) return;
                }
                klassCandidates[kc++] = v;
            };

            pushKlass(decodeNarrowKlass(narrowKlass));

            std::vector<uint64_t> klassBases;
            appendLikelyKlassBases(klassBases);
            if (klassBases.empty()) klassBases.push_back(0ULL);

            for (int shift = 0; shift <= 8; shift++) {
                uint64_t shifted = static_cast<uint64_t>(narrowKlass) << shift;
                pushKlass(shifted);
                for (uint64_t base : klassBases) {
                    pushKlass(base + shifted);
                }
            }

            for (int k = 0; k < kc; k++) {
                if (!looksLikeValidKlass(proc, klassCandidates[k])) continue;
                out->objAddr = objAddr;
                out->klassAddr = klassCandidates[k];
                out->oopCompressed = candidates[i].oopCompressed;
                out->klassCompressed = true;
                return true;
            }
        }
    }

    setError(std::string("klass_read_failed:decode_mismatch:raw_oop=")
             + std::to_string(rawOop)
             + ",candidates=" + std::to_string(candidateCount)
             + ",narrow_oop_base=" + std::to_string(g_target.narrowOopBase)
             + ",narrow_oop_shift=" + std::to_string(g_target.narrowOopShift)
             + ",narrow_klass_base=" + std::to_string(g_target.narrowKlassBase)
             + ",narrow_klass_shift=" + std::to_string(g_target.narrowKlassShift));
    return false;
}

// ============================================================
// Thread suspend / resume
// ============================================================

bool suspendTargetThreads(DWORD pid, std::vector<DWORD>& threadIds) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (ht) {
                    SuspendThread(ht);
                    CloseHandle(ht);
                    threadIds.push_back(te.th32ThreadID);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return !threadIds.empty();
}

void resumeTargetThreads(const std::vector<DWORD>& threadIds) {
    for (DWORD tid : threadIds) {
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (ht) {
            ResumeThread(ht);
            CloseHandle(ht);
        }
    }
}

// ============================================================
// Field descriptor helpers
// ============================================================

int32_t fieldSizeFromDescriptor(const std::string& desc) {
    if (desc.empty()) return 0;
    switch (desc[0]) {
        case 'Z': return 1; // boolean
        case 'B': return 1; // byte
        case 'C': return 2; // char
        case 'S': return 2; // short
        case 'I': return 4; // int
        case 'F': return 4; // float
        case 'J': return 8; // long
        case 'D': return 8; // double
        case 'L': return 8; // reference (or 4 compressed)
        case '[': return 8; // array reference
        default: return 0;
    }
}

static std::string slashToDot(const std::string& name) {
    std::string result = name;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i] == '/') result[i] = '.';
    }
    return result;
}

static std::string dotToSlash(const std::string& name) {
    std::string result = name;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i] == '.') result[i] = '/';
    }
    return result;
}

// ============================================================
// Symbol reading
// ============================================================

bool readSymbolBody(HANDLE proc, uint64_t symbolAddr, std::string* out) {
    int64_t lengthOff = structOffset("Symbol", "_length");
    int64_t bodyOff = structOffset("Symbol", "_body");
    if (lengthOff < 0 || bodyOff < 0) {
        // fallback: typical HotSpot layout
        uint16_t len = 0;
        if (readRemoteU16(proc, symbolAddr + 6, &len) && len > 0 && len < 1024) {
            char buf[1024];
            if (readRemoteMem(proc, symbolAddr + 8, buf, len)) {
                *out = std::string(buf, len);
                return true;
            }
        }
        if (readRemoteU16(proc, symbolAddr + 4, &len) && len > 0 && len < 1024) {
            char buf[1024];
            if (readRemoteMem(proc, symbolAddr + 6, buf, len)) {
                *out = std::string(buf, len);
                return true;
            }
        }
        return false;
    }

    uint16_t len = 0;
    if (!readRemoteU16(proc, symbolAddr + lengthOff, &len) || len == 0 || len > 4096) {
        return false;
    }
    char buf[4096];
    if (!readRemoteMem(proc, symbolAddr + bodyOff, buf, len)) {
        return false;
    }
    *out = std::string(buf, len);
    return true;
}

// ============================================================
// Field resolution within InstanceKlass
// ============================================================

bool resolveFieldInKlass(uint64_t klassAddr, const std::string& fieldName,
                         const std::string& descriptor, ResolvedField* out) {
    HANDLE proc = g_target.handle;

    int64_t ik_fields_off = structOffset("InstanceKlass", "_fields");
    int64_t ik_constants_off = structOffset("InstanceKlass", "_constants");
    int64_t ik_mirror_off = structOffset("Klass", "_java_mirror");

    if (ik_fields_off < 0 || ik_constants_off < 0) {
        setError("structmap_missing:InstanceKlass_fields_or_constants");
        return false;
    }

    // read ConstantPool pointer
    uint64_t cpAddr = 0;
    readRemotePointer(proc, klassAddr + ik_constants_off, &cpAddr);
    if (cpAddr == 0) {
        setError("constant_pool_null");
        return false;
    }

    // read fields Array<u2>*
    uint64_t fieldsArrayAddr = 0;
    readRemotePointer(proc, klassAddr + ik_fields_off, &fieldsArrayAddr);
    if (fieldsArrayAddr == 0) {
        setError("fields_array_null");
        return false;
    }

    // Array<u2> layout
    int64_t arrayHeaderSize = typeSize("Array<int>");
    if (arrayHeaderSize < 0) arrayHeaderSize = typeSize("Array<u2>");
    if (arrayHeaderSize < 0) arrayHeaderSize = 16;

    int32_t fieldsLen = 0;
    readRemoteI32(proc, fieldsArrayAddr + arrayHeaderSize - 4 - 4, &fieldsLen);
    if (fieldsLen <= 0 || fieldsLen > 100000) {
        readRemoteI32(proc, fieldsArrayAddr + 8, &fieldsLen);
    }
    if (fieldsLen <= 0 || fieldsLen > 100000) {
        readRemoteI32(proc, fieldsArrayAddr + 12, &fieldsLen);
    }
    if (fieldsLen <= 0 || fieldsLen > 100000) {
        setError("fields_array_bad_length");
        return false;
    }

    // ConstantPool header size
    int64_t cp_header_size = typeSize("ConstantPool");
    if (cp_header_size <= 0) {
        const int64_t kCandidates[] = {72, 80, 96};
        for (int64_t c : kCandidates) {
            uint64_t probePtr = 0;
            if (readRemotePointer(proc, cpAddr + c + 8, &probePtr)
                    && probePtr >= 0x10000ULL && (probePtr & 7) == 0) {
                cp_header_size = c;
                break;
            }
        }
        if (cp_header_size <= 0) cp_header_size = 72;
    }

    // ConstantPool length
    int64_t cp_length_off = structOffset("ConstantPool", "_length");
    int32_t cpLength = 0;
    if (cp_length_off >= 0) {
        readRemoteI32(proc, cpAddr + cp_length_off, &cpLength);
    }

    // Read the raw u2 array
    int totalU2 = fieldsLen;
    std::vector<uint16_t> fieldData(totalU2);
    uint64_t fieldDataAddr = fieldsArrayAddr + 16;

    bool readOk = false;
    for (int hdrTry = 16; hdrTry >= 8; hdrTry -= 4) {
        if (readRemoteMem(proc, fieldsArrayAddr + hdrTry, fieldData.data(), totalU2 * 2)) {
            readOk = true;
            fieldDataAddr = fieldsArrayAddr + hdrTry;
            break;
        }
    }
    if (!readOk) {
        setError("fields_data_read_failed");
        return false;
    }

    // java fields count
    int64_t jfc_off = structOffset("InstanceKlass", "_java_fields_count");
    int32_t javaFieldsCount = 0;
    if (jfc_off >= 0) {
        uint16_t jfc = 0;
        readRemoteU16(proc, klassAddr + jfc_off, &jfc);
        javaFieldsCount = jfc;
    } else {
        javaFieldsCount = totalU2 / 6;
    }

    // iterate fields
    for (int fi = 0; fi < javaFieldsCount && (fi * 6 + 5) < totalU2; fi++) {
        int base = fi * 6;
        uint16_t accessFlags = fieldData[base + 0];
        uint16_t nameIndex = fieldData[base + 1];
        uint16_t sigIndex = fieldData[base + 2];
        uint16_t lowOffset = fieldData[base + 4];
        uint16_t highOffset = fieldData[base + 5];

        // HotSpot FieldInfo packs offset with a 2-bit tag in the low bits
        int32_t fieldOffset;
        if ((lowOffset & 3) == 1) {
            fieldOffset = (int32_t)(lowOffset >> 2) | ((int32_t)highOffset << 14);
        } else {
            fieldOffset = (int32_t)lowOffset | ((int32_t)highOffset << 16);
            if (fieldOffset < 0 || fieldOffset > 1000000) {
                fieldOffset = (int32_t)lowOffset;
            }
        }

        // read name Symbol from constant pool
        uint64_t nameSymAddr = 0;
        if (cp_header_size > 0 && nameIndex > 0 && nameIndex < cpLength) {
            uint64_t cpEntryAddr = cpAddr + cp_header_size + (uint64_t)nameIndex * 8;
            readRemotePointer(proc, cpEntryAddr, &nameSymAddr);
        }

        uint64_t sigSymAddr = 0;
        if (cp_header_size > 0 && sigIndex > 0 && sigIndex < cpLength) {
            uint64_t cpEntryAddr = cpAddr + cp_header_size + (uint64_t)sigIndex * 8;
            readRemotePointer(proc, cpEntryAddr, &sigSymAddr);
        }

        std::string fName, fSig;
        if (nameSymAddr != 0) readSymbolBody(proc, nameSymAddr, &fName);
        if (sigSymAddr != 0) readSymbolBody(proc, sigSymAddr, &fSig);

        if (fName != fieldName) continue;
        if (!descriptor.empty() && !fSig.empty() && descriptor != fSig) continue;

        // found the field
        bool isStatic = (accessFlags & 0x0008) != 0;
        out->fieldName = fieldName;
        out->descriptor = fSig.empty() ? descriptor : fSig;
        out->offset = fieldOffset;
        out->isStatic = isStatic;
        out->fieldSize = fieldSizeFromDescriptor(out->descriptor);
        if (out->fieldSize == 0) out->fieldSize = 8;

        if (isStatic) {
            if (ik_mirror_off >= 0) {
                uint64_t mirrorOop = readOop(proc, klassAddr + ik_mirror_off, g_target.useCompressedOops);
                if (mirrorOop != 0) {
                    out->staticAddress = mirrorOop + fieldOffset;
                } else {
                    uint64_t mirrorHandle = 0;
                    readRemotePointer(proc, klassAddr + ik_mirror_off, &mirrorHandle);
                    if (mirrorHandle != 0) {
                        uint64_t mirrorVal = 0;
                        readRemotePointer(proc, mirrorHandle, &mirrorVal);
                        if (mirrorVal != 0) {
                            out->staticAddress = mirrorVal + fieldOffset;
                        }
                    }
                }
            }
            if (out->staticAddress == 0) {
                setError("mirror_oop_resolve_failed");
                return false;
            }
        } else {
            out->staticAddress = 0;
        }

        return true;
    }

    setError("field_not_found");
    return false;
}

// ============================================================
// Field resolution with klass hierarchy walk
// ============================================================

bool resolveAndCacheField(const char* fieldName,
                          uint64_t objAddr,
                          uint64_t klassAddr,
                          bool oopCompressed,
                          CachedFieldInfo* out) {
    HANDLE proc = g_target.handle;

    if (klassAddr == 0) {
        setError("klass_read_failed");
        return false;
    }

    int64_t superOff = structOffset("Klass", "_super");
    if (superOff < 0) superOff = 40;

    std::string fn(fieldName);
    ResolvedField resolved;
    bool found = false;
    uint64_t currentKlass = klassAddr;

    for (int depth = 0; depth < 64 && currentKlass != 0; depth++) {
        if (resolveFieldInKlass(currentKlass, fn, "", &resolved)) {
            found = true;
            break;
        }
        uint64_t superKlass = 0;
        if (!readRemotePointer(proc, currentKlass + superOff, &superKlass)) break;
        currentKlass = superKlass;
    }

    if (!found) {
        setError("field_not_found_in_class_hierarchy");
        return false;
    }

    out->offset = resolved.offset;
    out->isStatic = resolved.isStatic;
    out->staticAddr = resolved.staticAddress;
    out->oopCompressed = oopCompressed;
    return true;
}

// ============================================================
// put_field: write a primitive field value
// ============================================================

extern "C" __declspec(dllexport) int forgevm_put_field(
        unsigned long long oop,
        const char* fieldName,
        const char* className,
        const unsigned char* valueBytes,
        unsigned long long valueSize) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (fieldName == NULL || className == NULL || valueBytes == NULL || valueSize == 0) {
        setError("invalid_params");
        return 0;
    }

    std::string cacheKey = std::string(className) + "#" + fieldName;
    CachedFieldInfo fieldInfo;
    auto it = g_fieldInfoCache.find(cacheKey);
    if (it != g_fieldInfoCache.end()) {
        fieldInfo = it->second;
    } else {
        DecodedObjectInfo decoded;
        if (!resolveObjectAndKlassFromRawOop(oop, &decoded)) {
            return 0;
        }
        if (!resolveAndCacheField(fieldName, decoded.objAddr, decoded.klassAddr,
                                  decoded.oopCompressed, &fieldInfo)) {
            return 0;
        }
        g_fieldInfoCache[cacheKey] = fieldInfo;
    }

    uint64_t objAddr = decodeRawOopWithMode(oop, fieldInfo.oopCompressed);
    if (objAddr == 0) {
        setError("null_oop");
        return 0;
    }

    uint64_t writeAddr = fieldInfo.isStatic
        ? fieldInfo.staticAddr
        : objAddr + static_cast<uint32_t>(fieldInfo.offset);

    if (!writeRemoteMem(g_target.handle, writeAddr, valueBytes, static_cast<size_t>(valueSize))) {
        setError("write_remote_mem_failed");
        return 0;
    }

    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_put_field_batch(
        const unsigned long long* oops,
        unsigned long long count,
        const char* fieldName,
        const char* className,
        const unsigned char* valueBytes,
        unsigned long long valueSize) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (oops == NULL || count == 0 || fieldName == NULL || className == NULL ||
            valueBytes == NULL || valueSize == 0) {
        setError("invalid_params");
        return 0;
    }

    std::vector<DWORD> suspendedThreads;
    suspendTargetThreads(g_target.pid, suspendedThreads);

    std::string cacheKey = std::string(className) + "#" + fieldName;
    CachedFieldInfo fieldInfo;
    auto it = g_fieldInfoCache.find(cacheKey);
    if (it != g_fieldInfoCache.end()) {
        fieldInfo = it->second;
    } else {
        DecodedObjectInfo decoded;
        bool decodedOk = false;
        bool sawNonZeroOop = false;
        for (unsigned long long i = 0; i < count && !decodedOk; i++) {
            if (oops[i] != 0) sawNonZeroOop = true;
            decodedOk = resolveObjectAndKlassFromRawOop(oops[i], &decoded);
        }
        if (!decodedOk) {
            resumeTargetThreads(suspendedThreads);
            if (!sawNonZeroOop) setError("all_oops_null");
            return 0;
        }
        if (!resolveAndCacheField(fieldName, decoded.objAddr, decoded.klassAddr,
                                  decoded.oopCompressed, &fieldInfo)) {
            resumeTargetThreads(suspendedThreads);
            return 0;
        }
        g_fieldInfoCache[cacheKey] = fieldInfo;
    }

    int successCount = 0;
    for (unsigned long long i = 0; i < count; i++) {
        if (oops[i] == 0) continue;
        uint64_t objAddr = decodeRawOopWithMode(oops[i], fieldInfo.oopCompressed);
        if (objAddr == 0) continue;

        uint64_t writeAddr = fieldInfo.isStatic
            ? fieldInfo.staticAddr
            : objAddr + static_cast<uint32_t>(fieldInfo.offset);

        if (writeRemoteMem(g_target.handle, writeAddr, valueBytes, static_cast<size_t>(valueSize))) {
            successCount++;
        }
    }

    resumeTargetThreads(suspendedThreads);

    if (successCount == 0) {
        setError("write_remote_mem_failed");
        return 0;
    }

    setError("ok");
    return 1;
}

// ============================================================
// Card table support for Object reference writes
// ============================================================

static uint64_t g_cardTableBase = 0;
static bool g_cardTableResolved = false;
static const int CARD_SHIFT = 9;

static bool resolveCardTableBase() {
    if (g_cardTableResolved) return g_cardTableBase != 0;
    g_cardTableResolved = true;

    HANDLE proc = g_target.handle;

    uint64_t byteMapBaseAddr = structStaticAddr("CardTable", "_byte_map_base");
    if (byteMapBaseAddr != 0) {
        readRemotePointer(proc, byteMapBaseAddr, &g_cardTableBase);
        if (g_cardTableBase != 0) return true;
    }

    uint64_t heapAddr = structStaticAddr("Universe", "_collectedHeap");
    if (heapAddr == 0) {
        setError("card_table:no_collectedHeap");
        return false;
    }
    uint64_t heap = 0;
    readRemotePointer(proc, heapAddr, &heap);
    if (heap == 0) {
        setError("card_table:collectedHeap_null");
        return false;
    }

    int64_t bsOff = structOffset("CollectedHeap", "_barrier_set");
    if (bsOff < 0) bsOff = structOffset("G1CollectedHeap", "_barrier_set");
    if (bsOff < 0) bsOff = structOffset("ParallelScavengeHeap", "_barrier_set");
    if (bsOff < 0) bsOff = structOffset("GenCollectedHeap", "_barrier_set");
    if (bsOff < 0) {
        // scan structMap for any type with _barrier_set
        for (const auto& kv : g_structMap) {
            if (kv.first.fieldName == "_barrier_set") {
                bsOff = kv.second.offset;
                break;
            }
        }
    }
    if (bsOff < 0) {
        setError("card_table:no_barrier_set_offset");
        return false;
    }
    uint64_t barrierSet = 0;
    readRemotePointer(proc, heap + bsOff, &barrierSet);
    if (barrierSet == 0) {
        setError("card_table:barrier_set_null");
        return false;
    }

    int64_t ctOff = structOffset("CardTableBarrierSet", "_card_table");
    if (ctOff < 0) ctOff = structOffset("BarrierSet", "_card_table");
    if (ctOff < 0) ctOff = structOffset("G1BarrierSet", "_card_table");
    if (ctOff < 0) {
        for (const auto& kv : g_structMap) {
            if (kv.first.fieldName == "_card_table") {
                ctOff = kv.second.offset;
                break;
            }
        }
    }
    if (ctOff < 0) {
        setError("card_table:no_card_table_offset");
        return false;
    }
    uint64_t cardTable = 0;
    readRemotePointer(proc, barrierSet + ctOff, &cardTable);
    if (cardTable == 0) {
        setError("card_table:card_table_null");
        return false;
    }

    int64_t bmOff = structOffset("CardTable", "_byte_map_base");
    if (bmOff < 0) bmOff = structOffset("G1CardTable", "_byte_map_base");
    if (bmOff < 0) {
        for (const auto& kv : g_structMap) {
            if (kv.first.fieldName == "_byte_map_base") {
                bmOff = kv.second.offset;
                break;
            }
        }
    }
    if (bmOff < 0) {
        setError("card_table:no_byte_map_base_offset");
        return false;
    }
    readRemotePointer(proc, cardTable + bmOff, &g_cardTableBase);
    if (g_cardTableBase == 0) {
        setError("card_table:byte_map_base_null");
        return false;
    }
    return true;
}

static bool dirtyCard(uint64_t writeAddr) {
    if (g_cardTableBase == 0) return false;
    uint64_t cardAddr = g_cardTableBase + (writeAddr >> CARD_SHIFT);
    uint8_t dirty = 0;
    return writeRemoteMem(g_target.handle, cardAddr, &dirty, 1);
}

// ============================================================
// put_ref_field: write an Object reference field + dirty card table
// ============================================================

extern "C" __declspec(dllexport) int forgevm_put_ref_field(
        unsigned long long oop,
        const char* fieldName,
        const char* className,
        const unsigned char* valueBytes,
        unsigned long long valueSize) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (fieldName == NULL || className == NULL || valueBytes == NULL || valueSize == 0) {
        setError("invalid_params");
        return 0;
    }

    if (!resolveCardTableBase()) {
        return 0;
    }

    std::string cacheKey = std::string(className) + "#" + fieldName;
    CachedFieldInfo fieldInfo;
    auto it = g_fieldInfoCache.find(cacheKey);
    if (it != g_fieldInfoCache.end()) {
        fieldInfo = it->second;
    } else {
        DecodedObjectInfo decoded;
        if (!resolveObjectAndKlassFromRawOop(oop, &decoded)) {
            return 0;
        }
        if (!resolveAndCacheField(fieldName, decoded.objAddr, decoded.klassAddr,
                                  decoded.oopCompressed, &fieldInfo)) {
            return 0;
        }
        g_fieldInfoCache[cacheKey] = fieldInfo;
    }

    uint64_t objAddr = decodeRawOopWithMode(oop, fieldInfo.oopCompressed);
    if (objAddr == 0) {
        setError("null_oop");
        return 0;
    }

    uint64_t writeAddr = fieldInfo.isStatic
        ? fieldInfo.staticAddr
        : objAddr + static_cast<uint32_t>(fieldInfo.offset);

    if (!writeRemoteMem(g_target.handle, writeAddr, valueBytes, static_cast<size_t>(valueSize))) {
        setError("write_remote_mem_failed");
        return 0;
    }

    dirtyCard(writeAddr);
    setError("ok");
    return 1;
}

extern "C" __declspec(dllexport) int forgevm_put_ref_field_batch(
        const unsigned long long* oops,
        unsigned long long count,
        const char* fieldName,
        const char* className,
        const unsigned char* valueBytes,
        unsigned long long valueSize) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (oops == NULL || count == 0 || fieldName == NULL || className == NULL ||
            valueBytes == NULL || valueSize == 0) {
        setError("invalid_params");
        return 0;
    }

    if (!resolveCardTableBase()) {
        return 0;
    }

    std::vector<DWORD> suspendedThreads;
    suspendTargetThreads(g_target.pid, suspendedThreads);

    std::string cacheKey = std::string(className) + "#" + fieldName;
    CachedFieldInfo fieldInfo;
    auto it = g_fieldInfoCache.find(cacheKey);
    if (it != g_fieldInfoCache.end()) {
        fieldInfo = it->second;
    } else {
        DecodedObjectInfo decoded;
        bool decodedOk = false;
        bool sawNonZeroOop = false;
        for (unsigned long long i = 0; i < count && !decodedOk; i++) {
            if (oops[i] != 0) sawNonZeroOop = true;
            decodedOk = resolveObjectAndKlassFromRawOop(oops[i], &decoded);
        }
        if (!decodedOk) {
            resumeTargetThreads(suspendedThreads);
            if (!sawNonZeroOop) setError("all_oops_null");
            return 0;
        }
        if (!resolveAndCacheField(fieldName, decoded.objAddr, decoded.klassAddr,
                                  decoded.oopCompressed, &fieldInfo)) {
            resumeTargetThreads(suspendedThreads);
            return 0;
        }
        g_fieldInfoCache[cacheKey] = fieldInfo;
    }

    int successCount = 0;
    for (unsigned long long i = 0; i < count; i++) {
        if (oops[i] == 0) continue;
        uint64_t objAddr = decodeRawOopWithMode(oops[i], fieldInfo.oopCompressed);
        if (objAddr == 0) continue;

        uint64_t writeAddr = fieldInfo.isStatic
            ? fieldInfo.staticAddr
            : objAddr + static_cast<uint32_t>(fieldInfo.offset);

        if (writeRemoteMem(g_target.handle, writeAddr, valueBytes, static_cast<size_t>(valueSize))) {
            dirtyCard(writeAddr);
            successCount++;
        }
    }

    resumeTargetThreads(suspendedThreads);

    if (successCount == 0) {
        setError("write_remote_mem_failed");
        return 0;
    }

    setError("ok");
    return 1;
}

// ============================================================
// put_field_path: navigate a field chain from a static root
//
// className:  "com.example.Server" (dot or slash form)
// fieldChain: "INSTANCE.config.maxHealth" (dot-separated)
//
// Resolves className → Klass, then follows each field in the chain
// via RPM. Writes valueBytes to the final field.
// If the final field is a reference type, also dirties the GC card.
// ============================================================

static std::vector<std::string> splitDots(const std::string& s) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start < s.size()) {
        size_t dot = s.find('.', start);
        if (dot == std::string::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, dot - start));
        start = dot + 1;
    }
    return parts;
}

static std::string toInternalClassName(const char* name) {
    std::string result(name);
    for (char& c : result) { if (c == '.') c = '/'; }
    return result;
}

extern "C" __declspec(dllexport) int forgevm_put_field_path(
        const char* className, const char* fieldChain,
        const unsigned char* valueBytes, unsigned long long valueSize) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (className == NULL || fieldChain == NULL || valueBytes == NULL || valueSize == 0) {
        setError("invalid_params");
        return 0;
    }

    HANDLE proc = g_target.handle;
    std::string internalName = toInternalClassName(className);
    std::vector<std::string> fields = splitDots(fieldChain);
    if (fields.empty()) {
        setError("empty_field_chain");
        return 0;
    }

    FVM_LOG("put_field_path: %s -> %s (%llu bytes)", className, fieldChain, valueSize);

    // Step 1: Find the root Klass
    uint64_t currentKlass = 0;
    if (!findInstanceKlassByName(internalName, &currentKlass)) {
        return 0;
    }

    // Step 2: Navigate the chain
    // For each field except the last: resolve field, read OOP, get next Klass
    uint64_t currentObj = 0; // 0 means "reading from Klass (static context)"
    bool isRefWrite = false;

    for (size_t i = 0; i < fields.size(); i++) {
        bool isLast = (i == fields.size() - 1);
        const std::string& fname = fields[i];

        ResolvedField rf = {};
        if (!resolveFieldInKlass(currentKlass, fname, "", &rf)) {
            setError("field_not_found_in_chain:" + fname);
            return 0;
        }

        if (isLast) {
            // Write the value to this field
            uint64_t writeAddr = 0;
            if (rf.isStatic) {
                writeAddr = rf.staticAddress;
            } else {
                if (currentObj == 0) {
                    setError("instance_field_without_object:" + fname);
                    return 0;
                }
                writeAddr = currentObj + rf.offset;
            }

            if (writeAddr == 0) {
                setError("write_addr_zero:" + fname);
                return 0;
            }

            if (!writeRemoteMem(proc, writeAddr, valueBytes, static_cast<size_t>(valueSize))) {
                setError("write_failed:" + fname);
                return 0;
            }

            // If field descriptor starts with L or [, it's a reference — dirty GC card
            isRefWrite = (!rf.descriptor.empty() &&
                          (rf.descriptor[0] == 'L' || rf.descriptor[0] == '['));
            if (isRefWrite) {
                resolveCardTableBase();
                dirtyCard(writeAddr);
            }

            FVM_LOG("put_field_path: wrote %llu bytes to %s at 0x%llX (ref=%d)",
                    valueSize, fname.c_str(), writeAddr, isRefWrite ? 1 : 0);
            setError("ok");
            return 1;
        }

        // Not the last field: read the OOP and follow it
        uint64_t fieldAddr = 0;
        if (rf.isStatic) {
            fieldAddr = rf.staticAddress;
        } else {
            if (currentObj == 0) {
                setError("instance_field_without_object:" + fname);
                return 0;
            }
            fieldAddr = currentObj + rf.offset;
        }

        if (fieldAddr == 0) {
            setError("field_addr_zero:" + fname);
            return 0;
        }

        // Read the OOP value (reference to next object)
        uint64_t nextObj = readOop(proc, fieldAddr, g_target.useCompressedOops);
        if (nextObj == 0) {
            setError("null_ref_in_chain:" + fname);
            return 0;
        }

        // Read Klass from the object header
        uint64_t nextKlass = readKlass(proc, nextObj, g_target.useCompressedClassPointers);
        if (nextKlass == 0) {
            setError("klass_read_failed_in_chain:" + fname);
            return 0;
        }

        currentObj = nextObj;
        currentKlass = nextKlass;
    }

    setError("unexpected_end_of_chain");
    return 0;
}

// ============================================================
// put_object_field_path: read OOP from source path, write to target path
//
// Reads the OOP at sourceClass.sourceField, then writes it to
// targetClass.targetField. Handles compressed oops and GC card dirty.
// ============================================================

extern "C" __declspec(dllexport) int forgevm_put_object_field_path(
        const char* targetClass, const char* targetField,
        const char* sourceClass, const char* sourceField) {
    if (!g_target.structMapReady || g_target.handle == NULL) {
        setError("agent_not_bootstrapped");
        return 0;
    }
    if (targetClass == NULL || targetField == NULL || sourceClass == NULL || sourceField == NULL) {
        setError("invalid_params");
        return 0;
    }

    HANDLE proc = g_target.handle;

    FVM_LOG("put_object_field_path: %s.%s <- %s.%s",
            targetClass, targetField, sourceClass, sourceField);

    // ---- Step 1: Read the source OOP ----

    std::string srcInternal = toInternalClassName(sourceClass);
    std::vector<std::string> srcFields = splitDots(sourceField);
    if (srcFields.empty()) {
        setError("empty_source_field");
        return 0;
    }

    uint64_t srcKlass = 0;
    if (!findInstanceKlassByName(srcInternal, &srcKlass)) {
        setError("source_class_not_found");
        return 0;
    }

    uint64_t srcObj = 0;
    for (size_t i = 0; i < srcFields.size(); i++) {
        const std::string& fname = srcFields[i];
        ResolvedField rf = {};
        if (!resolveFieldInKlass(srcKlass, fname, "", &rf)) {
            setError("source_field_not_found:" + fname);
            return 0;
        }

        uint64_t fieldAddr = 0;
        if (rf.isStatic) {
            fieldAddr = rf.staticAddress;
        } else {
            if (srcObj == 0) {
                setError("source_instance_field_without_object:" + fname);
                return 0;
            }
            fieldAddr = srcObj + rf.offset;
        }

        if (fieldAddr == 0) {
            setError("source_field_addr_zero:" + fname);
            return 0;
        }

        // Read the OOP at this field
        uint64_t nextObj = readOop(proc, fieldAddr, g_target.useCompressedOops);
        if (nextObj == 0) {
            setError("source_null_ref:" + fname);
            return 0;
        }

        if (i < srcFields.size() - 1) {
            // Intermediate field: follow the chain
            uint64_t nextKlass = readKlass(proc, nextObj, g_target.useCompressedClassPointers);
            if (nextKlass == 0) {
                setError("source_klass_read_failed:" + fname);
                return 0;
            }
            srcObj = nextObj;
            srcKlass = nextKlass;
        } else {
            // Last field: this OOP is the value we want to write
            srcObj = nextObj;
        }
    }

    uint64_t sourceOop = srcObj;
    FVM_LOG("put_object_field_path: source OOP = 0x%llX", sourceOop);

    // ---- Step 2: Resolve target field address ----

    std::string tgtInternal = toInternalClassName(targetClass);
    std::vector<std::string> tgtFields = splitDots(targetField);
    if (tgtFields.empty()) {
        setError("empty_target_field");
        return 0;
    }

    uint64_t tgtKlass = 0;
    if (!findInstanceKlassByName(tgtInternal, &tgtKlass)) {
        setError("target_class_not_found");
        return 0;
    }

    uint64_t tgtObj = 0;
    for (size_t i = 0; i < tgtFields.size(); i++) {
        bool isLast = (i == tgtFields.size() - 1);
        const std::string& fname = tgtFields[i];

        ResolvedField rf = {};
        if (!resolveFieldInKlass(tgtKlass, fname, "", &rf)) {
            setError("target_field_not_found:" + fname);
            return 0;
        }

        if (isLast) {
            // Write the source OOP to this field
            uint64_t writeAddr = 0;
            if (rf.isStatic) {
                writeAddr = rf.staticAddress;
            } else {
                if (tgtObj == 0) {
                    setError("target_instance_field_without_object:" + fname);
                    return 0;
                }
                writeAddr = tgtObj + rf.offset;
            }

            if (writeAddr == 0) {
                setError("target_write_addr_zero:" + fname);
                return 0;
            }

            // Encode the OOP value (compressed or raw)
            bool success = false;
            if (g_target.useCompressedOops) {
                uint32_t narrowOop = 0;
                if (sourceOop != 0) {
                    narrowOop = static_cast<uint32_t>(
                        (sourceOop - g_target.narrowOopBase) >> g_target.narrowOopShift);
                }
                success = writeRemoteMem(proc, writeAddr, &narrowOop, sizeof(narrowOop));
                FVM_LOG("put_object_field_path: wrote compressed oop 0x%08X to 0x%llX",
                        narrowOop, writeAddr);
            } else {
                success = writeRemoteMem(proc, writeAddr, &sourceOop, sizeof(sourceOop));
                FVM_LOG("put_object_field_path: wrote raw oop 0x%llX to 0x%llX",
                        sourceOop, writeAddr);
            }

            if (!success) {
                setError("write_failed:" + fname);
                return 0;
            }

            // Dirty GC card table
            resolveCardTableBase();
            dirtyCard(writeAddr);

            FVM_LOG("put_object_field_path: success");
            setError("ok");
            return 1;
        }

        // Not last field: navigate
        uint64_t fieldAddr = 0;
        if (rf.isStatic) {
            fieldAddr = rf.staticAddress;
        } else {
            if (tgtObj == 0) {
                setError("target_instance_field_without_object:" + fname);
                return 0;
            }
            fieldAddr = tgtObj + rf.offset;
        }

        if (fieldAddr == 0) {
            setError("target_field_addr_zero:" + fname);
            return 0;
        }

        uint64_t nextObj = readOop(proc, fieldAddr, g_target.useCompressedOops);
        if (nextObj == 0) {
            setError("target_null_ref_in_chain:" + fname);
            return 0;
        }

        uint64_t nextKlass = readKlass(proc, nextObj, g_target.useCompressedClassPointers);
        if (nextKlass == 0) {
            setError("target_klass_read_failed:" + fname);
            return 0;
        }

        tgtObj = nextObj;
        tgtKlass = nextKlass;
    }

    setError("unexpected_end_of_chain");
    return 0;
}

// ============================================================
// Diagnostic: dump barrier/card related structMap entries
// ============================================================

extern "C" __declspec(dllexport) int forgevm_dump_card_structs() {
    if (!g_target.structMapReady) {
        setError("not_bootstrapped");
        return 0;
    }
    std::string result = "card_structs:[";
    bool first = true;
    for (const auto& kv : g_structMap) {
        const std::string& tn = kv.first.typeName;
        const std::string& fn = kv.first.fieldName;
        bool match = false;
        if (tn.find("arrier") != std::string::npos) match = true;
        if (tn.find("ard") != std::string::npos) match = true;
        if (tn.find("ollected") != std::string::npos) match = true;
        if (fn.find("barrier") != std::string::npos) match = true;
        if (fn.find("card") != std::string::npos) match = true;
        if (fn.find("_byte_map") != std::string::npos) match = true;
        if (match) {
            if (!first) result += ",";
            first = false;
            result += "{\"type\":\"" + tn + "\",\"field\":\"" + fn
                + "\",\"off\":" + std::to_string(kv.second.offset)
                + ",\"static\":" + (kv.second.isStatic ? "true" : "false")
                + ",\"addr\":" + std::to_string(kv.second.address) + "}";
        }
    }
    result += "]";
    setError(result);
    return 1;
}
