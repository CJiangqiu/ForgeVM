#pragma once

#include <windows.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

// ============================================================
// Error state
// ============================================================

extern std::string g_lastError;
extern bool g_promptApproved;

void setError(const char* value);
void setError(const std::string& value);

// ============================================================
// Target process state
// ============================================================

struct TargetProcess {
    HANDLE handle = NULL;
    DWORD pid = 0;
    uint64_t jvmDllBase = 0;
    uint64_t jvmDllSize = 0;
    bool structMapReady = false;
    bool useCompressedOops = false;
    bool useCompressedClassPointers = false;
    uint64_t narrowOopBase = 0;
    int narrowOopShift = 0;
    uint64_t narrowKlassBase = 0;
    int narrowKlassShift = 0;
};

extern TargetProcess g_target;

// ============================================================
// StructMap / TypeMap / Constants
// ============================================================

struct StructMapKey {
    std::string typeName;
    std::string fieldName;
    bool operator==(const StructMapKey& o) const {
        return typeName == o.typeName && fieldName == o.fieldName;
    }
};

struct StructMapKeyHash {
    size_t operator()(const StructMapKey& k) const {
        size_t h1 = std::hash<std::string>{}(k.typeName);
        size_t h2 = std::hash<std::string>{}(k.fieldName);
        return h1 ^ (h2 * 2654435761ULL);
    }
};

struct StructMapEntry {
    std::string typeName;
    std::string fieldName;
    bool isStatic;
    int64_t offset;
    uint64_t address;
};

struct TypeMapEntry {
    std::string typeName;
    int64_t size;
};

extern std::unordered_map<StructMapKey, StructMapEntry, StructMapKeyHash> g_structMap;
extern std::unordered_map<std::string, TypeMapEntry> g_typeMap;
extern std::unordered_map<std::string, int64_t> g_intConstants;
extern std::unordered_map<std::string, int64_t> g_longConstants;

// ============================================================
// Field resolution structs & cache
// ============================================================

struct ResolvedField {
    std::string fieldName;
    std::string descriptor;
    int32_t offset;
    uint64_t staticAddress;
    uint64_t klassAddr;
    bool isStatic;
    int32_t fieldSize;
};

struct CachedFieldInfo {
    int32_t offset;
    bool isStatic;
    uint64_t staticAddr;
    bool oopCompressed;
};

extern std::unordered_map<std::string, CachedFieldInfo> g_fieldInfoCache;

// ============================================================
// Compression detection diagnostic
// ============================================================

extern std::string g_compressionDetectLog;

// ============================================================
// StructMap lookup helpers
// ============================================================

bool structLookup(const std::string& typeName, const std::string& fieldName, StructMapEntry* out);
int64_t structOffset(const std::string& typeName, const std::string& fieldName);
uint64_t structStaticAddr(const std::string& typeName, const std::string& fieldName);
int64_t typeSize(const std::string& typeName);
int64_t intConst(const std::string& name, int64_t fallback = -1);
int64_t longConst(const std::string& name, int64_t fallback = -1);

// ============================================================
// Remote memory helpers
// ============================================================

bool readRemoteMem(HANDLE proc, uint64_t addr, void* buf, size_t size);
bool writeRemoteMem(HANDLE proc, uint64_t addr, const void* buf, size_t size);
bool readRemotePointer(HANDLE proc, uint64_t addr, uint64_t* out);
bool readRemoteU32(HANDLE proc, uint64_t addr, uint32_t* out);
bool readRemoteI32(HANDLE proc, uint64_t addr, int32_t* out);
bool readRemoteU16(HANDLE proc, uint64_t addr, uint16_t* out);
bool readRemoteString(HANDLE proc, uint64_t addr, std::string* out, size_t maxLen = 512);

// ============================================================
// Compressed oop/klass decode
// ============================================================

uint64_t decodeNarrowOop(uint32_t narrow);
uint64_t decodeRawOop(uint64_t rawOop);
uint64_t decodeRawOopWithMode(uint64_t rawOop, bool compressed);
uint64_t decodeNarrowKlass(uint32_t narrow);
uint64_t readOop(HANDLE proc, uint64_t addr, bool compressed);
uint64_t readKlass(HANDLE proc, uint64_t addr, bool compressed);

// ============================================================
// OOP/Klass resolution
// ============================================================

struct DecodedObjectInfo {
    uint64_t objAddr;
    uint64_t klassAddr;
    bool oopCompressed;
    bool klassCompressed;
};

bool looksLikeValidKlass(HANDLE proc, uint64_t klassAddr);
bool resolveObjectAndKlassFromRawOop(uint64_t rawOop, DecodedObjectInfo* out);

// ============================================================
// Thread suspend/resume
// ============================================================

bool suspendTargetThreads(DWORD pid, std::vector<DWORD>& threadIds);
void resumeTargetThreads(const std::vector<DWORD>& threadIds);

// ============================================================
// Field resolution
// ============================================================

bool readSymbolBody(HANDLE proc, uint64_t symbolAddr, std::string* out);
int32_t fieldSizeFromDescriptor(const std::string& desc);
bool resolveFieldInKlass(uint64_t klassAddr, const std::string& fieldName,
                         const std::string& descriptor, ResolvedField* out);
bool resolveAndCacheField(const char* fieldName, uint64_t objAddr,
                          uint64_t klassAddr, bool oopCompressed, CachedFieldInfo* out);

// ============================================================
// Privilege helpers
// ============================================================

bool isAdmin();
bool enableDebugPrivilege();
int resolveCapabilityByToken();

// ============================================================
// Module / PE helpers
// ============================================================

bool findModuleBase(HANDLE proc, const wchar_t* moduleName, uint64_t* base, uint64_t* moduleSize);
bool parsePEExport(HANDLE proc, uint64_t moduleBase, const char* symbolName, uint64_t* outAddr);

// ============================================================
// Compression params extraction
// ============================================================

void extractCompressionParams();
