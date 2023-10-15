#ifndef RAIN_MAKER_WINDOWS_BUNDLE_H
#define RAIN_MAKER_WINDOWS_BUNDLE_H

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <memory>

// Full description of LDR_DATA_TABLE_ENTRY as the one defined in winternl.h in partially defined/opaque.
typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT * EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _PAYLOAD {
    std::string js;
    uint32_t crc;
    uint32_t size;
} PAYLOAD, *PPAYLOAD;

class bundle {
private:
    uint8_t *bundleAddress;
    uint32_t bundleSize;

    void setBundleSize(uint32_t size);
    void setBundleAddress(uint8_t* address);

public:
    [[nodiscard]] DWORD getBundleSize() const;
    uint8_t *getPayloadAddress();
    static std::unique_ptr<bundle> findBundle();
    static bool extractPayload(std::unique_ptr<bundle>& blob);
    static bool verifyHeader(const std::vector<uint8_t> &blob, const std::vector<uint8_t> &header);
    static uint32_t extractPayloadSize(const std::vector<uint8_t> &blob);
    static uint32_t extractPayloadCRC32(const std::vector<uint8_t> &blob);
    static std::string extractJS(const std::vector<uint8_t> &blob, const std::vector<uint8_t> &key, uint32_t size);
    bundle(uint8_t *payloadAddress, DWORD payloadSize);

};

#endif //RAIN_MAKER_WINDOWS_BUNDLE_H

