#include <tchar.h>
#include "crypto_crc32.h"

void crypto_crc32::init() {

    // Official polynomial used by CRC32 in PKZip.
    DWORD polynomial = 0xEDB88320;
    crc32Table = new DWORD[256];

    DWORD crc;
    for (int i = 0; i < 256; i++) {
        crc = i;
        for (int j = 8; j > 0; j--) {
            if (crc & 1)
                crc = (crc >> 1) ^ polynomial;
            else
                crc >>= 1;
        }
        crc32Table[i] = crc;
    }
}

DWORD crypto_crc32::stringCRC32(LPCTSTR szString, DWORD &dwCRC32) const {

    DWORD errorCode = NO_ERROR;
    dwCRC32 = 0xFFFFFFFF;

    try {
        // Is the table init'd
        if (crc32Table == nullptr)
            throw 0;

        while (*szString != _T('\0')) {
            calcCRC32((BYTE)*szString, dwCRC32);
            szString++;
        }
    } catch (...) {
        // Unknown exception, or table is not init'd
        errorCode = ERROR_CRC;
    }

    dwCRC32 = ~dwCRC32;
    return dwCRC32;
}

void crypto_crc32::calcCRC32(const BYTE byte, DWORD &dwCRC32) const {

    dwCRC32 = ((dwCRC32) >> 8) ^ crc32Table[(byte) ^ ((dwCRC32) & 0x000000FF)];
}

crypto_crc32::crypto_crc32() : crc32Table(nullptr) {}

crypto_crc32::~crypto_crc32() {
    free();
}

void crypto_crc32::free() {
    delete crc32Table;
    crc32Table = nullptr;
}
