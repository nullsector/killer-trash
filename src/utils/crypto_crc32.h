#ifndef RAIN_MAKER_WINDOWS_CRYPTO_CRC32_H
#define RAIN_MAKER_WINDOWS_CRYPTO_CRC32_H

#include <windows.h>

class crypto_crc32 {
public:

    crypto_crc32();
    virtual ~crypto_crc32();

    void init();
    void free();
    DWORD stringCRC32(LPCTSTR szString, DWORD &dwCRC32) const;

protected:
    inline void calcCRC32(const BYTE byte, DWORD &dwCRC32) const;
    DWORD *crc32Table;

};


#endif //RAIN_MAKER_WINDOWS_CRYPTO_CRC32_H