#ifndef RAIN_MAKER_WINDOWS_PROCESS_H
#define RAIN_MAKER_WINDOWS_PROCESS_H

#include <windows.h>

class ProcessUtils {
public:
    static int FindProcessExecutable(PCSTR target_process, LPSTR path);
    static int GetPayload();
};



#endif //RAIN_MAKER_WINDOWS_PROCESS_H
