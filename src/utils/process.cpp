#include "process.h"

#include <iostream>

#include <tlhelp32.h>
#include <psapi.h>

using namespace std;

int ProcessUtils::FindProcessExecutable(PCSTR target_process, LPSTR path) {

    cout << "Looking for " << target_process << endl;
    DWORD pid = 0;
    HANDLE processHandle = nullptr;

    // Create a snapshot of all processes running on the system.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32  process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Enumerate all of the processes until we find target_process
    if (Process32First(snapshot, &process)) {
        do {
            if(string(process.szExeFile) == string(target_process)) {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    // Responsible for snapshot cleanup
    CloseHandle(snapshot);

    if (pid != 0) {
        cout << "Found " << target_process << endl;
        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    } else {
        cerr << "Failed to find " << target_process << endl;
        return -1;
    }

    if (GetModuleFileNameEx(processHandle, nullptr, path, MAX_PATH) == 0) {
        cerr << "Failed to find " << target_process << "full path."  << endl;
        return -1;
    } else {
        cout << target_process << " full path is " << path << endl;
    }

    CloseHandle(processHandle);
    return 0;

}

int ProcessUtils::GetPayload() {
    return 0;
}