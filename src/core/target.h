#ifndef RAIN_MAKER_WINDOWS_TARGET_H
#define RAIN_MAKER_WINDOWS_TARGET_H

#include <filesystem>

class target {
private:
    std::filesystem::path target_path;

public:
    std::filesystem::path& getTargetPath();
};


#endif //RAIN_MAKER_WINDOWS_TARGET_H

