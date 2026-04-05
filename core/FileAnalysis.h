#pragma once
#include <string>
#include <vector>

struct FileAnalysis {
    std::vector<std::string> metadata;
    std::vector<std::string> warnings;

    bool empty() const {
        return metadata.empty() && warnings.empty();
    }
};
