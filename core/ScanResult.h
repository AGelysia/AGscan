#pragma once
#include <string>
#include <vector>

struct FileFixInfo {
    std::vector<std::string> metadata;
    std::vector<std::string> warnings;
};

struct ScanResult {
    std::string type;
    size_t offset;
    size_t size;

    ScanResult(const std::string& t,
        size_t o,
        size_t s)
        : type(t), offset(o), size(s) {
    }
};