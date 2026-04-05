#pragma once
#include <vector>
#include <memory>
#include <string>
#include <istream>
#include "../formats/IFileHandler.h"

struct ScanResult {
    std::string type;
    size_t offset = 0;
    size_t size = 0;
};

class Scanner {
public:
    void registerHandler(std::unique_ptr<IFileHandler> handler);
    std::vector<ScanResult> scan(const std::vector<uint8_t>& buffer);
    std::vector<ScanResult> scanStream(std::istream& input,
        size_t chunkSize = 1024 * 1024,
        size_t overlapSize = 64 * 1024);

private:
    std::vector<std::unique_ptr<IFileHandler>> handlers_;
};
