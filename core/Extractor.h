#pragma once
#include <vector>
#include <string>
#include "Scanner.h"

class Extractor {
public:
    static void extract(const std::vector<uint8_t>& buffer,
        const std::vector<ScanResult>& results,
        const std::string& outputDir);
};