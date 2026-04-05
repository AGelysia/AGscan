#include "Extractor.h"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

void Extractor::extract(const std::vector<uint8_t>& buffer,
    const std::vector<ScanResult>& results,
    const std::string& outputDir) {

    fs::create_directories(outputDir);

    int counter = 0;

    for (const auto& r : results) {
        std::string filename =
            outputDir + "/" +
            r.type + "_" +
            std::to_string(counter++) + "." +
            r.type;

        std::ofstream out(filename, std::ios::binary);

        out.write(reinterpret_cast<const char*>(
            buffer.data() + r.offset),
            r.size);
    }
}