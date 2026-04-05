#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include "core/Scanner.h"
#include "core/Extractor.h"
#include "formats/PngHandler.h"

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cout << "Usage: agscan <file> scan|extract\n";
        return 0;
    }

    std::string input = argv[1];
    std::string mode = argv[2];

    Scanner scanner;
    scanner.registerHandler(std::make_unique<PngHandler>());

    if (mode == "scan") {
        std::ifstream file(input, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open input file: " << input << "\n";
            return 1;
        }

        auto results = scanner.scanStream(file);
        for (const auto& r : results) {
            std::cout << r.type
                << " at 0x"
                << std::hex << r.offset
                << " size "
                << std::dec << r.size
                << "\n";
        }
    }
    else if (mode == "extract") {
        auto buffer = readFile(input);
        auto results = scanner.scan(buffer);
        Extractor::extract(buffer, results, "out");
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}
