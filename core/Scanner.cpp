#include "Scanner.h"
#include <algorithm>
#include <unordered_set>

namespace {
std::string makeResultKey(const std::string& type, size_t offset) {
    return type + " at " + std::to_string(offset);
}
}

void Scanner::registerHandler(std::unique_ptr<IFileHandler> handler) {
    handlers_.push_back(std::move(handler));
}

std::vector<ScanResult> Scanner::scan(
    const std::vector<uint8_t>& buffer) {

    std::vector<ScanResult> results;

    for (size_t i = 0; i < buffer.size(); ++i) {
        size_t skip = 1;

        for (const auto& h : handlers_) {
            if (!h->match(buffer, i)) {
                continue;
            }

            const size_t size = h->getSize(buffer, i);
            if (size == 0) {
                continue;
            }

            results.push_back({ h->type(), i, size });
            skip = std::max(skip, size);
        }

        if (skip > 1) {
            i += skip - 1;
        }
    }

    return results;
}

std::vector<ScanResult> Scanner::scanStream(std::istream& input,
    size_t chunkSize,
    size_t overlapSize) {

    if (chunkSize == 0) {
        chunkSize = 1024 * 1024;
    }

    overlapSize = std::min(overlapSize, chunkSize);

    std::vector<ScanResult> results;
    std::unordered_set<std::string> seen;

    std::vector<uint8_t> carry;
    std::vector<uint8_t> chunk(chunkSize);
    size_t fileOffset = 0;

    while (input) {
        input.read(reinterpret_cast<char*>(chunk.data()),
            static_cast<std::streamsize>(chunk.size()));
        const size_t bytesRead = static_cast<size_t>(input.gcount());
        if (bytesRead == 0) {
            break;
        }

        std::vector<uint8_t> window;
        window.reserve(carry.size() + bytesRead);
        window.insert(window.end(), carry.begin(), carry.end());
        window.insert(window.end(), chunk.begin(), chunk.begin() + bytesRead);

        const size_t baseOffset = fileOffset - carry.size();

        for (size_t i = 0; i < window.size(); ++i) {
            size_t skip = 1;

            for (const auto& h : handlers_) {
                if (!h->match(window, i)) {
                    continue;
                }

                const size_t size = h->getSize(window, i);
                if (size == 0) {
                    continue;
                }

                const size_t absoluteOffset = baseOffset + i;
                const std::string key = makeResultKey(h->type(), absoluteOffset); 
                if (seen.insert(key).second) {
                    results.push_back({ h->type(), absoluteOffset, size });
                }

                skip = std::max(skip, size);
            }

            if (skip > 1) {
                i += skip - 1;
            }
        }

        const size_t keep = std::min(overlapSize, window.size());
        carry.assign(window.end() - keep, window.end());
        fileOffset += bytesRead;
    }

    return results;
}
