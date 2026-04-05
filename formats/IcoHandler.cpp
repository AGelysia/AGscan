#include "IcoHandler.h"
#include "FormatUtils.h"
#include <algorithm>

namespace {
struct IcoInfo {
    uint16_t count = 0;
    uint32_t maxSize = 0;
};

MatchResult parseIco(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    IcoInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 6)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    if (format_utils::readLe16(buffer, pos) != 0 ||
        format_utils::readLe16(buffer, pos + 2) != 1) {
        return MatchResult::noMatch();
    }

    const uint16_t count = format_utils::readLe16(buffer, pos + 4);
    if (count == 0 || count > 256) {
        return MatchResult::noMatch();
    }

    const size_t dirSize = 6ULL + static_cast<size_t>(count) * 16ULL;
    if (!format_utils::hasBytes(buffer, pos, dirSize)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    uint32_t maxExtent = static_cast<uint32_t>(dirSize);
    for (uint16_t i = 0; i < count; ++i) {
        const size_t entry = pos + 6 + static_cast<size_t>(i) * 16;
        const uint32_t bytesInRes = format_utils::readLe32(buffer, entry + 8);
        const uint32_t imageOffset = format_utils::readLe32(buffer, entry + 12);

        if (bytesInRes == 0 || imageOffset < dirSize) {
            return MatchResult::noMatch();
        }

        if (imageOffset > UINT32_MAX - bytesInRes) {
            return MatchResult::noMatch();
        }

        maxExtent = std::max(maxExtent, imageOffset + bytesInRes);
    }

    if (!isFinalChunk && maxExtent > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && maxExtent > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid ICO directory, truncated image data");
    }

    if (info != nullptr) {
        info->count = count;
        info->maxSize = maxExtent;
    }

    return MatchResult::matched(maxExtent);
}
}

std::string IcoHandler::type() const {
    return "ico";
}

bool IcoHandler::canStartWith(uint8_t value) const {
    return value == 0x00;
}

size_t IcoHandler::minimumSize() const {
    return 22;
}

MatchResult IcoHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    IcoInfo info;
    return parseIco(buffer, position, isFinalChunk, &info);
}

FileAnalysis IcoHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    IcoInfo info;
    const MatchResult result = parseIco(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("ICO analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back("images=" + std::to_string(info.count));
    analysis.metadata.push_back("payload_size=" + std::to_string(info.maxSize));

    std::string sizes = "sizes=";
    for (uint16_t i = 0; i < info.count; ++i) {
        const size_t entry = position + 6 + static_cast<size_t>(i) * 16;
        const uint32_t width = buffer[entry] == 0 ? 256U : buffer[entry];
        const uint32_t height = buffer[entry + 1] == 0 ? 256U : buffer[entry + 1];
        if (i != 0) {
            sizes += ", ";
        }
        sizes += format_utils::dimensionsToString(width, height);
    }

    analysis.metadata.push_back(sizes);
    return analysis;
}
