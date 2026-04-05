#include "DexHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 4> DEX_HEAD = { 'd', 'e', 'x', '\n' };
constexpr uint32_t DEX_HEADER_SIZE = 0x70;

bool hasDexSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!format_utils::hasBytes(buffer, pos, 8)) {
        return false;
    }

    for (size_t i = 0; i < DEX_HEAD.size(); ++i) {
        if (buffer[pos + i] != DEX_HEAD[i]) {
            return false;
        }
    }

    return buffer[pos + 7] == '\0';
}

bool isSupportedDexVersion(const std::vector<uint8_t>& buffer, size_t pos) {
    return format_utils::hasBytes(buffer, pos + 4, 3) &&
        buffer[pos + 4] >= '0' && buffer[pos + 4] <= '9' &&
        buffer[pos + 5] >= '0' && buffer[pos + 5] <= '9' &&
        buffer[pos + 6] >= '0' && buffer[pos + 6] <= '9';
}
}

std::string DexHandler::type() const {
    return "dex";
}

std::string DexHandler::extension() const {
    return "dex";
}

bool DexHandler::canStartWith(uint8_t value) const {
    return value == 'd';
}

size_t DexHandler::minimumSize() const {
    return DEX_HEADER_SIZE;
}

MatchResult DexHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    if (!format_utils::hasBytes(buffer, position, DEX_HEADER_SIZE)) {
        return isFinalChunk
            ? MatchResult::partial(buffer.size() - position, "partial DEX header")
            : MatchResult::needMoreData();
    }

    if (!hasDexSignature(buffer, position) || !isSupportedDexVersion(buffer, position)) {
        return MatchResult::noMatch();
    }

    const uint32_t fileSize = format_utils::readLe32(buffer, position + 32);
    const uint32_t headerSize = format_utils::readLe32(buffer, position + 36);
    const uint32_t endianTag = format_utils::readLe32(buffer, position + 40);

    if (headerSize != DEX_HEADER_SIZE ||
        (endianTag != 0x12345678U && endianTag != 0x78563412U) ||
        fileSize < DEX_HEADER_SIZE) {
        return MatchResult::noMatch();
    }

    if (!isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::partial(
            buffer.size() - position,
            "valid DEX header, truncated payload");
    }

    return MatchResult::matched(fileSize);
}

FileAnalysis DexHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    if (!format_utils::hasBytes(buffer, position, DEX_HEADER_SIZE)) {
        analysis.warnings.push_back("truncated DEX header");
        return analysis;
    }

    const std::string version(
        reinterpret_cast<const char*>(buffer.data() + position + 4),
        3);
    const uint32_t fileSize = format_utils::readLe32(buffer, position + 32);
    const uint32_t stringIds = format_utils::readLe32(buffer, position + 56);
    const uint32_t methodIds = format_utils::readLe32(buffer, position + 88);
    const uint32_t classDefs = format_utils::readLe32(buffer, position + 96);
    const uint32_t dataSize = format_utils::readLe32(buffer, position + 104);
    const uint32_t endianTag = format_utils::readLe32(buffer, position + 40);

    analysis.metadata.push_back("version=" + version);
    analysis.metadata.push_back(
        "strings=" + std::to_string(stringIds) +
        ", methods=" + std::to_string(methodIds) +
        ", classes=" + std::to_string(classDefs));
    analysis.metadata.push_back(
        "file_size=" + std::to_string(fileSize) +
        ", data_size=" + std::to_string(dataSize));
    analysis.metadata.push_back(
        std::string("endian=") +
        (endianTag == 0x78563412U ? "reverse" : "little"));
    return analysis;
}
