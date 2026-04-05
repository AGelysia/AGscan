#include "SevenZipHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 6> SEVEN_Z_SIG =
{ 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };

bool hasSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!format_utils::hasBytes(buffer, pos, SEVEN_Z_SIG.size())) {
        return false;
    }

    for (size_t i = 0; i < SEVEN_Z_SIG.size(); ++i) {
        if (buffer[pos + i] != SEVEN_Z_SIG[i]) {
            return false;
        }
    }

    return true;
}

MatchResult parseSevenZip(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    bool* startHeaderCrcValid) {

    if (!format_utils::hasBytes(buffer, pos, 32)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    if (!hasSignature(buffer, pos)) {
        return MatchResult::noMatch();
    }

    const uint8_t major = buffer[pos + 6];
    const uint8_t minor = buffer[pos + 7];
    if (major != 0 || minor > 5) {
        return MatchResult::noMatch();
    }

    const uint32_t storedCrc = format_utils::readLe32(buffer, pos + 8);
    const uint32_t computedCrc = format_utils::crc32(buffer, pos + 12, 20);
    if (startHeaderCrcValid != nullptr) {
        *startHeaderCrcValid = storedCrc == computedCrc;
    }

    const uint64_t nextHeaderOffset = format_utils::readLe64(buffer, pos + 12);
    const uint64_t nextHeaderSize = format_utils::readLe64(buffer, pos + 20);
    if (nextHeaderOffset > (1ULL << 34) || nextHeaderSize > (1ULL << 34)) {
        return MatchResult::noMatch();
    }

    const uint64_t totalSize = 32ULL + nextHeaderOffset + nextHeaderSize;
    if (totalSize < 32ULL) {
        return MatchResult::noMatch();
    }

    if (!isFinalChunk && totalSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && totalSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid 7z start header, truncated next-header region");
    }

    return MatchResult::matched(static_cast<size_t>(totalSize));
}
}

std::string SevenZipHandler::type() const {
    return "7z";
}

std::string SevenZipHandler::extension() const {
    return "7z";
}

bool SevenZipHandler::canStartWith(uint8_t value) const {
    return value == SEVEN_Z_SIG[0];
}

size_t SevenZipHandler::minimumSize() const {
    return 32;
}

MatchResult SevenZipHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    bool unused = false;
    return parseSevenZip(buffer, position, isFinalChunk, &unused);
}

FileAnalysis SevenZipHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    bool startHeaderCrcValid = false;
    const MatchResult result = parseSevenZip(buffer, position, true, &startHeaderCrcValid);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("7z analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        "version=" + std::to_string(buffer[position + 6]) +
        "." + std::to_string(buffer[position + 7]));
    analysis.metadata.push_back(
        "next_header_size=" +
        std::to_string(format_utils::readLe64(buffer, position + 20)));
    analysis.metadata.push_back(
        "next_header_offset=" +
        std::to_string(format_utils::readLe64(buffer, position + 12)));
    analysis.metadata.push_back(
        std::string("start_header_crc=") +
        (startHeaderCrcValid ? "ok" : "mismatch"));
    return analysis;
}
