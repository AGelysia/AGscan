#include "GifHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 6> GIF87A = { 'G', 'I', 'F', '8', '7', 'a' };
constexpr std::array<uint8_t, 6> GIF89A = { 'G', 'I', 'F', '8', '9', 'a' };

bool matchesSignature(const std::vector<uint8_t>& buffer,
    size_t pos,
    const std::array<uint8_t, 6>& signature) {

    if (!format_utils::hasBytes(buffer, pos, signature.size())) {
        return false;
    }

    for (size_t i = 0; i < signature.size(); ++i) {
        if (buffer[pos + i] != signature[i]) {
            return false;
        }
    }

    return true;
}

bool matchesPartialSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (pos >= buffer.size()) {
        return false;
    }

    const size_t available = buffer.size() - pos;
    const auto test = [&](const std::array<uint8_t, 6>& signature) {
        if (available >= signature.size()) {
            return false;
        }

        for (size_t i = 0; i < available; ++i) {
            if (buffer[pos + i] != signature[i]) {
                return false;
            }
        }

        return true;
        };

    return test(GIF87A) || test(GIF89A);
}

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk
        ? MatchResult::partial(0, "valid GIF structure, trailer not found")
        : MatchResult::needMoreData();
}

MatchResult parseGif(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk) {

    if (!format_utils::hasBytes(buffer, pos, GIF87A.size())) {
        if (matchesPartialSignature(buffer, pos) && !isFinalChunk) {
            return MatchResult::needMoreData();
        }
        return MatchResult::noMatch();
    }

    if (!matchesSignature(buffer, pos, GIF87A) &&
        !matchesSignature(buffer, pos, GIF89A)) {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, pos, 13)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid GIF signature, truncated logical screen descriptor")
            : MatchResult::needMoreData();
    }

    size_t cursor = pos + 13;
    const uint8_t packed = buffer[pos + 10];
    if ((packed & 0x80U) != 0) {
        const size_t globalTableSize = 3ULL << ((packed & 0x07U) + 1U);
        if (!format_utils::hasBytes(buffer, cursor, globalTableSize)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid GIF header, truncated global color table")
                : MatchResult::needMoreData();
        }
        cursor += globalTableSize;
    }

    while (true) {
        if (!format_utils::hasBytes(buffer, cursor, 1)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid GIF structure, trailer not found")
                : MatchResult::needMoreData();
        }

        const uint8_t introducer = buffer[cursor++];
        if (introducer == 0x3B) {
            return MatchResult::matched(cursor - pos);
        }

        if (introducer == 0x2C) {
            if (!format_utils::hasBytes(buffer, cursor, 9)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid GIF image descriptor, truncated payload")
                    : MatchResult::needMoreData();
            }

            const uint8_t localPacked = buffer[cursor + 8];
            cursor += 9;

            if ((localPacked & 0x80U) != 0) {
                const size_t localTableSize = 3ULL << ((localPacked & 0x07U) + 1U);
                if (!format_utils::hasBytes(buffer, cursor, localTableSize)) {
                    return isFinalChunk
                        ? MatchResult::partial(
                            buffer.size() - pos,
                            "valid GIF local color table, truncated payload")
                        : MatchResult::needMoreData();
                }
                cursor += localTableSize;
            }

            if (!format_utils::hasBytes(buffer, cursor, 1)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid GIF image data header, truncated payload")
                    : MatchResult::needMoreData();
            }
            ++cursor;
        }
        else if (introducer == 0x21) {
            if (!format_utils::hasBytes(buffer, cursor, 1)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid GIF extension block, truncated payload")
                    : MatchResult::needMoreData();
            }
            ++cursor;
        }
        else {
            return MatchResult::noMatch();
        }

        while (true) {
            if (!format_utils::hasBytes(buffer, cursor, 1)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid GIF sub-block chain, truncated payload")
                    : MatchResult::needMoreData();
            }

            const uint8_t blockSize = buffer[cursor++];
            if (blockSize == 0) {
                break;
            }

            if (!format_utils::hasBytes(buffer, cursor, blockSize)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid GIF data sub-block, truncated payload")
                    : MatchResult::needMoreData();
            }
            cursor += blockSize;
        }
    }
}
}

std::string GifHandler::type() const {
    return "gif";
}

bool GifHandler::canStartWith(uint8_t value) const {
    return value == 'G';
}

size_t GifHandler::minimumSize() const {
    return 13;
}

MatchResult GifHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    return parseGif(buffer, position, isFinalChunk);
}

FileAnalysis GifHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    if (!format_utils::hasBytes(buffer, position, 13)) {
        analysis.warnings.push_back("truncated GIF header");
        return analysis;
    }

    const std::string version(
        reinterpret_cast<const char*>(buffer.data() + position),
        6);
    const uint16_t width = format_utils::readLe16(buffer, position + 6);
    const uint16_t height = format_utils::readLe16(buffer, position + 8);
    const uint8_t packed = buffer[position + 10];
    const uint8_t backgroundIndex = buffer[position + 11];
    const uint8_t aspect = buffer[position + 12];

    analysis.metadata.push_back("version=" + version);
    analysis.metadata.push_back(
        "dimensions=" + format_utils::dimensionsToString(width, height));
    analysis.metadata.push_back(
        std::string("global_palette=") +
        (((packed & 0x80U) != 0) ? "yes" : "no"));
    analysis.metadata.push_back(
        "background_index=" + std::to_string(backgroundIndex) +
        ", aspect_byte=" + std::to_string(aspect));
    return analysis;
}
