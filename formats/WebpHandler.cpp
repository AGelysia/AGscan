#include "WebpHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 4> RIFF = { 'R', 'I', 'F', 'F' };
constexpr std::array<uint8_t, 4> WEBP = { 'W', 'E', 'B', 'P' };

struct WebpInfo {
    uint32_t width = 0;
    uint32_t height = 0;
    std::string chunkKind;
    bool hasAlpha = false;
    bool animated = false;
};

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
}

bool hasSignature(const std::vector<uint8_t>& buffer,
    size_t pos,
    const std::array<uint8_t, 4>& signature) {

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

MatchResult parseWebp(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    WebpInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 12)) {
        return incomplete(isFinalChunk);
    }

    if (!hasSignature(buffer, pos, RIFF) ||
        !hasSignature(buffer, pos + 8, WEBP)) {
        return MatchResult::noMatch();
    }

    const size_t fileSize =
        static_cast<size_t>(format_utils::readLe32(buffer, pos + 4)) + 8;
    if (fileSize < 20) {
        return MatchResult::noMatch();
    }

    if (!isFinalChunk && fileSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && fileSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid WEBP RIFF header, truncated payload");
    }

    const size_t end = pos + fileSize;
    size_t cursor = pos + 12;
    bool foundImageChunk = false;

    while (cursor + 8 <= end) {
        const size_t chunkData = cursor + 8;
        const uint32_t chunkSize = format_utils::readLe32(buffer, cursor + 4);
        const size_t paddedChunkSize =
            static_cast<size_t>(chunkSize) + (chunkSize & 1U);

        if (chunkData + paddedChunkSize > end) {
            return MatchResult::partial(
                std::min(end, buffer.size()) - pos,
                "valid WEBP container, truncated chunk data");
        }

        const std::string fourcc(
            reinterpret_cast<const char*>(buffer.data() + cursor),
            4);

        if (fourcc == "VP8X" && chunkSize >= 10 && info != nullptr) {
            info->chunkKind = "VP8X";
            info->hasAlpha = (buffer[chunkData] & 0x10U) != 0;
            info->animated = (buffer[chunkData] & 0x02U) != 0;
            info->width = 1 + format_utils::readLe24(buffer, chunkData + 4);
            info->height = 1 + format_utils::readLe24(buffer, chunkData + 7);
            foundImageChunk = true;
        }
        else if (fourcc == "VP8 " && chunkSize >= 10 && info != nullptr) {
            if (buffer[chunkData + 3] == 0x9D &&
                buffer[chunkData + 4] == 0x01 &&
                buffer[chunkData + 5] == 0x2A) {
                info->chunkKind = "VP8";
                info->width = format_utils::readLe16(buffer, chunkData + 6) & 0x3FFFU;
                info->height = format_utils::readLe16(buffer, chunkData + 8) & 0x3FFFU;
                foundImageChunk = true;
            }
        }
        else if (fourcc == "VP8L" && chunkSize >= 5 && info != nullptr) {
            if (buffer[chunkData] == 0x2F) {
                const uint8_t b1 = buffer[chunkData + 1];
                const uint8_t b2 = buffer[chunkData + 2];
                const uint8_t b3 = buffer[chunkData + 3];
                const uint8_t b4 = buffer[chunkData + 4];
                info->chunkKind = "VP8L";
                info->width = 1 + (static_cast<uint32_t>(b1) |
                    ((static_cast<uint32_t>(b2) & 0x3FU) << 8));
                info->height = 1 + ((static_cast<uint32_t>(b2) >> 6) |
                    (static_cast<uint32_t>(b3) << 2) |
                    ((static_cast<uint32_t>(b4) & 0x0FU) << 10));
                foundImageChunk = true;
            }
        }

        if (fourcc == "VP8 " || fourcc == "VP8L" || fourcc == "VP8X") {
            foundImageChunk = true;
        }

        cursor = chunkData + paddedChunkSize;
    }

    return foundImageChunk ? MatchResult::matched(fileSize) : MatchResult::noMatch();
}
}

std::string WebpHandler::type() const {
    return "webp";
}

bool WebpHandler::canStartWith(uint8_t value) const {
    return value == 'R';
}

size_t WebpHandler::minimumSize() const {
    return 20;
}

MatchResult WebpHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    WebpInfo info;
    return parseWebp(buffer, position, isFinalChunk, &info);
}

FileAnalysis WebpHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    WebpInfo info;
    const MatchResult result = parseWebp(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("WEBP analysis failed on carved payload");
        return analysis;
    }

    if (info.width != 0 && info.height != 0) {
        analysis.metadata.push_back(
            "dimensions=" + format_utils::dimensionsToString(info.width, info.height));
    }
    if (!info.chunkKind.empty()) {
        analysis.metadata.push_back("variant=" + info.chunkKind);
    }
    if (info.chunkKind == "VP8X") {
        analysis.metadata.push_back(
            std::string("alpha=") + (info.hasAlpha ? "yes" : "no") +
            ", animated=" + (info.animated ? "yes" : "no"));
    }
    return analysis;
}
