#include "BmpHandler.h"
#include "FormatUtils.h"
#include <cstdint>

namespace {
MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk
        ? MatchResult::partial(0, "partial BMP signature or header")
        : MatchResult::needMoreData();
}

bool matchesPartialSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    return pos < buffer.size() && buffer[pos] == 'B' && pos + 1 == buffer.size();
}

int32_t readLe32Signed(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<int32_t>(format_utils::readLe32(buffer, pos));
}

const char* bmpCompressionName(uint32_t value) {
    switch (value) {
    case 0:
        return "BI_RGB";
    case 1:
        return "BI_RLE8";
    case 2:
        return "BI_RLE4";
    case 3:
        return "BI_BITFIELDS";
    case 4:
        return "BI_JPEG";
    case 5:
        return "BI_PNG";
    default:
        return "UNKNOWN";
    }
}
}

std::string BmpHandler::type() const {
    return "bmp";
}

bool BmpHandler::canStartWith(uint8_t value) const {
    return value == 'B';
}

size_t BmpHandler::minimumSize() const {
    return 26;
}

MatchResult BmpHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    if (!format_utils::hasBytes(buffer, position, 2)) {
        if (matchesPartialSignature(buffer, position) && !isFinalChunk) {
            return MatchResult::needMoreData();
        }
        return MatchResult::noMatch();
    }

    if (buffer[position] != 'B' || buffer[position + 1] != 'M') {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, position, minimumSize())) {
        return incomplete(isFinalChunk);
    }

    const uint32_t fileSize = format_utils::readLe32(buffer, position + 2);
    const uint32_t pixelOffset = format_utils::readLe32(buffer, position + 10);
    const uint32_t dibSize = format_utils::readLe32(buffer, position + 14);
    if (fileSize < minimumSize() ||
        pixelOffset < 14 ||
        dibSize < 12 ||
        pixelOffset > fileSize) {
        return MatchResult::noMatch();
    }

    if (!isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::partial(
            buffer.size() - position,
            "valid BMP header, truncated payload");
    }

    return MatchResult::matched(fileSize);
}

FileAnalysis BmpHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    if (!format_utils::hasBytes(buffer, position, minimumSize())) {
        analysis.warnings.push_back("truncated BMP header");
        return analysis;
    }

    const uint32_t dibSize = format_utils::readLe32(buffer, position + 14);
    const uint32_t fileSize = format_utils::readLe32(buffer, position + 2);
    const uint32_t pixelOffset = format_utils::readLe32(buffer, position + 10);
    uint32_t width = 0;
    uint32_t height = 0;
    uint16_t bitsPerPixel = 0;
    uint32_t compression = 0;
    std::string orientation = "top-down";

    if (dibSize == 12 && format_utils::hasBytes(buffer, position + 14, 12)) {
        width = format_utils::readLe16(buffer, position + 18);
        height = format_utils::readLe16(buffer, position + 20);
        bitsPerPixel = format_utils::readLe16(buffer, position + 24);
    }
    else if (dibSize >= 40 && format_utils::hasBytes(buffer, position + 14, 40)) {
        width = static_cast<uint32_t>(readLe32Signed(buffer, position + 18));
        const int32_t signedHeight = readLe32Signed(buffer, position + 22);
        height = static_cast<uint32_t>(signedHeight < 0 ? -signedHeight : signedHeight);
        bitsPerPixel = format_utils::readLe16(buffer, position + 28);
        compression = format_utils::readLe32(buffer, position + 30);
        orientation = signedHeight < 0 ? "top-down" : "bottom-up";
    }

    analysis.metadata.push_back(
        "dimensions=" + format_utils::dimensionsToString(width, height));
    analysis.metadata.push_back(
        "dib_header=" + std::to_string(dibSize) +
        ", bpp=" + std::to_string(bitsPerPixel));
    analysis.metadata.push_back(
        "compression=" + std::string(bmpCompressionName(compression)) +
        ", pixel_offset=" + std::to_string(pixelOffset));
    analysis.metadata.push_back("file_size=" + std::to_string(fileSize));
    analysis.metadata.push_back("orientation=" + orientation);
    return analysis;
}
