#include "PngHandler.h"

namespace {
constexpr uint8_t PNG_HEAD[8] =
{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

uint32_t readBe32(const std::vector<uint8_t>& buffer, size_t pos) {
    return (static_cast<uint32_t>(buffer[pos]) << 24) |
        (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
        (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
        static_cast<uint32_t>(buffer[pos + 3]);
}

bool hasPngSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (pos + 8 > buffer.size()) {
        return false;
    }

    for (size_t i = 0; i < 8; ++i) {
        if (buffer[pos + i] != PNG_HEAD[i]) {
            return false;
        }
    }

    return true;
}
}

std::string PngHandler::type() const {
    return "png";
}

bool PngHandler::match(const std::vector<uint8_t>& buffer,
    size_t pos) const {

    if (!hasPngSignature(buffer, pos)) {
        return false;
    }

    // Fast sanity check for IHDR chunk.
    if (pos + 8 + 12 + 13 > buffer.size()) {
        return false;
    }

    const size_t firstChunk = pos + 8;
    const uint32_t firstLen = readBe32(buffer, firstChunk);
    if (firstLen != 13) {
        return false;
    }

    return buffer[firstChunk + 4] == 'I' &&
        buffer[firstChunk + 5] == 'H' &&
        buffer[firstChunk + 6] == 'D' &&
        buffer[firstChunk + 7] == 'R';
}

size_t PngHandler::getSize(const std::vector<uint8_t>& buffer,
    size_t pos) const {

    if (!hasPngSignature(buffer, pos)) {
        return 0;
    }

    size_t cursor = pos + 8;
    bool seenIHDR = false;

    while (cursor + 12 <= buffer.size()) {
        const uint32_t length = readBe32(buffer, cursor);

        if (length > buffer.size()) {
            return 0;
        }

        const size_t chunkTotal = static_cast<size_t>(length) + 12;
        if (cursor + chunkTotal > buffer.size()) {
            return 0;
        }

        const uint8_t c0 = buffer[cursor + 4];
        const uint8_t c1 = buffer[cursor + 5];
        const uint8_t c2 = buffer[cursor + 6];
        const uint8_t c3 = buffer[cursor + 7];

        if (!seenIHDR) {
            if (!(c0 == 'I' && c1 == 'H' && c2 == 'D' && c3 == 'R' && length == 13)) {
                return 0;
            }
            seenIHDR = true;
        }

        cursor += chunkTotal;

        if (c0 == 'I' && c1 == 'E' && c2 == 'N' && c3 == 'D') {
            return cursor - pos;
        }
    }

    return 0;
}
