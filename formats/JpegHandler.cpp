#include "JpegHandler.h"

static const uint8_t PNG_HEAD[8] =
{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

std::string JpegHandler::type() const {
    return "jpg";
}

bool JpegHandler::match(const std::vector<uint8_t>& buffer,
    size_t pos) const {
    if (pos + 8 > buffer.size())
        return false;

    for (int i = 0; i < 8; ++i)
        if (buffer[pos + i] != PNG_HEAD[i])
            return false;

    for (int p = 0; p < buffer.size() - pos; ++p) {
        if (buffer[pos + p] != 'I' &&
            buffer[pos + p + 1] != 'E' &&
            buffer[pos + p + 2] != 'N' &&
            buffer[pos + p + 3] != 'D') {
            return false;
        }
    }

    return true;
}

size_t JpegHandler::getSize(const std::vector<uint8_t>& buffer,
    size_t pos) const {
    for (size_t i = pos + 8; i + 12 < buffer.size(); ++i) {
        if (buffer[i] == 'I' &&
            buffer[i + 1] == 'E' &&
            buffer[i + 2] == 'N' &&
            buffer[i + 3] == 'D') {
            return (i + 8) - pos;
        }
    }
    return 0;
}