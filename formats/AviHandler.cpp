#include "AviHandler.h"
#include "FormatUtils.h"
#include <array>
#include <sstream>

namespace {
constexpr std::array<uint8_t, 4> RIFF = { 'R', 'I', 'F', 'F' };
constexpr std::array<uint8_t, 4> AVI = { 'A', 'V', 'I', ' ' };

bool hasFourcc(const std::vector<uint8_t>& buffer,
    size_t pos,
    const std::array<uint8_t, 4>& value) {

    if (!format_utils::hasBytes(buffer, pos, value.size())) {
        return false;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        if (buffer[pos + i] != value[i]) {
            return false;
        }
    }

    return true;
}

MatchResult parseAvi(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk) {

    if (!format_utils::hasBytes(buffer, pos, 12)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    if (!hasFourcc(buffer, pos, RIFF) || !hasFourcc(buffer, pos + 8, AVI)) {
        return MatchResult::noMatch();
    }

    const size_t totalSize =
        static_cast<size_t>(format_utils::readLe32(buffer, pos + 4)) + 8;
    if (totalSize < 12) {
        return MatchResult::noMatch();
    }

    if (!isFinalChunk && totalSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && totalSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid RIFF/AVI header, truncated payload");
    }

    return MatchResult::matched(totalSize);
}
}

std::string AviHandler::type() const {
    return "avi";
}

bool AviHandler::canStartWith(uint8_t value) const {
    return value == 'R';
}

size_t AviHandler::minimumSize() const {
    return 12;
}

MatchResult AviHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    return parseAvi(buffer, position, isFinalChunk);
}

FileAnalysis AviHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t size) const {

    FileAnalysis analysis;
    const size_t end = position + size;

    for (size_t cursor = position + 12; cursor + 8 <= end; ++cursor) {
        if (buffer[cursor] != 'a' ||
            buffer[cursor + 1] != 'v' ||
            buffer[cursor + 2] != 'i' ||
            buffer[cursor + 3] != 'h') {
            continue;
        }

        const uint32_t chunkSize = format_utils::readLe32(buffer, cursor + 4);
        if (chunkSize < 56 || cursor + 8 + chunkSize > end) {
            continue;
        }

        const size_t data = cursor + 8;
        const uint32_t microSecPerFrame = format_utils::readLe32(buffer, data);
        const uint32_t totalFrames = format_utils::readLe32(buffer, data + 16);
        const uint32_t streams = format_utils::readLe32(buffer, data + 24);
        const uint32_t width = format_utils::readLe32(buffer, data + 32);
        const uint32_t height = format_utils::readLe32(buffer, data + 36);

        analysis.metadata.push_back(
            "dimensions=" + format_utils::dimensionsToString(width, height));
        analysis.metadata.push_back(
            "frames=" + std::to_string(totalFrames) +
            ", streams=" + std::to_string(streams));

        if (microSecPerFrame != 0 && totalFrames != 0) {
            std::ostringstream out;
            out.setf(std::ios::fixed);
            out.precision(3);
            out << "duration="
                << (static_cast<double>(microSecPerFrame) * totalFrames / 1000000.0)
                << "s";
            analysis.metadata.push_back(out.str());
            out.str({});
            out.clear();
            out << "frame_rate=" << (1000000.0 / microSecPerFrame);
            analysis.metadata.push_back(out.str());
        }

        return analysis;
    }

    analysis.warnings.push_back("AVI main header not found");
    return analysis;
}
