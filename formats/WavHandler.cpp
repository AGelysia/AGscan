#include "WavHandler.h"
#include "FormatUtils.h"
#include <array>
#include <sstream>

namespace {
constexpr std::array<uint8_t, 4> RIFF = { 'R', 'I', 'F', 'F' };
constexpr std::array<uint8_t, 4> WAVE = { 'W', 'A', 'V', 'E' };

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

MatchResult parseWav(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk) {

    if (!format_utils::hasBytes(buffer, pos, 12)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    if (!hasFourcc(buffer, pos, RIFF) || !hasFourcc(buffer, pos + 8, WAVE)) {
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
            "valid RIFF/WAVE header, truncated payload");
    }

    return MatchResult::matched(totalSize);
}

const char* wavFormatName(uint16_t formatTag) {
    switch (formatTag) {
    case 0x0001:
        return "PCM";
    case 0x0003:
        return "IEEE_FLOAT";
    case 0x0006:
        return "A_LAW";
    case 0x0007:
        return "MU_LAW";
    case 0xFFFE:
        return "EXTENSIBLE";
    default:
        return "UNKNOWN";
    }
}
}

std::string WavHandler::type() const {
    return "wav";
}

bool WavHandler::canStartWith(uint8_t value) const {
    return value == 'R';
}

size_t WavHandler::minimumSize() const {
    return 12;
}

MatchResult WavHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    return parseWav(buffer, position, isFinalChunk);
}

FileAnalysis WavHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t size) const {

    FileAnalysis analysis;
    const size_t end = position + size;
    size_t cursor = position + 12;
    bool foundFmt = false;
    bool foundData = false;

    uint16_t audioFormat = 0;
    uint16_t channels = 0;
    uint32_t sampleRate = 0;
    uint32_t byteRate = 0;
    uint16_t bitsPerSample = 0;
    uint16_t blockAlign = 0;
    uint32_t dataSize = 0;

    while (cursor + 8 <= end) {
        const std::string fourcc(
            reinterpret_cast<const char*>(buffer.data() + cursor),
            4);
        const uint32_t chunkSize = format_utils::readLe32(buffer, cursor + 4);
        const size_t chunkData = cursor + 8;
        const size_t paddedChunkSize =
            static_cast<size_t>(chunkSize) + (chunkSize & 1U);

        if (chunkData + paddedChunkSize > end) {
            analysis.warnings.push_back("invalid WAV chunk layout");
            return analysis;
        }

        if (fourcc == "fmt " && chunkSize >= 16) {
            audioFormat = format_utils::readLe16(buffer, chunkData);
            channels = format_utils::readLe16(buffer, chunkData + 2);
            sampleRate = format_utils::readLe32(buffer, chunkData + 4);
            byteRate = format_utils::readLe32(buffer, chunkData + 8);
            blockAlign = format_utils::readLe16(buffer, chunkData + 12);
            bitsPerSample = format_utils::readLe16(buffer, chunkData + 14);
            foundFmt = true;
        }
        else if (fourcc == "data") {
            dataSize = chunkSize;
            foundData = true;
        }

        cursor = chunkData + paddedChunkSize;
    }

    if (foundFmt) {
        analysis.metadata.push_back(
            std::string("format=") + wavFormatName(audioFormat) +
            ", channels=" + std::to_string(channels));
        analysis.metadata.push_back(
            "sample_rate=" + std::to_string(sampleRate) +
            ", bits_per_sample=" + std::to_string(bitsPerSample));
        analysis.metadata.push_back(
            "byte_rate=" + std::to_string(byteRate) +
            ", block_align=" + std::to_string(blockAlign));
    }

    if (foundData) {
        analysis.metadata.push_back("data_bytes=" + std::to_string(dataSize));

        if (byteRate != 0) {
            std::ostringstream out;
            out.setf(std::ios::fixed);
            out.precision(3);
            out << "duration=" << (static_cast<double>(dataSize) / byteRate) << "s";
            analysis.metadata.push_back(out.str());
        }
    }

    return analysis;
}
