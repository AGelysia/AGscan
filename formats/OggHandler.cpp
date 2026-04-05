#include "OggHandler.h"
#include "FormatUtils.h"
#include <set>

namespace {
struct OggInfo {
    size_t pageCount = 0;
    size_t streamCount = 0;
    std::string codec = "unknown";
};

bool hasOggSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    return format_utils::hasBytes(buffer, pos, 4) &&
        buffer[pos] == 'O' &&
        buffer[pos + 1] == 'g' &&
        buffer[pos + 2] == 'g' &&
        buffer[pos + 3] == 'S';
}

std::string detectCodec(const std::vector<uint8_t>& buffer,
    size_t payloadPos,
    size_t payloadSize) {

    if (payloadSize >= 8 &&
        buffer[payloadPos] == 'O' &&
        buffer[payloadPos + 1] == 'p' &&
        buffer[payloadPos + 2] == 'u' &&
        buffer[payloadPos + 3] == 's' &&
        buffer[payloadPos + 4] == 'H' &&
        buffer[payloadPos + 5] == 'e' &&
        buffer[payloadPos + 6] == 'a' &&
        buffer[payloadPos + 7] == 'd') {
        return "Opus";
    }

    if (payloadSize >= 7 &&
        buffer[payloadPos] == 0x01 &&
        buffer[payloadPos + 1] == 'v' &&
        buffer[payloadPos + 2] == 'o' &&
        buffer[payloadPos + 3] == 'r' &&
        buffer[payloadPos + 4] == 'b' &&
        buffer[payloadPos + 5] == 'i' &&
        buffer[payloadPos + 6] == 's') {
        return "Vorbis";
    }

    if (payloadSize >= 8 &&
        buffer[payloadPos] == 'S' &&
        buffer[payloadPos + 1] == 'p' &&
        buffer[payloadPos + 2] == 'e' &&
        buffer[payloadPos + 3] == 'e' &&
        buffer[payloadPos + 4] == 'x' &&
        buffer[payloadPos + 5] == ' ' &&
        buffer[payloadPos + 6] == ' ' &&
        buffer[payloadPos + 7] == ' ') {
        return "Speex";
    }

    if (payloadSize >= 7 &&
        buffer[payloadPos] == 0x7F &&
        buffer[payloadPos + 1] == 'F' &&
        buffer[payloadPos + 2] == 'L' &&
        buffer[payloadPos + 3] == 'A' &&
        buffer[payloadPos + 4] == 'C') {
        return "FLAC";
    }

    if (payloadSize >= 7 &&
        buffer[payloadPos] == 0x80 &&
        buffer[payloadPos + 1] == 't' &&
        buffer[payloadPos + 2] == 'h' &&
        buffer[payloadPos + 3] == 'e' &&
        buffer[payloadPos + 4] == 'o' &&
        buffer[payloadPos + 5] == 'r' &&
        buffer[payloadPos + 6] == 'a') {
        return "Theora";
    }

    return "unknown";
}

MatchResult parseOgg(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    OggInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 27)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    if (!hasOggSignature(buffer, pos) || buffer[pos + 4] != 0) {
        return MatchResult::noMatch();
    }

    size_t cursor = pos;
    bool sawEos = false;
    std::set<uint32_t> serials;

    while (true) {
        if (!format_utils::hasBytes(buffer, cursor, 27)) {
            if (!isFinalChunk) {
                return MatchResult::needMoreData();
            }

            return sawEos
                ? MatchResult::matched(cursor - pos)
                : MatchResult::partial(
                    buffer.size() - pos,
                    "valid OGG pages, EOS page not found");
        }

        if (!hasOggSignature(buffer, cursor) || buffer[cursor + 4] != 0) {
            return sawEos ? MatchResult::matched(cursor - pos) : MatchResult::noMatch();
        }

        const uint8_t headerType = buffer[cursor + 5];
        const uint8_t pageSegments = buffer[cursor + 26];
        if (!format_utils::hasBytes(buffer, cursor + 27, pageSegments)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid OGG page header, truncated segment table")
                : MatchResult::needMoreData();
        }

        size_t payloadSize = 0;
        for (size_t i = 0; i < pageSegments; ++i) {
            payloadSize += buffer[cursor + 27 + i];
        }

        const size_t pageSize = 27 + pageSegments + payloadSize;
        if (!format_utils::hasBytes(buffer, cursor, pageSize)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid OGG pages, truncated payload")
                : MatchResult::needMoreData();
        }

        if (info != nullptr) {
            ++info->pageCount;
            const uint32_t serial = format_utils::readLe32(buffer, cursor + 14);
            serials.insert(serial);

            if (info->codec == "unknown" && payloadSize != 0) {
                info->codec = detectCodec(
                    buffer,
                    cursor + 27 + pageSegments,
                    payloadSize);
            }
        }

        if ((headerType & 0x04U) != 0) {
            sawEos = true;
        }

        cursor += pageSize;

        if (cursor == buffer.size()) {
            if (!isFinalChunk) {
                return MatchResult::needMoreData();
            }

            return sawEos
                ? MatchResult::matched(cursor - pos)
                : MatchResult::partial(
                    cursor - pos,
                    "valid OGG stream, EOF reached before EOS");
        }
    }
}
}

std::string OggHandler::type() const {
    return "ogg";
}

bool OggHandler::canStartWith(uint8_t value) const {
    return value == 'O';
}

size_t OggHandler::minimumSize() const {
    return 27;
}

MatchResult OggHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    OggInfo info;
    return parseOgg(buffer, position, isFinalChunk, &info);
}

FileAnalysis OggHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    OggInfo info;
    const MatchResult result = parseOgg(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("OGG analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back("pages=" + std::to_string(info.pageCount));
    analysis.metadata.push_back("codec=" + info.codec);
    return analysis;
}
