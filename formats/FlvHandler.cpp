#include "FlvHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 3> FLV_HEAD = { 'F', 'L', 'V' };

struct FlvInfo {
    uint8_t version = 0;
    bool hasAudio = false;
    bool hasVideo = false;
    size_t audioTags = 0;
    size_t videoTags = 0;
    size_t scriptTags = 0;
    uint32_t maxTimestamp = 0;
};

bool hasSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    return format_utils::hasBytes(buffer, pos, FLV_HEAD.size()) &&
        buffer[pos] == FLV_HEAD[0] &&
        buffer[pos + 1] == FLV_HEAD[1] &&
        buffer[pos + 2] == FLV_HEAD[2];
}

MatchResult parseFlv(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    FlvInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 13)) {
        return isFinalChunk
            ? MatchResult::partial(buffer.size() - pos, "partial FLV header")
            : MatchResult::needMoreData();
    }

    if (!hasSignature(buffer, pos)) {
        return MatchResult::noMatch();
    }

    const uint8_t version = buffer[pos + 3];
    const uint8_t flags = buffer[pos + 4];
    const uint32_t dataOffset = format_utils::readBe32(buffer, pos + 5);
    if (version == 0 || dataOffset < 9 || dataOffset > 4096) {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, pos, dataOffset + 4)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid FLV header, truncated initial previous-tag size")
            : MatchResult::needMoreData();
    }

    if (format_utils::readBe32(buffer, pos + dataOffset) != 0) {
        return MatchResult::noMatch();
    }

    if (info != nullptr) {
        info->version = version;
        info->hasAudio = (flags & 0x04U) != 0;
        info->hasVideo = (flags & 0x01U) != 0;
    }

    size_t cursor = pos + dataOffset + 4;
    while (cursor < buffer.size()) {
        if (!format_utils::hasBytes(buffer, cursor, 11)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid FLV tag stream, truncated tag header")
                : MatchResult::needMoreData();
        }

        const uint8_t tagType = buffer[cursor];
        const uint32_t dataSize = format_utils::readBe24(buffer, cursor + 1);
        const uint32_t timestamp =
            format_utils::readBe24(buffer, cursor + 4) |
            (static_cast<uint32_t>(buffer[cursor + 7]) << 24);
        const uint32_t streamId = format_utils::readBe24(buffer, cursor + 8);
        const size_t tagSize = 11ULL + dataSize;

        if (streamId != 0) {
            return cursor == pos + dataOffset + 4
                ? MatchResult::noMatch()
                : MatchResult::matched(cursor - pos);
        }

        if (!format_utils::hasBytes(buffer, cursor + 11, dataSize + 4)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid FLV tag, truncated payload")
                : MatchResult::needMoreData();
        }

        const uint32_t previousTagSize =
            format_utils::readBe32(buffer, cursor + tagSize);
        if (previousTagSize != tagSize) {
            return cursor == pos + dataOffset + 4
                ? MatchResult::noMatch()
                : MatchResult::matched(cursor - pos);
        }

        if (info != nullptr) {
            info->maxTimestamp = std::max(info->maxTimestamp, timestamp);
            if (tagType == 8) {
                ++info->audioTags;
            }
            else if (tagType == 9) {
                ++info->videoTags;
            }
            else if (tagType == 18) {
                ++info->scriptTags;
            }
        }

        cursor += tagSize + 4;

        if (cursor == buffer.size()) {
            return isFinalChunk
                ? MatchResult::matched(cursor - pos)
                : MatchResult::needMoreData();
        }
    }

    return MatchResult::matched(cursor - pos);
}
}

std::string FlvHandler::type() const {
    return "flv";
}

bool FlvHandler::canStartWith(uint8_t value) const {
    return value == FLV_HEAD[0];
}

size_t FlvHandler::minimumSize() const {
    return 13;
}

MatchResult FlvHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    FlvInfo info;
    return parseFlv(buffer, position, isFinalChunk, &info);
}

FileAnalysis FlvHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    FlvInfo info;
    const MatchResult result = parseFlv(buffer, position, true, &info);
    if (result.status == MatchStatus::no_match) {
        analysis.warnings.push_back("FLV analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back("version=" + std::to_string(info.version));
    analysis.metadata.push_back(
        std::string("audio=") + (info.hasAudio ? "yes" : "no") +
        ", video=" + (info.hasVideo ? "yes" : "no"));
    analysis.metadata.push_back(
        "audio_tags=" + std::to_string(info.audioTags) +
        ", video_tags=" + std::to_string(info.videoTags) +
        ", script_tags=" + std::to_string(info.scriptTags));
    analysis.metadata.push_back("max_timestamp_ms=" + std::to_string(info.maxTimestamp));
    if (result.status == MatchStatus::partial_match) {
        analysis.warnings.push_back("FLV payload appears truncated");
    }
    return analysis;
}
