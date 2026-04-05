#include "PcapngHandler.h"
#include "FormatUtils.h"

namespace {
constexpr uint32_t SECTION_HEADER_BLOCK = 0x0A0D0D0A;
constexpr uint32_t INTERFACE_DESCRIPTION_BLOCK = 0x00000001;
constexpr uint32_t ENHANCED_PACKET_BLOCK = 0x00000006;
constexpr uint32_t SIMPLE_PACKET_BLOCK = 0x00000003;
constexpr uint32_t NAME_RESOLUTION_BLOCK = 0x00000004;

struct PcapngInfo {
    bool bigEndian = false;
    size_t sections = 0;
    size_t interfaces = 0;
    size_t packets = 0;
};

bool determineEndian(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool& bigEndian) {

    if (!format_utils::hasBytes(buffer, pos + 8, 4)) {
        return false;
    }

    const uint32_t little = format_utils::readLe32(buffer, pos + 8);
    if (little == 0x1A2B3C4D) {
        bigEndian = false;
        return true;
    }

    const uint32_t big = format_utils::readBe32(buffer, pos + 8);
    if (big == 0x1A2B3C4D) {
        bigEndian = true;
        return true;
    }

    return false;
}

uint32_t readBlockValue(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool bigEndian) {

    return bigEndian
        ? format_utils::readBe32(buffer, pos)
        : format_utils::readLe32(buffer, pos);
}

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk
        ? MatchResult::partial(1, "valid pcapng blocks, truncated payload")
        : MatchResult::needMoreData();
}

MatchResult parsePcapng(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    PcapngInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 12)) {
        return incomplete(isFinalChunk);
    }

    if (format_utils::readLe32(buffer, pos) != SECTION_HEADER_BLOCK) {
        return MatchResult::noMatch();
    }

    bool bigEndian = false;
    if (!determineEndian(buffer, pos, bigEndian)) {
        return MatchResult::noMatch();
    }

    size_t cursor = pos;
    size_t parsedBlocks = 0;

    while (true) {
        if (!format_utils::hasBytes(buffer, cursor, 12)) {
            if (parsedBlocks != 0) {
                return incomplete(isFinalChunk);
            }
            return MatchResult::noMatch();
        }

        const uint32_t blockType = readBlockValue(buffer, cursor, bigEndian);
        const uint32_t blockLength = readBlockValue(buffer, cursor + 4, bigEndian);
        if (blockLength < 12 || (blockLength & 0x03U) != 0) {
            return parsedBlocks == 0
                ? MatchResult::noMatch()
                : MatchResult::matched(cursor - pos);
        }

        if (!format_utils::hasBytes(buffer, cursor, blockLength)) {
            return incomplete(isFinalChunk);
        }

        const uint32_t trailingLength =
            readBlockValue(buffer, cursor + blockLength - 4, bigEndian);
        if (trailingLength != blockLength) {
            return parsedBlocks == 0
                ? MatchResult::noMatch()
                : MatchResult::matched(cursor - pos);
        }

        if (info != nullptr) {
            info->bigEndian = bigEndian;
            if (blockType == SECTION_HEADER_BLOCK) {
                ++info->sections;
            }
            else if (blockType == INTERFACE_DESCRIPTION_BLOCK) {
                ++info->interfaces;
            }
            else if (blockType == ENHANCED_PACKET_BLOCK ||
                blockType == SIMPLE_PACKET_BLOCK) {
                ++info->packets;
            }
        }

        if (blockType == SECTION_HEADER_BLOCK && cursor != pos) {
            if (!determineEndian(buffer, cursor, bigEndian)) {
                return MatchResult::matched(cursor - pos);
            }
        }

        cursor += blockLength;
        ++parsedBlocks;

        if (cursor >= buffer.size()) {
            return isFinalChunk
                ? MatchResult::matched(cursor - pos)
                : MatchResult::needMoreData();
        }

        const uint32_t nextType = format_utils::readLe32(buffer, cursor);
        if (nextType != SECTION_HEADER_BLOCK &&
            nextType != INTERFACE_DESCRIPTION_BLOCK &&
            nextType != ENHANCED_PACKET_BLOCK &&
            nextType != SIMPLE_PACKET_BLOCK &&
            nextType != NAME_RESOLUTION_BLOCK) {
            return MatchResult::matched(cursor - pos);
        }
    }
}
}

std::string PcapngHandler::type() const {
    return "pcapng";
}

bool PcapngHandler::canStartWith(uint8_t value) const {
    return value == 0x0A;
}

size_t PcapngHandler::minimumSize() const {
    return 28;
}

MatchResult PcapngHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    PcapngInfo info;
    return parsePcapng(buffer, position, isFinalChunk, &info);
}

FileAnalysis PcapngHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    PcapngInfo info;
    const MatchResult result = parsePcapng(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("pcapng analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        std::string("endian=") + (info.bigEndian ? "big" : "little"));
    analysis.metadata.push_back(
        "sections=" + std::to_string(info.sections) +
        ", interfaces=" + std::to_string(info.interfaces));
    analysis.metadata.push_back("packets=" + std::to_string(info.packets));
    return analysis;
}
