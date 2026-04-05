#include "CabHandler.h"
#include "FormatUtils.h"
#include <algorithm>
#include <array>

namespace {
constexpr std::array<uint8_t, 4> CAB_HEAD = { 'M', 'S', 'C', 'F' };
constexpr uint16_t CAB_FLAG_PREV = 0x0001;
constexpr uint16_t CAB_FLAG_NEXT = 0x0002;
constexpr uint16_t CAB_FLAG_RESERVE = 0x0004;
constexpr uint32_t MAX_CAB_SIZE = 512U * 1024U * 1024U;

struct CabInfo {
    uint8_t versionMinor = 0;
    uint8_t versionMajor = 0;
    uint16_t folders = 0;
    uint16_t files = 0;
    uint16_t flags = 0;
    uint16_t setId = 0;
    uint16_t cabinetIndex = 0;
    uint32_t cabinetSize = 0;
    uint16_t compressionType = 0xFFFF;
    uint16_t earliestDate = 0;
    uint16_t earliestTime = 0;
    uint16_t latestDate = 0;
    uint16_t latestTime = 0;
};

bool hasSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    return format_utils::hasBytes(buffer, pos, CAB_HEAD.size()) &&
        buffer[pos] == CAB_HEAD[0] &&
        buffer[pos + 1] == CAB_HEAD[1] &&
        buffer[pos + 2] == CAB_HEAD[2] &&
        buffer[pos + 3] == CAB_HEAD[3];
}

const char* cabinetCompressionName(uint16_t value) {
    switch (value & 0x000F) {
    case 0:
        return "none";
    case 1:
        return "mszip";
    case 2:
        return "quantum";
    case 3:
        return "lzx";
    default:
        return "unknown";
    }
}

MatchResult partialOrNeedMoreData(bool isFinalChunk,
    size_t available,
    const char* detail) {

    return isFinalChunk
        ? MatchResult::partial(available, detail)
        : MatchResult::needMoreData();
}

MatchResult parseCab(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    CabInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 36)) {
        return partialOrNeedMoreData(
            isFinalChunk,
            buffer.size() - pos,
            "partial CAB header");
    }

    if (!hasSignature(buffer, pos)) {
        return MatchResult::noMatch();
    }

    const uint32_t cabinetSize = format_utils::readLe32(buffer, pos + 8);
    const uint32_t fileTableOffset = format_utils::readLe32(buffer, pos + 16);
    const uint8_t versionMinor = buffer[pos + 24];
    const uint8_t versionMajor = buffer[pos + 25];
    const uint16_t folders = format_utils::readLe16(buffer, pos + 26);
    const uint16_t files = format_utils::readLe16(buffer, pos + 28);
    const uint16_t flags = format_utils::readLe16(buffer, pos + 30);
    const uint16_t setId = format_utils::readLe16(buffer, pos + 32);
    const uint16_t cabinetIndex = format_utils::readLe16(buffer, pos + 34);

    if (cabinetSize < 36 || cabinetSize > MAX_CAB_SIZE ||
        versionMajor != 1 || folders == 0 ||
        fileTableOffset < 36 || fileTableOffset >= cabinetSize) {
        return MatchResult::noMatch();
    }

    size_t headerSize = 36;
    if ((flags & CAB_FLAG_RESERVE) != 0) {
        if (!format_utils::hasBytes(buffer, pos, 40)) {
            return partialOrNeedMoreData(
                isFinalChunk,
                buffer.size() - pos,
                "valid CAB header, truncated reserve data");
        }

        const uint16_t headerReserve = format_utils::readLe16(buffer, pos + 36);
        headerSize = 40ULL + headerReserve;
    }

    const size_t folderTableSize = static_cast<size_t>(folders) * 8ULL;
    if (headerSize + folderTableSize > cabinetSize) {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, pos, headerSize + folderTableSize)) {
        return partialOrNeedMoreData(
            isFinalChunk,
            buffer.size() - pos,
            "valid CAB header, truncated folder table");
    }

    if (info != nullptr) {
        info->versionMinor = versionMinor;
        info->versionMajor = versionMajor;
        info->folders = folders;
        info->files = files;
        info->flags = flags;
        info->setId = setId;
        info->cabinetIndex = cabinetIndex;
        info->cabinetSize = cabinetSize;
        info->compressionType = format_utils::readLe16(buffer, pos + headerSize + 6);
    }

    if (!isFinalChunk && cabinetSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && cabinetSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid CAB header, truncated cabinet payload");
    }

    size_t cursor = pos + fileTableOffset;
    const size_t end = pos + cabinetSize;
    for (uint16_t i = 0; i < files; ++i) {
        if (!format_utils::hasBytes(buffer, cursor, 16)) {
            return MatchResult::partial(
                buffer.size() - pos,
                "valid CAB file table, truncated file entry");
        }

        const uint16_t date = format_utils::readLe16(buffer, cursor + 10);
        const uint16_t time = format_utils::readLe16(buffer, cursor + 12);
        cursor += 16;

        size_t nameEnd = cursor;
        while (nameEnd < end && buffer[nameEnd] != 0) {
            ++nameEnd;
        }

        if (nameEnd >= end) {
            return MatchResult::partial(
                buffer.size() - pos,
                "valid CAB file entry, truncated filename");
        }

        if (info != nullptr) {
            if (info->earliestDate == 0 ||
                std::tie(date, time) < std::tie(info->earliestDate, info->earliestTime)) {
                info->earliestDate = date;
                info->earliestTime = time;
            }

            if (info->latestDate == 0 ||
                std::tie(date, time) > std::tie(info->latestDate, info->latestTime)) {
                info->latestDate = date;
                info->latestTime = time;
            }
        }

        cursor = nameEnd + 1;
    }

    return MatchResult::matched(cabinetSize);
}
}

std::string CabHandler::type() const {
    return "cab";
}

bool CabHandler::canStartWith(uint8_t value) const {
    return value == CAB_HEAD[0];
}

size_t CabHandler::minimumSize() const {
    return 36;
}

MatchResult CabHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    CabInfo info;
    return parseCab(buffer, position, isFinalChunk, &info);
}

FileAnalysis CabHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    CabInfo info;
    const MatchResult result = parseCab(buffer, position, true, &info);
    if (result.status == MatchStatus::no_match) {
        analysis.warnings.push_back("CAB analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        "version=" + std::to_string(info.versionMajor) +
        "." + std::to_string(info.versionMinor));
    analysis.metadata.push_back(
        "folders=" + std::to_string(info.folders) +
        ", files=" + std::to_string(info.files));
    analysis.metadata.push_back(
        "compression=" + std::string(cabinetCompressionName(info.compressionType)));
    analysis.metadata.push_back(
        "set_id=" + std::to_string(info.setId) +
        ", cabinet_index=" + std::to_string(info.cabinetIndex));
    analysis.metadata.push_back(
        std::string("has_prev=") + (((info.flags & CAB_FLAG_PREV) != 0) ? "yes" : "no") +
        ", has_next=" + (((info.flags & CAB_FLAG_NEXT) != 0) ? "yes" : "no"));
    if (info.earliestDate != 0) {
        analysis.metadata.push_back(
            "first_file_time=" +
            format_utils::formatDosDateTime(info.earliestDate, info.earliestTime));
        analysis.metadata.push_back(
            "last_file_time=" +
            format_utils::formatDosDateTime(info.latestDate, info.latestTime));
    }
    if (result.status == MatchStatus::partial_match) {
        analysis.warnings.push_back("CAB payload appears truncated");
    }
    return analysis;
}
