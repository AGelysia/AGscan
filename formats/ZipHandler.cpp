#include "ZipHandler.h"
#include "FormatUtils.h"
#include <string>

namespace {
constexpr uint32_t ZIP_LOCAL_FILE_HEADER = 0x04034B50;
constexpr uint32_t ZIP_CENTRAL_DIRECTORY = 0x02014B50;
constexpr uint32_t ZIP_EOCD = 0x06054B50;

struct ZipInfo {
    uint16_t entries = 0;
    uint16_t commentLength = 0;
    uint16_t primaryMethod = 0xFFFF;
    size_t encryptedEntries = 0;
    uint16_t earliestDate = 0;
    uint16_t earliestTime = 0;
    uint16_t latestDate = 0;
    uint16_t latestTime = 0;
};

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk
        ? MatchResult::partial(0, "valid ZIP local header, EOCD not found")
        : MatchResult::needMoreData();
}

const char* zipMethodName(uint16_t method) {
    switch (method) {
    case 0:
        return "stored";
    case 8:
        return "deflate";
    case 12:
        return "bzip2";
    case 14:
        return "lzma";
    case 93:
        return "zstd";
    case 99:
        return "aes";
    default:
        return "unknown";
    }
}

bool validateCentralDirectory(const std::vector<uint8_t>& buffer,
    size_t archiveStart,
    size_t archiveEnd,
    size_t directoryStart,
    uint32_t directorySize,
    uint16_t entryCount,
    ZipInfo* info) {

    if (directoryStart + directorySize > archiveEnd) {
        return false;
    }

    size_t cursor = directoryStart;
    for (uint16_t entry = 0; entry < entryCount; ++entry) {
        if (!format_utils::hasBytes(buffer, cursor, 46)) {
            return false;
        }

        if (format_utils::readLe32(buffer, cursor) != ZIP_CENTRAL_DIRECTORY) {
            return false;
        }

        const uint16_t nameLength = format_utils::readLe16(buffer, cursor + 28);
        const uint16_t extraLength = format_utils::readLe16(buffer, cursor + 30);
        const uint16_t commentLength = format_utils::readLe16(buffer, cursor + 32);
        const uint32_t localOffset = format_utils::readLe32(buffer, cursor + 42);
        const size_t recordSize =
            46ULL + nameLength + extraLength + commentLength;

        if (cursor + recordSize > archiveEnd) {
            return false;
        }

        if (localOffset + 4 > archiveEnd - archiveStart) {
            return false;
        }

        if (format_utils::readLe32(buffer, archiveStart + localOffset) !=
            ZIP_LOCAL_FILE_HEADER) {
            return false;
        }

        if (info != nullptr) {
            const uint16_t flags = format_utils::readLe16(buffer, cursor + 8);
            const uint16_t method = format_utils::readLe16(buffer, cursor + 10);
            const uint16_t modTime = format_utils::readLe16(buffer, cursor + 12);
            const uint16_t modDate = format_utils::readLe16(buffer, cursor + 14);

            if (info->primaryMethod == 0xFFFF) {
                info->primaryMethod = method;
            }

            if ((flags & 0x0001U) != 0) {
                ++info->encryptedEntries;
            }

            if (info->earliestDate == 0 ||
                std::tie(modDate, modTime) < std::tie(info->earliestDate, info->earliestTime)) {
                info->earliestDate = modDate;
                info->earliestTime = modTime;
            }

            if (info->latestDate == 0 ||
                std::tie(modDate, modTime) > std::tie(info->latestDate, info->latestTime)) {
                info->latestDate = modDate;
                info->latestTime = modTime;
            }
        }

        cursor += recordSize;
    }

    return cursor == directoryStart + directorySize;
}

MatchResult parseZip(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    ZipInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 4)) {
        return incomplete(isFinalChunk);
    }

    if (format_utils::readLe32(buffer, pos) != ZIP_LOCAL_FILE_HEADER) {
        return MatchResult::noMatch();
    }

    bool sawPotentialEocd = false;
    for (size_t cursor = pos + 22; cursor + 22 <= buffer.size(); ++cursor) {
        if (format_utils::readLe32(buffer, cursor) != ZIP_EOCD) {
            continue;
        }

        sawPotentialEocd = true;
        if (!format_utils::hasBytes(buffer, cursor, 22)) {
            return incomplete(isFinalChunk);
        }

        const uint16_t disk = format_utils::readLe16(buffer, cursor + 4);
        const uint16_t centralDirDisk = format_utils::readLe16(buffer, cursor + 6);
        const uint16_t entriesOnDisk = format_utils::readLe16(buffer, cursor + 8);
        const uint16_t entries = format_utils::readLe16(buffer, cursor + 10);
        const uint32_t centralDirSize = format_utils::readLe32(buffer, cursor + 12);
        const uint32_t centralDirOffset = format_utils::readLe32(buffer, cursor + 16);
        const uint16_t commentLength = format_utils::readLe16(buffer, cursor + 20);
        const size_t archiveEnd = cursor + 22ULL + commentLength;

        if (archiveEnd > buffer.size()) {
            return incomplete(isFinalChunk);
        }

        if (disk != 0 || centralDirDisk != 0 || entriesOnDisk != entries) {
            continue;
        }

        const size_t centralDirStart = pos + static_cast<size_t>(centralDirOffset);
        if (!validateCentralDirectory(
            buffer,
            pos,
            archiveEnd,
            centralDirStart,
            centralDirSize,
            entries,
            info)) {
            continue;
        }

        if (info != nullptr) {
            info->entries = entries;
            info->commentLength = commentLength;
        }

        return MatchResult::matched(archiveEnd - pos);
    }

    return (!isFinalChunk && sawPotentialEocd)
        ? MatchResult::needMoreData()
        : (isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid ZIP local header, EOCD not found")
            : MatchResult::needMoreData());
}
}

std::string ZipHandler::type() const {
    return "zip";
}

bool ZipHandler::canStartWith(uint8_t value) const {
    return value == 'P';
}

size_t ZipHandler::minimumSize() const {
    return 30;
}

MatchResult ZipHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    ZipInfo info;
    return parseZip(buffer, position, isFinalChunk, &info);
}

FileAnalysis ZipHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    ZipInfo info;
    const MatchResult result = parseZip(buffer, position, true, &info);
    if (result.status == MatchStatus::matched) {
        analysis.metadata.push_back("entries=" + std::to_string(info.entries));
        analysis.metadata.push_back("comment_length=" + std::to_string(info.commentLength));
        analysis.metadata.push_back(
            "primary_method=" + std::string(zipMethodName(info.primaryMethod)) +
            ", encrypted_entries=" + std::to_string(info.encryptedEntries));
        if (info.earliestDate != 0) {
            analysis.metadata.push_back(
                "first_entry_time=" +
                format_utils::formatDosDateTime(info.earliestDate, info.earliestTime));
            analysis.metadata.push_back(
                "last_entry_time=" +
                format_utils::formatDosDateTime(info.latestDate, info.latestTime));
        }
        return analysis;
    }

    if (!format_utils::hasBytes(buffer, position, 30) ||
        format_utils::readLe32(buffer, position) != ZIP_LOCAL_FILE_HEADER) {
        analysis.warnings.push_back("ZIP analysis failed on carved payload");
        return analysis;
    }

    const uint16_t flags = format_utils::readLe16(buffer, position + 6);
    const uint16_t method = format_utils::readLe16(buffer, position + 8);
    const uint16_t modTime = format_utils::readLe16(buffer, position + 10);
    const uint16_t modDate = format_utils::readLe16(buffer, position + 12);
    const uint16_t nameLength = format_utils::readLe16(buffer, position + 26);
    const uint16_t extraLength = format_utils::readLe16(buffer, position + 28);

    analysis.metadata.push_back(
        "local_method=" + std::string(zipMethodName(method)) +
        ", encrypted=" + (((flags & 0x0001U) != 0) ? "yes" : "no"));
    analysis.metadata.push_back(
        "name_length=" + std::to_string(nameLength) +
        ", extra_length=" + std::to_string(extraLength));
    analysis.metadata.push_back(
        "local_header_time=" + format_utils::formatDosDateTime(modDate, modTime));
    analysis.warnings.push_back("ZIP central directory not found");
    return analysis;
}
