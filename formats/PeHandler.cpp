#include "PeHandler.h"
#include "FormatUtils.h"
#include <algorithm>
#include <array>

namespace {
constexpr std::array<uint8_t, 2> DOS_HEAD = { 'M', 'Z' };
constexpr uint32_t PE_HEAD = 0x00004550;
constexpr size_t DOS_HEADER_SIZE = 0x40;
constexpr size_t FILE_HEADER_SIZE = 20;
constexpr size_t SECTION_HEADER_SIZE = 40;
constexpr size_t MAX_SECTION_COUNT = 96;
constexpr uint32_t MAX_PE_HEADER_OFFSET = 16 * 1024 * 1024;

struct PeInfo {
    bool is64 = false;
    uint16_t machine = 0;
    uint16_t sectionCount = 0;
    uint16_t subsystem = 0;
    uint32_t sizeOfImage = 0;
    uint32_t timestamp = 0;
    uint32_t entryPoint = 0;
};

bool matchesPartialSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (pos >= buffer.size()) {
        return false;
    }

    const size_t available = buffer.size() - pos;
    if (available >= DOS_HEAD.size()) {
        return false;
    }

    for (size_t i = 0; i < available; ++i) {
        if (buffer[pos + i] != DOS_HEAD[i]) {
            return false;
        }
    }

    return true;
}

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
}

const char* machineName(uint16_t machine) {
    switch (machine) {
    case 0x14C:
        return "x86";
    case 0x8664:
        return "x64";
    case 0x1C0:
        return "ARM";
    case 0xAA64:
        return "ARM64";
    default:
        return "unknown";
    }
}

const char* subsystemName(uint16_t subsystem) {
    switch (subsystem) {
    case 1:
        return "native";
    case 2:
        return "windows-gui";
    case 3:
        return "windows-cui";
    case 9:
        return "windows-ce";
    case 10:
        return "efi-app";
    case 14:
        return "xbox";
    default:
        return "unknown";
    }
}

MatchResult parsePe(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    PeInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, DOS_HEAD.size())) {
        if (matchesPartialSignature(buffer, pos) && !isFinalChunk) {
            return MatchResult::needMoreData();
        }

        return MatchResult::noMatch();
    }

    if (buffer[pos] != DOS_HEAD[0] || buffer[pos + 1] != DOS_HEAD[1]) {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, pos, DOS_HEADER_SIZE)) {
        return incomplete(isFinalChunk);
    }

    const uint32_t peHeaderOffset = format_utils::readLe32(buffer, pos + 0x3C);
    if (peHeaderOffset < DOS_HEADER_SIZE ||
        peHeaderOffset > MAX_PE_HEADER_OFFSET) {
        return MatchResult::noMatch();
    }

    const size_t ntHeaders = pos + static_cast<size_t>(peHeaderOffset);
    if (!format_utils::hasBytes(buffer, ntHeaders, 4 + FILE_HEADER_SIZE)) {
        return incomplete(isFinalChunk);
    }

    if (format_utils::readLe32(buffer, ntHeaders) != PE_HEAD) {
        return MatchResult::noMatch();
    }

    const size_t fileHeader = ntHeaders + 4;
    const uint16_t machine = format_utils::readLe16(buffer, fileHeader);
    const uint16_t numberOfSections = format_utils::readLe16(buffer, fileHeader + 2);
    const uint32_t timestamp = format_utils::readLe32(buffer, fileHeader + 4);
    const uint16_t sizeOfOptionalHeader =
        format_utils::readLe16(buffer, fileHeader + 16);
    if (numberOfSections == 0 ||
        numberOfSections > MAX_SECTION_COUNT ||
        sizeOfOptionalHeader == 0) {
        return MatchResult::noMatch();
    }

    const size_t optionalHeader = fileHeader + FILE_HEADER_SIZE;
    if (!format_utils::hasBytes(buffer, optionalHeader, sizeOfOptionalHeader)) {
        return incomplete(isFinalChunk);
    }

    const uint16_t magic = format_utils::readLe16(buffer, optionalHeader);
    size_t numberOfRvaAndSizesOffset = 0;
    size_t dataDirectoriesOffset = 0;
    size_t minimumOptionalHeaderSize = 0;
    bool is64 = false;

    if (magic == 0x10B) {
        minimumOptionalHeaderSize = 96;
        numberOfRvaAndSizesOffset = optionalHeader + 92;
        dataDirectoriesOffset = optionalHeader + 96;
    }
    else if (magic == 0x20B) {
        minimumOptionalHeaderSize = 112;
        numberOfRvaAndSizesOffset = optionalHeader + 108;
        dataDirectoriesOffset = optionalHeader + 112;
        is64 = true;
    }
    else {
        return MatchResult::noMatch();
    }

    if (sizeOfOptionalHeader < minimumOptionalHeaderSize) {
        return MatchResult::noMatch();
    }

    const uint32_t entryPoint = format_utils::readLe32(buffer, optionalHeader + 16);
    const uint32_t sizeOfImage = format_utils::readLe32(buffer, optionalHeader + 56);
    const uint32_t sizeOfHeaders = format_utils::readLe32(buffer, optionalHeader + 60);
    const uint16_t subsystem = format_utils::readLe16(buffer, optionalHeader + 68);
    const uint32_t numberOfDirectories =
        format_utils::readLe32(buffer, numberOfRvaAndSizesOffset);

    const size_t sectionTable = optionalHeader + sizeOfOptionalHeader;
    const size_t sectionTableSize =
        static_cast<size_t>(numberOfSections) * SECTION_HEADER_SIZE;
    if (!format_utils::hasBytes(buffer, sectionTable, sectionTableSize)) {
        return incomplete(isFinalChunk);
    }

    size_t detectedSize = std::max(
        size_t{ sizeOfHeaders },
        sectionTable + sectionTableSize - pos);

    for (size_t section = 0; section < numberOfSections; ++section) {
        const size_t header = sectionTable + section * SECTION_HEADER_SIZE;
        const uint32_t rawSize = format_utils::readLe32(buffer, header + 16);
        const uint32_t rawOffset = format_utils::readLe32(buffer, header + 20);
        if (rawSize == 0 || rawOffset == 0) {
            continue;
        }

        detectedSize = std::max(
            detectedSize,
            static_cast<size_t>(rawOffset) + rawSize);
    }

    if (numberOfDirectories > 4 &&
        dataDirectoriesOffset + (5 * 8) <= optionalHeader + sizeOfOptionalHeader) {
        const uint32_t certificateOffset =
            format_utils::readLe32(buffer, dataDirectoriesOffset + (4 * 8));
        const uint32_t certificateSize =
            format_utils::readLe32(buffer, dataDirectoriesOffset + (4 * 8) + 4);

        if (certificateOffset != 0 && certificateSize != 0) {
            detectedSize = std::max(
                detectedSize,
                static_cast<size_t>(certificateOffset) + certificateSize);
        }
    }

    if (info != nullptr) {
        info->is64 = is64;
        info->machine = machine;
        info->sectionCount = numberOfSections;
        info->subsystem = subsystem;
        info->sizeOfImage = sizeOfImage;
        info->timestamp = timestamp;
        info->entryPoint = entryPoint;
    }

    if (!isFinalChunk && detectedSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && detectedSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid PE headers, truncated image");
    }

    return MatchResult::matched(detectedSize);
}
}

std::string PeHandler::type() const {
    return "pe";
}

bool PeHandler::canStartWith(uint8_t value) const {
    return value == DOS_HEAD[0];
}

size_t PeHandler::minimumSize() const {
    return DOS_HEADER_SIZE;
}

MatchResult PeHandler::detect(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk) const {

    PeInfo info;
    return parsePe(buffer, pos, isFinalChunk, &info);
}

FileAnalysis PeHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t pos,
    size_t) const {

    FileAnalysis analysis;
    PeInfo info;
    const MatchResult result = parsePe(buffer, pos, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("PE analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        std::string("machine=") + machineName(info.machine) +
        ", format=" + (info.is64 ? "PE32+" : "PE32"));
    analysis.metadata.push_back(
        "sections=" + std::to_string(info.sectionCount) +
        ", size_of_image=" + std::to_string(info.sizeOfImage));
    analysis.metadata.push_back(
        std::string("subsystem=") + subsystemName(info.subsystem));
    analysis.metadata.push_back(
        "timestamp=" + format_utils::formatUnixTime(info.timestamp));
    analysis.metadata.push_back(
        "entry_point_rva=" + format_utils::hexValue(info.entryPoint, 8));
    return analysis;
}
