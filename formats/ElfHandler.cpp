#include "ElfHandler.h"
#include "FormatUtils.h"
#include <algorithm>
#include <array>

namespace {
constexpr std::array<uint8_t, 4> ELF_HEAD = { 0x7F, 'E', 'L', 'F' };
constexpr uint64_t MAX_ELF_OFFSET = 128ULL * 1024 * 1024;

struct ElfInfo {
    bool is64 = false;
    bool bigEndian = false;
    uint16_t machine = 0;
    uint16_t type = 0;
    uint16_t sectionCount = 0;
    uint16_t programCount = 0;
    uint64_t entry = 0;
};

bool hasElfSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!format_utils::hasBytes(buffer, pos, ELF_HEAD.size())) {
        return false;
    }

    for (size_t i = 0; i < ELF_HEAD.size(); ++i) {
        if (buffer[pos + i] != ELF_HEAD[i]) {
            return false;
        }
    }

    return true;
}

uint16_t readU16(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool bigEndian) {

    return bigEndian
        ? format_utils::readBe16(buffer, pos)
        : format_utils::readLe16(buffer, pos);
}

uint32_t readU32(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool bigEndian) {

    return bigEndian
        ? format_utils::readBe32(buffer, pos)
        : format_utils::readLe32(buffer, pos);
}

uint64_t readU64(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool bigEndian) {

    return bigEndian
        ? format_utils::readBe64(buffer, pos)
        : format_utils::readLe64(buffer, pos);
}

MatchResult incomplete(bool isFinalChunk) {
    return isFinalChunk
        ? MatchResult::partial(0, "valid ELF header, truncated structure")
        : MatchResult::needMoreData();
}

const char* elfMachineName(uint16_t machine) {
    switch (machine) {
    case 0x03:
        return "x86";
    case 0x3E:
        return "x86-64";
    case 0x28:
        return "ARM";
    case 0xB7:
        return "AArch64";
    case 0x08:
        return "MIPS";
    default:
        return "unknown";
    }
}

const char* elfTypeName(uint16_t type) {
    switch (type) {
    case 1:
        return "relocatable";
    case 2:
        return "executable";
    case 3:
        return "shared";
    case 4:
        return "core";
    default:
        return "unknown";
    }
}

MatchResult parseElf(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    ElfInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 16)) {
        return incomplete(isFinalChunk);
    }

    if (!hasElfSignature(buffer, pos)) {
        return MatchResult::noMatch();
    }

    const uint8_t elfClass = buffer[pos + 4];
    const uint8_t elfData = buffer[pos + 5];
    if ((elfClass != 1 && elfClass != 2) || (elfData != 1 && elfData != 2)) {
        return MatchResult::noMatch();
    }

    const bool is64 = elfClass == 2;
    const bool bigEndian = elfData == 2;
    const size_t headerSize = is64 ? 64 : 52;
    if (!format_utils::hasBytes(buffer, pos, headerSize)) {
        return incomplete(isFinalChunk);
    }

    const uint16_t type = readU16(buffer, pos + 16, bigEndian);
    const uint16_t machine = readU16(buffer, pos + 18, bigEndian);
    const uint64_t entry = is64
        ? readU64(buffer, pos + 24, bigEndian)
        : readU32(buffer, pos + 24, bigEndian);
    const uint64_t programOffset = is64
        ? readU64(buffer, pos + 32, bigEndian)
        : readU32(buffer, pos + 28, bigEndian);
    const uint64_t sectionOffset = is64
        ? readU64(buffer, pos + 40, bigEndian)
        : readU32(buffer, pos + 32, bigEndian);
    const uint16_t headerBytes = readU16(buffer, pos + (is64 ? 52 : 40), bigEndian);
    const uint16_t programEntrySize = readU16(buffer, pos + (is64 ? 54 : 42), bigEndian);
    const uint16_t programCount = readU16(buffer, pos + (is64 ? 56 : 44), bigEndian);
    const uint16_t sectionEntrySize = readU16(buffer, pos + (is64 ? 58 : 46), bigEndian);
    const uint16_t sectionCount = readU16(buffer, pos + (is64 ? 60 : 48), bigEndian);

    if (headerBytes < headerSize ||
        programOffset > MAX_ELF_OFFSET ||
        sectionOffset > MAX_ELF_OFFSET) {
        return MatchResult::noMatch();
    }

    size_t detectedSize = headerBytes;

    if (programCount != 0) {
        const size_t tableSize = static_cast<size_t>(programCount) * programEntrySize;
        if (!format_utils::hasBytes(buffer, pos + static_cast<size_t>(programOffset), tableSize)) {
            return incomplete(isFinalChunk);
        }

        detectedSize = std::max(
            detectedSize,
            static_cast<size_t>(programOffset) + tableSize);

        for (uint16_t i = 0; i < programCount; ++i) {
            const size_t header = pos + static_cast<size_t>(programOffset) +
                static_cast<size_t>(i) * programEntrySize;
            const uint64_t fileOffset = is64
                ? readU64(buffer, header + 8, bigEndian)
                : readU32(buffer, header + 4, bigEndian);
            const uint64_t fileSize = is64
                ? readU64(buffer, header + 32, bigEndian)
                : readU32(buffer, header + 16, bigEndian);
            if (fileOffset > MAX_ELF_OFFSET || fileSize > MAX_ELF_OFFSET) {
                return MatchResult::noMatch();
            }
            detectedSize = std::max(
                detectedSize,
                static_cast<size_t>(fileOffset + fileSize));
        }
    }

    if (sectionCount != 0) {
        const size_t tableSize = static_cast<size_t>(sectionCount) * sectionEntrySize;
        if (!format_utils::hasBytes(buffer, pos + static_cast<size_t>(sectionOffset), tableSize)) {
            return incomplete(isFinalChunk);
        }

        detectedSize = std::max(
            detectedSize,
            static_cast<size_t>(sectionOffset) + tableSize);

        for (uint16_t i = 0; i < sectionCount; ++i) {
            const size_t header = pos + static_cast<size_t>(sectionOffset) +
                static_cast<size_t>(i) * sectionEntrySize;
            const uint64_t fileOffset = is64
                ? readU64(buffer, header + 24, bigEndian)
                : readU32(buffer, header + 16, bigEndian);
            const uint64_t fileSize = is64
                ? readU64(buffer, header + 32, bigEndian)
                : readU32(buffer, header + 20, bigEndian);
            if (fileOffset > MAX_ELF_OFFSET || fileSize > MAX_ELF_OFFSET) {
                return MatchResult::noMatch();
            }
            detectedSize = std::max(
                detectedSize,
                static_cast<size_t>(fileOffset + fileSize));
        }
    }

    if (info != nullptr) {
        info->is64 = is64;
        info->bigEndian = bigEndian;
        info->machine = machine;
        info->type = type;
        info->sectionCount = sectionCount;
        info->programCount = programCount;
        info->entry = entry;
    }

    if (!isFinalChunk && detectedSize > buffer.size() - pos) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && detectedSize > buffer.size() - pos) {
        return MatchResult::partial(
            buffer.size() - pos,
            "valid ELF headers, truncated image");
    }

    return MatchResult::matched(detectedSize);
}
}

std::string ElfHandler::type() const {
    return "elf";
}

bool ElfHandler::canStartWith(uint8_t value) const {
    return value == 0x7F;
}

size_t ElfHandler::minimumSize() const {
    return 52;
}

MatchResult ElfHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    ElfInfo info;
    return parseElf(buffer, position, isFinalChunk, &info);
}

FileAnalysis ElfHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    ElfInfo info;
    const MatchResult result = parseElf(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("ELF analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        std::string("class=") + (info.is64 ? "ELF64" : "ELF32") +
        ", endian=" + (info.bigEndian ? "big" : "little"));
    analysis.metadata.push_back(
        std::string("machine=") + elfMachineName(info.machine) +
        ", type=" + elfTypeName(info.type));
    analysis.metadata.push_back(
        "program_headers=" + std::to_string(info.programCount) +
        ", sections=" + std::to_string(info.sectionCount));
    analysis.metadata.push_back(
        "entry=" + format_utils::hexValue(info.entry));
    return analysis;
}
