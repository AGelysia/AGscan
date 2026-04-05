#include "WasmHandler.h"
#include "FormatUtils.h"
#include <array>

namespace {
constexpr std::array<uint8_t, 4> WASM_HEAD = { 0x00, 0x61, 0x73, 0x6D };

struct WasmInfo {
    uint32_t version = 0;
    size_t sections = 0;
    uint32_t typeCount = 0;
    uint32_t importCount = 0;
    uint32_t functionCount = 0;
    uint32_t exportCount = 0;
};

bool readVarUInt32(const std::vector<uint8_t>& buffer,
    size_t pos,
    size_t end,
    uint32_t& value,
    size_t& bytesRead) {

    value = 0;
    bytesRead = 0;
    for (uint32_t shift = 0; shift < 35; shift += 7) {
        if (pos + bytesRead >= end) {
            return false;
        }

        const uint8_t byte = buffer[pos + bytesRead];
        value |= static_cast<uint32_t>(byte & 0x7FU) << shift;
        ++bytesRead;

        if ((byte & 0x80U) == 0) {
            return true;
        }
    }

    return false;
}

MatchResult parseWasm(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    WasmInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 8)) {
        return isFinalChunk ? MatchResult::noMatch() : MatchResult::needMoreData();
    }

    for (size_t i = 0; i < WASM_HEAD.size(); ++i) {
        if (buffer[pos + i] != WASM_HEAD[i]) {
            return MatchResult::noMatch();
        }
    }

    const uint32_t version = format_utils::readLe32(buffer, pos + 4);
    if (version == 0 || version > 1) {
        return MatchResult::noMatch();
    }

    size_t cursor = pos + 8;
    uint8_t lastStandardSection = 0;
    bool sawSection = false;

    if (info != nullptr) {
        info->version = version;
    }

    while (cursor < buffer.size()) {
        const uint8_t sectionId = buffer[cursor];
        if (sectionId > 12) {
            return sawSection ? MatchResult::matched(cursor - pos) : MatchResult::noMatch();
        }

        if (sectionId != 0) {
            if (sectionId < lastStandardSection) {
                return sawSection ? MatchResult::matched(cursor - pos) : MatchResult::noMatch();
            }
            lastStandardSection = sectionId;
        }

        ++cursor;

        uint32_t payloadSize = 0;
        size_t varSize = 0;
        if (!readVarUInt32(buffer, cursor, buffer.size(), payloadSize, varSize)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid WASM section header, truncated varuint")
                : MatchResult::needMoreData();
        }

        cursor += varSize;
        if (!format_utils::hasBytes(buffer, cursor, payloadSize)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid WASM module, truncated section payload")
                : MatchResult::needMoreData();
        }

        if (info != nullptr) {
            ++info->sections;
            uint32_t count = 0;
            size_t countBytes = 0;
            if (payloadSize != 0 &&
                readVarUInt32(buffer, cursor, cursor + payloadSize, count, countBytes)) {
                switch (sectionId) {
                case 1:
                    info->typeCount = count;
                    break;
                case 2:
                    info->importCount = count;
                    break;
                case 3:
                    info->functionCount = count;
                    break;
                case 7:
                    info->exportCount = count;
                    break;
                default:
                    break;
                }
            }
        }

        sawSection = true;
        cursor += payloadSize;

        if (cursor == buffer.size()) {
            return isFinalChunk
                ? (sawSection ? MatchResult::matched(cursor - pos) : MatchResult::noMatch())
                : MatchResult::needMoreData();
        }
    }

    return sawSection ? MatchResult::matched(cursor - pos) : MatchResult::noMatch();
}
}

std::string WasmHandler::type() const {
    return "wasm";
}

bool WasmHandler::canStartWith(uint8_t value) const {
    return value == 0x00;
}

size_t WasmHandler::minimumSize() const {
    return 8;
}

MatchResult WasmHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    WasmInfo info;
    return parseWasm(buffer, position, isFinalChunk, &info);
}

FileAnalysis WasmHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    WasmInfo info;
    const MatchResult result = parseWasm(buffer, position, true, &info);
    if (result.status != MatchStatus::matched) {
        analysis.warnings.push_back("WASM analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back("version=" + std::to_string(info.version));
    analysis.metadata.push_back("sections=" + std::to_string(info.sections));
    analysis.metadata.push_back(
        "types=" + std::to_string(info.typeCount) +
        ", imports=" + std::to_string(info.importCount) +
        ", functions=" + std::to_string(info.functionCount) +
        ", exports=" + std::to_string(info.exportCount));
    return analysis;
}
