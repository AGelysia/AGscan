#include "SqliteHandler.h"
#include "FormatUtils.h"
#include <algorithm>
#include <array>

namespace {
constexpr std::array<uint8_t, 16> SQLITE_HEAD =
{ 'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', '\0' };
constexpr size_t SQLITE_HEADER_SIZE = 100;

bool hasSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!format_utils::hasBytes(buffer, pos, SQLITE_HEAD.size())) {
        return false;
    }

    for (size_t i = 0; i < SQLITE_HEAD.size(); ++i) {
        if (buffer[pos + i] != SQLITE_HEAD[i]) {
            return false;
        }
    }

    return true;
}

const char* encodingName(uint32_t value) {
    switch (value) {
    case 1:
        return "UTF-8";
    case 2:
        return "UTF-16le";
    case 3:
        return "UTF-16be";
    default:
        return "unknown";
    }
}
}

std::string SqliteHandler::type() const {
    return "sqlite";
}

std::string SqliteHandler::extension() const {
    return "db";
}

bool SqliteHandler::canStartWith(uint8_t value) const {
    return value == 'S';
}

size_t SqliteHandler::minimumSize() const {
    return SQLITE_HEADER_SIZE;
}

MatchResult SqliteHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    if (!format_utils::hasBytes(buffer, position, SQLITE_HEAD.size())) {
        return isFinalChunk
            ? MatchResult::partial(buffer.size() - position, "partial SQLite signature")
            : MatchResult::needMoreData();
    }

    if (!hasSignature(buffer, position)) {
        return MatchResult::noMatch();
    }

    if (!format_utils::hasBytes(buffer, position, SQLITE_HEADER_SIZE)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - position,
                "valid SQLite signature, truncated database header")
            : MatchResult::needMoreData();
    }

    uint32_t pageSize = format_utils::readBe16(buffer, position + 16);
    if (pageSize == 1) {
        pageSize = 65536;
    }

    const uint32_t pageCount = format_utils::readBe32(buffer, position + 28);
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) {
        return MatchResult::noMatch();
    }

    const uint64_t fileSize =
        static_cast<uint64_t>(pageSize) * std::max<uint32_t>(pageCount, 1);

    if (!isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::needMoreData();
    }

    if (isFinalChunk && fileSize > buffer.size() - position) {
        return MatchResult::partial(
            buffer.size() - position,
            "valid SQLite header, truncated database payload");
    }

    return MatchResult::matched(static_cast<size_t>(fileSize));
}

FileAnalysis SqliteHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    if (!format_utils::hasBytes(buffer, position, SQLITE_HEADER_SIZE)) {
        analysis.warnings.push_back("truncated SQLite header");
        return analysis;
    }

    uint32_t pageSize = format_utils::readBe16(buffer, position + 16);
    if (pageSize == 1) {
        pageSize = 65536;
    }

    const uint32_t pageCount = format_utils::readBe32(buffer, position + 28);
    const uint8_t writeVersion = buffer[position + 18];
    const uint8_t readVersion = buffer[position + 19];
    const uint32_t schemaFormat = format_utils::readBe32(buffer, position + 44);
    const uint32_t encoding = format_utils::readBe32(buffer, position + 56);
    const uint32_t userVersion = format_utils::readBe32(buffer, position + 60);
    const uint32_t applicationId = format_utils::readBe32(buffer, position + 68);

    analysis.metadata.push_back("page_size=" + std::to_string(pageSize));
    analysis.metadata.push_back("pages=" + std::to_string(pageCount));
    analysis.metadata.push_back(
        "read_version=" + std::to_string(readVersion) +
        ", write_version=" + std::to_string(writeVersion));
    analysis.metadata.push_back(
        "schema_format=" + std::to_string(schemaFormat) +
        ", encoding=" + encodingName(encoding));
    analysis.metadata.push_back(
        "user_version=" + std::to_string(userVersion) +
        ", application_id=" + format_utils::hexValue(applicationId, 8));
    return analysis;
}
