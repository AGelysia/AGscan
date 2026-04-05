#include "RtfHandler.h"
#include "FormatUtils.h"
#include <cctype>
#include <string>

namespace {
constexpr char RTF_HEAD[] = "{\\rtf";

bool hasSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    return format_utils::hasBytes(buffer, pos, 5) &&
        buffer[pos] == '{' &&
        buffer[pos + 1] == '\\' &&
        buffer[pos + 2] == 'r' &&
        buffer[pos + 3] == 't' &&
        buffer[pos + 4] == 'f';
}

bool matchesPartialSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (pos >= buffer.size()) {
        return false;
    }

    const size_t available = buffer.size() - pos;
    if (available >= 5) {
        return false;
    }

    for (size_t i = 0; i < available; ++i) {
        if (buffer[pos + i] != static_cast<uint8_t>(RTF_HEAD[i])) {
            return false;
        }
    }

    return true;
}

struct RtfInfo {
    std::string version;
    std::string charset = "unknown";
    std::string codepage;
    std::string generator;
    size_t paragraphs = 0;
};

MatchResult parseRtf(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    RtfInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 5)) {
        if (!isFinalChunk && matchesPartialSignature(buffer, pos)) {
            return MatchResult::needMoreData();
        }

        return isFinalChunk
            ? MatchResult::partial(buffer.size() - pos, "partial RTF header")
            : MatchResult::needMoreData();
    }

    if (!hasSignature(buffer, pos)) {
        return MatchResult::noMatch();
    }

    if (info != nullptr) {
        size_t cursor = pos + 5;
        while (cursor < buffer.size() &&
            std::isdigit(static_cast<unsigned char>(buffer[cursor])) != 0) {
            info->version.push_back(static_cast<char>(buffer[cursor]));
            ++cursor;
        }
    }

    size_t depth = 0;
    bool escaped = false;
    for (size_t cursor = pos; cursor < buffer.size(); ++cursor) {
        const uint8_t ch = buffer[cursor];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (ch == '\\') {
            escaped = true;
            continue;
        }

        if (ch == '{') {
            ++depth;
            continue;
        }

        if (ch == '}') {
            if (depth == 0) {
                return MatchResult::noMatch();
            }

            --depth;
            if (depth == 0) {
                return MatchResult::matched(cursor - pos + 1);
            }
        }
    }

    return isFinalChunk
        ? MatchResult::partial(
            buffer.size() - pos,
            "valid RTF header, missing closing brace")
        : MatchResult::needMoreData();
}

std::string findControlWordValue(const std::string& payload,
    const std::string& token) {

    const size_t start = payload.find(token);
    if (start == std::string::npos) {
        return {};
    }

    size_t cursor = start + token.size();
    while (cursor < payload.size() &&
        std::isdigit(static_cast<unsigned char>(payload[cursor])) != 0) {
        ++cursor;
    }

    return payload.substr(start + token.size(), cursor - (start + token.size()));
}
}

std::string RtfHandler::type() const {
    return "rtf";
}

bool RtfHandler::canStartWith(uint8_t value) const {
    return value == '{';
}

size_t RtfHandler::minimumSize() const {
    return 5;
}

MatchResult RtfHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    RtfInfo info;
    return parseRtf(buffer, position, isFinalChunk, &info);
}

FileAnalysis RtfHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t size) const {

    FileAnalysis analysis;
    RtfInfo info;
    const MatchResult result = parseRtf(buffer, position, true, &info);
    if (result.status == MatchStatus::no_match) {
        analysis.warnings.push_back("RTF analysis failed on carved payload");
        return analysis;
    }

    const size_t payloadSize = std::min(size, buffer.size() - position);
    const std::string payload = format_utils::readAscii(buffer, position, payloadSize);

    if (!info.version.empty()) {
        analysis.metadata.push_back("rtf_version=" + info.version);
    }

    if (payload.find("\\ansi") != std::string::npos) {
        info.charset = "ansi";
    }
    else if (payload.find("\\mac") != std::string::npos) {
        info.charset = "mac";
    }
    else if (payload.find("\\pc") != std::string::npos) {
        info.charset = "pc";
    }
    else if (payload.find("\\pca") != std::string::npos) {
        info.charset = "pca";
    }

    analysis.metadata.push_back("charset=" + info.charset);

    info.codepage = findControlWordValue(payload, "\\ansicpg");
    if (!info.codepage.empty()) {
        analysis.metadata.push_back("codepage=" + info.codepage);
    }

    const size_t generatorPos = payload.find("\\generator");
    if (generatorPos != std::string::npos) {
        size_t start = generatorPos + 10;
        while (start < payload.size() &&
            std::isspace(static_cast<unsigned char>(payload[start])) != 0) {
            ++start;
        }

        size_t end = payload.find(';', start);
        if (end != std::string::npos && end > start) {
            info.generator = format_utils::trimAscii(payload.substr(start, end - start));
            if (!info.generator.empty()) {
                analysis.metadata.push_back("generator=" + info.generator);
            }
        }
    }

    size_t search = 0;
    while ((search = payload.find("\\par", search)) != std::string::npos) {
        ++info.paragraphs;
        search += 4;
    }

    analysis.metadata.push_back("paragraphs~" + std::to_string(info.paragraphs));
    if (result.status == MatchStatus::partial_match) {
        analysis.warnings.push_back("RTF payload appears truncated");
    }
    return analysis;
}
