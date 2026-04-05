#include "PdfHandler.h"
#include "FormatUtils.h"
#include <array>
#include <cctype>
#include <string>

namespace {
constexpr std::array<uint8_t, 5> PDF_HEAD = { '%', 'P', 'D', 'F', '-' };
constexpr std::array<uint8_t, 5> PDF_EOF = { '%', '%', 'E', 'O', 'F' };

bool matchesSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!format_utils::hasBytes(buffer, pos, PDF_HEAD.size())) {
        return false;
    }

    for (size_t i = 0; i < PDF_HEAD.size(); ++i) {
        if (buffer[pos + i] != PDF_HEAD[i]) {
            return false;
        }
    }
    return true;
}

bool matchesPartialSignature(const std::vector<uint8_t>& buffer, size_t pos) {
    if (pos >= buffer.size()) {
        return false;
    }

    const size_t available = buffer.size() - pos;
    if (available >= PDF_HEAD.size()) {
        return false;
    }

    for (size_t i = 0; i < available; ++i) {
        if (buffer[pos + i] != PDF_HEAD[i]) {
            return false;
        }
    }
    return true;
}

size_t findLastPdfEof(const std::vector<uint8_t>& buffer, size_t pos) {
    size_t last = std::string::npos;
    constexpr size_t contextWindow = 4096;
    const auto hasNearbyToken = [&](size_t markerPos, const char* token) {
        const size_t tokenLength = std::char_traits<char>::length(token);
        const size_t searchStart =
            markerPos > contextWindow ? markerPos - contextWindow : pos;

        for (size_t i = searchStart; i + tokenLength <= markerPos; ++i) {
            bool match = true;
            for (size_t j = 0; j < tokenLength; ++j) {
                if (buffer[i + j] != static_cast<uint8_t>(token[j])) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return true;
            }
        }

        return false;
        };

    for (size_t i = pos + PDF_HEAD.size(); i + PDF_EOF.size() <= buffer.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < PDF_EOF.size(); ++j) {
            if (buffer[i + j] != PDF_EOF[j]) {
                match = false;
                break;
            }
        }

        if (!match) {
            continue;
        }

        if (hasNearbyToken(i, "startxref") || hasNearbyToken(i, "trailer")) {
            last = i;
        }
    }
    return last;
}
}

std::string PdfHandler::type() const {
    return "pdf";
}

bool PdfHandler::canStartWith(uint8_t value) const {
    return value == '%';
}

size_t PdfHandler::minimumSize() const {
    return 8;
}

MatchResult PdfHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    if (!format_utils::hasBytes(buffer, position, PDF_HEAD.size())) {
        if (matchesPartialSignature(buffer, position) && !isFinalChunk) {
            return MatchResult::needMoreData();
        }
        return MatchResult::noMatch();
    }

    if (!matchesSignature(buffer, position)) {
        return MatchResult::noMatch();
    }

    const size_t eofPos = findLastPdfEof(buffer, position);
    if (eofPos == std::string::npos) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - position,
                "valid PDF header, %%EOF not found")
            : MatchResult::needMoreData();
    }

    size_t end = eofPos + PDF_EOF.size();
    while (end < buffer.size() &&
        std::isspace(static_cast<unsigned char>(buffer[end])) != 0) {
        ++end;
    }

    return MatchResult::matched(end - position);
}

FileAnalysis PdfHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t size) const {

    FileAnalysis analysis;
    if (!format_utils::hasBytes(buffer, position, size)) {
        analysis.warnings.push_back("truncated PDF payload");
        return analysis;
    }

    size_t cursor = position + PDF_HEAD.size();
    while (cursor < buffer.size() && cursor < position + 16) {
        const unsigned char ch = buffer[cursor];
        if (std::isdigit(ch) == 0 && ch != '.') {
            break;
        }
        ++cursor;
    }

    const std::string version(
        reinterpret_cast<const char*>(buffer.data() + position + PDF_HEAD.size()),
        cursor - (position + PDF_HEAD.size()));
    analysis.metadata.push_back("version=" + version);

    size_t pageCount = 0;
    static const std::string token = "/Type /Page";
    for (size_t i = position; i + token.size() <= position + size; ++i) {
        bool match = true;
        for (size_t j = 0; j < token.size(); ++j) {
            if (buffer[i + j] != static_cast<uint8_t>(token[j])) {
                match = false;
                break;
            }
        }

        if (match) {
            const size_t next = i + token.size();
            if (next >= position + size || buffer[next] != 's') {
                ++pageCount;
            }
        }
    }

    if (pageCount != 0) {
        analysis.metadata.push_back("page_objects~" + std::to_string(pageCount));
    }

    const std::string payload = format_utils::readAscii(buffer, position, size);
    if (payload.find("/Encrypt") != std::string::npos) {
        analysis.metadata.push_back("encryption=present");
    }
    else {
        analysis.metadata.push_back("encryption=not_seen");
    }

    const auto findDate = [&](const std::string& token) {
        const size_t tokenPos = payload.find(token);
        if (tokenPos == std::string::npos) {
            return std::string{};
        }

        size_t start = payload.find('(', tokenPos + token.size());
        if (start == std::string::npos) {
            return std::string{};
        }

        const size_t end = payload.find(')', start + 1);
        if (end == std::string::npos || end <= start + 1) {
            return std::string{};
        }

        return payload.substr(start + 1, end - start - 1);
        };

    const std::string creationDate = findDate("/CreationDate");
    if (!creationDate.empty()) {
        analysis.metadata.push_back("creation_date=" + creationDate);
    }

    const std::string modDate = findDate("/ModDate");
    if (!modDate.empty()) {
        analysis.metadata.push_back("mod_date=" + modDate);
    }
    return analysis;
}
