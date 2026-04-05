#include "JavaClassHandler.h"
#include "FormatUtils.h"
#include <vector>

namespace {
struct ClassInfo {
    uint16_t minor = 0;
    uint16_t major = 0;
    uint16_t constantPoolEntries = 0;
    uint16_t fieldCount = 0;
    uint16_t methodCount = 0;
    std::string className;
};

const char* javaVersionName(uint16_t major) {
    switch (major) {
    case 45:
        return "Java 1.1";
    case 46:
        return "Java 1.2";
    case 47:
        return "Java 1.3";
    case 48:
        return "Java 1.4";
    case 49:
        return "Java 5";
    case 50:
        return "Java 6";
    case 51:
        return "Java 7";
    case 52:
        return "Java 8";
    case 53:
        return "Java 9";
    case 54:
        return "Java 10";
    case 55:
        return "Java 11";
    case 56:
        return "Java 12";
    case 57:
        return "Java 13";
    case 58:
        return "Java 14";
    case 59:
        return "Java 15";
    case 60:
        return "Java 16";
    case 61:
        return "Java 17";
    case 62:
        return "Java 18";
    case 63:
        return "Java 19";
    case 64:
        return "Java 20";
    case 65:
        return "Java 21";
    default:
        return "unknown";
    }
}

bool parseAttributes(const std::vector<uint8_t>& buffer,
    size_t end,
    size_t& cursor,
    uint16_t count) {

    for (uint16_t i = 0; i < count; ++i) {
        if (!format_utils::hasBytes(buffer, cursor, 6)) {
            return false;
        }

        const uint32_t length = format_utils::readBe32(buffer, cursor + 2);
        cursor += 6;
        if (!format_utils::hasBytes(buffer, cursor, length)) {
            return false;
        }
        cursor += length;
    }

    return cursor <= end;
}

MatchResult parseJavaClass(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    ClassInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 10)) {
        return isFinalChunk
            ? MatchResult::partial(buffer.size() - pos, "partial Java class header")
            : MatchResult::needMoreData();
    }

    if (format_utils::readBe32(buffer, pos) != 0xCAFEBABEU) {
        return MatchResult::noMatch();
    }

    size_t cursor = pos + 4;
    const uint16_t minor = format_utils::readBe16(buffer, cursor);
    const uint16_t major = format_utils::readBe16(buffer, cursor + 2);
    const uint16_t constantPoolCount = format_utils::readBe16(buffer, cursor + 4);
    cursor += 6;

    if (constantPoolCount == 0) {
        return MatchResult::noMatch();
    }

    std::vector<std::string> utf8(constantPoolCount);
    std::vector<uint16_t> classNameIndex(constantPoolCount, 0);

    for (uint16_t index = 1; index < constantPoolCount; ++index) {
        if (!format_utils::hasBytes(buffer, cursor, 1)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid Java class header, truncated constant pool")
                : MatchResult::needMoreData();
        }

        const uint8_t tag = buffer[cursor++];
        switch (tag) {
        case 1: {
            if (!format_utils::hasBytes(buffer, cursor, 2)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated UTF-8 entry")
                    : MatchResult::needMoreData();
            }
            const uint16_t length = format_utils::readBe16(buffer, cursor);
            cursor += 2;
            if (!format_utils::hasBytes(buffer, cursor, length)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated UTF-8 payload")
                    : MatchResult::needMoreData();
            }
            utf8[index] = std::string(
                reinterpret_cast<const char*>(buffer.data() + cursor),
                length);
            cursor += length;
            break;
        }
        case 3:
        case 4:
            if (!format_utils::hasBytes(buffer, cursor, 4)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated numeric entry")
                    : MatchResult::needMoreData();
            }
            cursor += 4;
            break;
        case 5:
        case 6:
            if (!format_utils::hasBytes(buffer, cursor, 8)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated wide numeric entry")
                    : MatchResult::needMoreData();
            }
            cursor += 8;
            ++index;
            break;
        case 7:
        case 8:
        case 16:
        case 19:
        case 20:
            if (!format_utils::hasBytes(buffer, cursor, 2)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated reference entry")
                    : MatchResult::needMoreData();
            }
            if (tag == 7) {
                classNameIndex[index] = format_utils::readBe16(buffer, cursor);
            }
            cursor += 2;
            break;
        case 9:
        case 10:
        case 11:
        case 12:
        case 17:
        case 18:
            if (!format_utils::hasBytes(buffer, cursor, 4)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated member reference")
                    : MatchResult::needMoreData();
            }
            cursor += 4;
            break;
        case 15:
            if (!format_utils::hasBytes(buffer, cursor, 3)) {
                return isFinalChunk
                    ? MatchResult::partial(
                        buffer.size() - pos,
                        "valid Java class constant pool, truncated handle entry")
                    : MatchResult::needMoreData();
            }
            cursor += 3;
            break;
        default:
            return MatchResult::noMatch();
        }
    }

    if (!format_utils::hasBytes(buffer, cursor, 8)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class constant pool, truncated class header")
            : MatchResult::needMoreData();
    }

    cursor += 2;
    const uint16_t thisClass = format_utils::readBe16(buffer, cursor);
    cursor += 4;

    const uint16_t interfacesCount = format_utils::readBe16(buffer, cursor);
    cursor += 2;
    if (!format_utils::hasBytes(buffer, cursor, static_cast<size_t>(interfacesCount) * 2)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class interfaces table, truncated payload")
            : MatchResult::needMoreData();
    }
    cursor += static_cast<size_t>(interfacesCount) * 2;

    if (!format_utils::hasBytes(buffer, cursor, 2)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class fields count, truncated payload")
            : MatchResult::needMoreData();
    }
    const uint16_t fieldsCount = format_utils::readBe16(buffer, cursor);
    cursor += 2;

    for (uint16_t i = 0; i < fieldsCount; ++i) {
        if (!format_utils::hasBytes(buffer, cursor, 8)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid Java class field table, truncated entry")
                : MatchResult::needMoreData();
        }
        cursor += 6;
        const uint16_t attributesCount = format_utils::readBe16(buffer, cursor);
        cursor += 2;
        if (!parseAttributes(buffer, buffer.size(), cursor, attributesCount)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid Java class field attributes, truncated payload")
                : MatchResult::needMoreData();
        }
    }

    if (!format_utils::hasBytes(buffer, cursor, 2)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class methods count, truncated payload")
            : MatchResult::needMoreData();
    }
    const uint16_t methodsCount = format_utils::readBe16(buffer, cursor);
    cursor += 2;

    for (uint16_t i = 0; i < methodsCount; ++i) {
        if (!format_utils::hasBytes(buffer, cursor, 8)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid Java class method table, truncated entry")
                : MatchResult::needMoreData();
        }
        cursor += 6;
        const uint16_t attributesCount = format_utils::readBe16(buffer, cursor);
        cursor += 2;
        if (!parseAttributes(buffer, buffer.size(), cursor, attributesCount)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid Java class method attributes, truncated payload")
                : MatchResult::needMoreData();
        }
    }

    if (!format_utils::hasBytes(buffer, cursor, 2)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class attributes count, truncated payload")
            : MatchResult::needMoreData();
    }
    const uint16_t classAttributes = format_utils::readBe16(buffer, cursor);
    cursor += 2;
    if (!parseAttributes(buffer, buffer.size(), cursor, classAttributes)) {
        return isFinalChunk
            ? MatchResult::partial(
                buffer.size() - pos,
                "valid Java class attributes, truncated payload")
            : MatchResult::needMoreData();
    }

    if (info != nullptr) {
        info->minor = minor;
        info->major = major;
        info->constantPoolEntries = static_cast<uint16_t>(constantPoolCount - 1);
        info->fieldCount = fieldsCount;
        info->methodCount = methodsCount;

        if (thisClass < classNameIndex.size()) {
            const uint16_t nameIndex = classNameIndex[thisClass];
            if (nameIndex < utf8.size()) {
                info->className = utf8[nameIndex];
            }
        }
    }

    return MatchResult::matched(cursor - pos);
}
}

std::string JavaClassHandler::type() const {
    return "class";
}

std::string JavaClassHandler::extension() const {
    return "class";
}

bool JavaClassHandler::canStartWith(uint8_t value) const {
    return value == 0xCA;
}

size_t JavaClassHandler::minimumSize() const {
    return 10;
}

MatchResult JavaClassHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    ClassInfo info;
    return parseJavaClass(buffer, position, isFinalChunk, &info);
}

FileAnalysis JavaClassHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    ClassInfo info;
    const MatchResult result = parseJavaClass(buffer, position, true, &info);
    if (result.status == MatchStatus::no_match) {
        analysis.warnings.push_back("Java class analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        "version=" + std::to_string(info.major) + "." + std::to_string(info.minor) +
        " (" + javaVersionName(info.major) + ")");
    analysis.metadata.push_back(
        "constant_pool=" + std::to_string(info.constantPoolEntries) +
        ", fields=" + std::to_string(info.fieldCount) +
        ", methods=" + std::to_string(info.methodCount));
    if (!info.className.empty()) {
        analysis.metadata.push_back("class_name=" + info.className);
    }
    if (result.status == MatchStatus::partial_match) {
        analysis.warnings.push_back("Java class payload appears truncated");
    }
    return analysis;
}
