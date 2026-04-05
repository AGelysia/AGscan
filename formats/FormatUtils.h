#pragma once
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

namespace format_utils {
inline bool hasBytes(const std::vector<uint8_t>& buffer,
    size_t pos,
    size_t count) {

    return pos <= buffer.size() && count <= buffer.size() - pos;
}

inline uint16_t readLe16(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(buffer[pos]) |
        (static_cast<uint16_t>(buffer[pos + 1]) << 8));
}

inline uint32_t readLe24(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<uint32_t>(buffer[pos]) |
        (static_cast<uint32_t>(buffer[pos + 1]) << 8) |
        (static_cast<uint32_t>(buffer[pos + 2]) << 16);
}

inline uint32_t readBe24(const std::vector<uint8_t>& buffer, size_t pos) {
    return (static_cast<uint32_t>(buffer[pos]) << 16) |
        (static_cast<uint32_t>(buffer[pos + 1]) << 8) |
        static_cast<uint32_t>(buffer[pos + 2]);
}

inline uint32_t readLe32(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<uint32_t>(buffer[pos]) |
        (static_cast<uint32_t>(buffer[pos + 1]) << 8) |
        (static_cast<uint32_t>(buffer[pos + 2]) << 16) |
        (static_cast<uint32_t>(buffer[pos + 3]) << 24);
}

inline uint64_t readLe64(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<uint64_t>(readLe32(buffer, pos)) |
        (static_cast<uint64_t>(readLe32(buffer, pos + 4)) << 32);
}

inline uint16_t readBe16(const std::vector<uint8_t>& buffer, size_t pos) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(buffer[pos]) << 8) |
        static_cast<uint16_t>(buffer[pos + 1]));
}

inline uint32_t readBe32(const std::vector<uint8_t>& buffer, size_t pos) {
    return (static_cast<uint32_t>(buffer[pos]) << 24) |
        (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
        (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
        static_cast<uint32_t>(buffer[pos + 3]);
}

inline uint64_t readBe64(const std::vector<uint8_t>& buffer, size_t pos) {
    return (static_cast<uint64_t>(readBe32(buffer, pos)) << 32) |
        static_cast<uint64_t>(readBe32(buffer, pos + 4));
}

inline uint32_t crc32(const uint8_t* data, size_t size) {
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> values{};
        for (uint32_t i = 0; i < values.size(); ++i) {
            uint32_t crc = i;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1) != 0
                    ? 0xEDB88320U ^ (crc >> 1)
                    : (crc >> 1);
            }
            values[i] = crc;
        }
        return values;
        }();

    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < size; ++i) {
        crc = table[(crc ^ data[i]) & 0xFFU] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFFU;
}

inline uint32_t crc32(const std::vector<uint8_t>& buffer,
    size_t pos,
    size_t size) {

    return crc32(buffer.data() + pos, size);
}

inline std::string dimensionsToString(uint32_t width, uint32_t height) {
    return std::to_string(width) + "x" + std::to_string(height);
}

inline std::string hexValue(uint64_t value, size_t width = 0) {
    std::ostringstream out;
    out << "0x"
        << std::uppercase
        << std::hex
        << std::setfill('0');

    if (width != 0) {
        out << std::setw(static_cast<int>(width));
    }

    out << value;
    return out.str();
}

inline std::string trimAscii(const std::string& value) {
    size_t start = 0;
    while (start < value.size() &&
        std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }

    size_t end = value.size();
    while (end > start &&
        std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return value.substr(start, end - start);
}

inline std::string readAscii(const std::vector<uint8_t>& buffer,
    size_t pos,
    size_t size) {

    if (!hasBytes(buffer, pos, size)) {
        return {};
    }

    return std::string(
        reinterpret_cast<const char*>(buffer.data() + pos),
        size);
}

inline std::string formatUtcTime(std::time_t timestamp) {
    std::tm value{};
#ifdef _WIN32
    if (gmtime_s(&value, &timestamp) != 0) {
        return "invalid";
    }
#else
    if (gmtime_r(&timestamp, &value) == nullptr) {
        return "invalid";
    }
#endif

    std::ostringstream out;
    out << std::put_time(&value, "%Y-%m-%d %H:%M:%SZ");
    return out.str();
}

inline std::string formatUnixTime(int64_t seconds) {
    if (seconds < 0) {
        return "invalid";
    }

    return formatUtcTime(static_cast<std::time_t>(seconds));
}

inline std::string formatDosDateTime(uint16_t date, uint16_t time) {
    const int day = date & 0x1F;
    const int month = (date >> 5) & 0x0F;
    const int year = ((date >> 9) & 0x7F) + 1980;
    const int second = (time & 0x1F) * 2;
    const int minute = (time >> 5) & 0x3F;
    const int hour = (time >> 11) & 0x1F;

    if (year < 1980 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59) {
        return "invalid";
    }

    std::ostringstream out;
    out << std::setfill('0')
        << std::setw(4) << year
        << "-"
        << std::setw(2) << month
        << "-"
        << std::setw(2) << day
        << " "
        << std::setw(2) << hour
        << ":"
        << std::setw(2) << minute
        << ":"
        << std::setw(2) << second;
    return out.str();
}

inline std::string formatMacEpochTime(uint64_t secondsSince1904) {
    constexpr uint64_t UnixEpochDelta = 2082844800ULL;
    if (secondsSince1904 < UnixEpochDelta) {
        return "invalid";
    }

    return formatUnixTime(
        static_cast<int64_t>(secondsSince1904 - UnixEpochDelta));
}

inline std::string ipv4ToString(const std::vector<uint8_t>& buffer, size_t pos) {
    if (!hasBytes(buffer, pos, 4)) {
        return {};
    }

    return std::to_string(buffer[pos]) + "." +
        std::to_string(buffer[pos + 1]) + "." +
        std::to_string(buffer[pos + 2]) + "." +
        std::to_string(buffer[pos + 3]);
}
}
