#include "PcapHandler.h"
#include "FormatUtils.h"
#include <array>
#include <set>
#include <sstream>

namespace {
constexpr uint32_t PCAP_MAGIC_USEC = 0xA1B2C3D4U;
constexpr uint32_t PCAP_MAGIC_NSEC = 0xA1B23C4DU;

struct PcapInfo {
    bool bigEndian = false;
    bool nanosecondResolution = false;
    uint16_t versionMajor = 0;
    uint16_t versionMinor = 0;
    uint32_t snaplen = 0;
    uint32_t network = 0;
    size_t packets = 0;
    uint32_t firstSec = 0;
    uint32_t firstFrac = 0;
    uint32_t lastSec = 0;
    uint32_t lastFrac = 0;
    std::set<std::string> ipv4Peers;
};

bool determinePcapFormat(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool& bigEndian,
    bool& nanosecondResolution) {

    if (!format_utils::hasBytes(buffer, pos, 4)) {
        return false;
    }

    const uint32_t little = format_utils::readLe32(buffer, pos);
    if (little == PCAP_MAGIC_USEC) {
        bigEndian = false;
        nanosecondResolution = false;
        return true;
    }

    if (little == PCAP_MAGIC_NSEC) {
        bigEndian = false;
        nanosecondResolution = true;
        return true;
    }

    const uint32_t big = format_utils::readBe32(buffer, pos);
    if (big == PCAP_MAGIC_USEC) {
        bigEndian = true;
        nanosecondResolution = false;
        return true;
    }

    if (big == PCAP_MAGIC_NSEC) {
        bigEndian = true;
        nanosecondResolution = true;
        return true;
    }

    return false;
}

uint16_t readU16(const std::vector<uint8_t>& buffer, size_t pos, bool bigEndian) {
    return bigEndian
        ? format_utils::readBe16(buffer, pos)
        : format_utils::readLe16(buffer, pos);
}

uint32_t readU32(const std::vector<uint8_t>& buffer, size_t pos, bool bigEndian) {
    return bigEndian
        ? format_utils::readBe32(buffer, pos)
        : format_utils::readLe32(buffer, pos);
}

const char* linkTypeName(uint32_t value) {
    switch (value) {
    case 1:
        return "ethernet";
    case 101:
        return "raw-ip";
    case 113:
        return "linux-sll";
    default:
        return "unknown";
    }
}

std::string formatPcapTimestamp(uint32_t seconds,
    uint32_t fraction,
    bool nanosecondResolution) {

    std::ostringstream out;
    out << format_utils::formatUnixTime(seconds)
        << "."
        << std::setfill('0')
        << std::setw(nanosecondResolution ? 9 : 6)
        << fraction;
    return out.str();
}

void collectIpv4Peers(const std::vector<uint8_t>& buffer,
    size_t packetPos,
    uint32_t capturedLength,
    uint32_t linkType,
    std::set<std::string>& peers) {

    if (linkType == 1) {
        if (capturedLength < 34) {
            return;
        }

        if (buffer[packetPos + 12] != 0x08 || buffer[packetPos + 13] != 0x00) {
            return;
        }

        peers.insert(format_utils::ipv4ToString(buffer, packetPos + 26));
        peers.insert(format_utils::ipv4ToString(buffer, packetPos + 30));
        return;
    }

    if (linkType == 101) {
        if (capturedLength < 20 || (buffer[packetPos] >> 4) != 4) {
            return;
        }

        peers.insert(format_utils::ipv4ToString(buffer, packetPos + 12));
        peers.insert(format_utils::ipv4ToString(buffer, packetPos + 16));
    }
}

MatchResult parsePcap(const std::vector<uint8_t>& buffer,
    size_t pos,
    bool isFinalChunk,
    PcapInfo* info) {

    if (!format_utils::hasBytes(buffer, pos, 24)) {
        return isFinalChunk
            ? MatchResult::partial(buffer.size() - pos, "partial pcap global header")
            : MatchResult::needMoreData();
    }

    bool bigEndian = false;
    bool nanosecondResolution = false;
    if (!determinePcapFormat(buffer, pos, bigEndian, nanosecondResolution)) {
        return MatchResult::noMatch();
    }

    const uint16_t versionMajor = readU16(buffer, pos + 4, bigEndian);
    const uint16_t versionMinor = readU16(buffer, pos + 6, bigEndian);
    const uint32_t snaplen = readU32(buffer, pos + 16, bigEndian);
    const uint32_t network = readU32(buffer, pos + 20, bigEndian);

    if (versionMajor == 0 || snaplen == 0 || snaplen > (16U * 1024U * 1024U)) {
        return MatchResult::noMatch();
    }

    if (info != nullptr) {
        info->bigEndian = bigEndian;
        info->nanosecondResolution = nanosecondResolution;
        info->versionMajor = versionMajor;
        info->versionMinor = versionMinor;
        info->snaplen = snaplen;
        info->network = network;
    }

    size_t cursor = pos + 24;
    while (cursor < buffer.size()) {
        if (!format_utils::hasBytes(buffer, cursor, 16)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid pcap global header, truncated packet header")
                : MatchResult::needMoreData();
        }

        const uint32_t tsSec = readU32(buffer, cursor, bigEndian);
        const uint32_t tsFrac = readU32(buffer, cursor + 4, bigEndian);
        const uint32_t inclLen = readU32(buffer, cursor + 8, bigEndian);
        const uint32_t origLen = readU32(buffer, cursor + 12, bigEndian);
        if (inclLen > snaplen || origLen < inclLen) {
            return cursor == pos + 24
                ? MatchResult::noMatch()
                : MatchResult::matched(cursor - pos);
        }

        if (!format_utils::hasBytes(buffer, cursor + 16, inclLen)) {
            return isFinalChunk
                ? MatchResult::partial(
                    buffer.size() - pos,
                    "valid pcap packet header, truncated packet data")
                : MatchResult::needMoreData();
        }

        if (info != nullptr) {
            if (info->packets == 0) {
                info->firstSec = tsSec;
                info->firstFrac = tsFrac;
            }
            info->lastSec = tsSec;
            info->lastFrac = tsFrac;
            ++info->packets;
            if (info->ipv4Peers.size() < 8) {
                collectIpv4Peers(buffer, cursor + 16, inclLen, network, info->ipv4Peers);
            }
        }

        cursor += 16ULL + inclLen;

        if (cursor == buffer.size()) {
            return isFinalChunk
                ? MatchResult::matched(cursor - pos)
                : MatchResult::needMoreData();
        }
    }

    return MatchResult::matched(cursor - pos);
}
}

std::string PcapHandler::type() const {
    return "pcap";
}

std::string PcapHandler::extension() const {
    return "pcap";
}

bool PcapHandler::canStartWith(uint8_t value) const {
    return value == 0xD4 || value == 0xA1 || value == 0x4D;
}

size_t PcapHandler::minimumSize() const {
    return 24;
}

MatchResult PcapHandler::detect(const std::vector<uint8_t>& buffer,
    size_t position,
    bool isFinalChunk) const {

    PcapInfo info;
    return parsePcap(buffer, position, isFinalChunk, &info);
}

FileAnalysis PcapHandler::analyze(const std::vector<uint8_t>& buffer,
    size_t position,
    size_t) const {

    FileAnalysis analysis;
    PcapInfo info;
    const MatchResult result = parsePcap(buffer, position, true, &info);
    if (result.status == MatchStatus::no_match) {
        analysis.warnings.push_back("pcap analysis failed on carved payload");
        return analysis;
    }

    analysis.metadata.push_back(
        std::string("version=") +
        std::to_string(info.versionMajor) + "." + std::to_string(info.versionMinor));
    analysis.metadata.push_back(
        std::string("endian=") + (info.bigEndian ? "big" : "little") +
        ", ts_resolution=" + (info.nanosecondResolution ? "ns" : "us"));
    analysis.metadata.push_back(
        "linktype=" + std::string(linkTypeName(info.network)) +
        ", packets=" + std::to_string(info.packets));
    analysis.metadata.push_back("snaplen=" + std::to_string(info.snaplen));
    if (info.packets != 0) {
        analysis.metadata.push_back(
            "first_packet=" +
            formatPcapTimestamp(info.firstSec, info.firstFrac, info.nanosecondResolution));
        analysis.metadata.push_back(
            "last_packet=" +
            formatPcapTimestamp(info.lastSec, info.lastFrac, info.nanosecondResolution));
    }

    if (!info.ipv4Peers.empty()) {
        std::string peers = "ipv4_peers=";
        bool first = true;
        for (const auto& peer : info.ipv4Peers) {
            if (!first) {
                peers += ", ";
            }
            peers += peer;
            first = false;
        }
        analysis.metadata.push_back(peers);
    }

    if (result.status == MatchStatus::partial_match) {
        analysis.warnings.push_back("pcap payload appears truncated");
    }
    return analysis;
}
