#pragma once
#include <vector>
#include <string>
#include <cstdint>

class IFileHandler {
public:
    virtual ~IFileHandler() = default;

    virtual std::string type() const = 0;

    virtual bool match(const std::vector<uint8_t>& buffer,
        size_t position) const = 0;

    virtual size_t getSize(const std::vector<uint8_t>& buffer,
        size_t position) const = 0;
};