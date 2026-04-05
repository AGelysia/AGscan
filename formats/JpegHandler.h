#pragma once
#include "IFileHandler.h"

class JpegHandler : public IFileHandler {
public:
    std::string type() const override;
    bool match(const std::vector<uint8_t>& buffer,
        size_t position) const override;
    size_t getSize(const std::vector<uint8_t>& buffer,
        size_t position) const override;
};