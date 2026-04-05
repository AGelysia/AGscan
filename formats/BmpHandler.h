#pragma once
#include "IFileHandler.h"

class BmpHandler : public IFileHandler {
public:
    std::string type() const override;
    bool canStartWith(uint8_t value) const override;
    size_t minimumSize() const override;
    MatchResult detect(const std::vector<uint8_t>& buffer,
        size_t position,
        bool isFinalChunk) const override;
    FileAnalysis analyze(const std::vector<uint8_t>& buffer,
        size_t position,
        size_t size) const override;
};
