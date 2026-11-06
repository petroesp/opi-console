#pragma once

#include <stddef.h>
#include <stdint.h>

namespace uart_rx {

template <size_t Capacity>
class Buffer {
 public:
  void push(uint8_t value) {
    bytes_[sequence_ % Capacity] = value;
    ++sequence_;
  }

  uint64_t sequence() const { return sequence_; }

  size_t read(uint64_t since, uint8_t* output, size_t limit, uint64_t& next) const {
    const uint64_t oldest = sequence_ > Capacity ? sequence_ - Capacity : 0;
    uint64_t start = since < oldest ? oldest : since;
    if (start > sequence_) start = sequence_;
    const uint64_t remaining = sequence_ - start;
    const size_t count = remaining < limit ? static_cast<size_t>(remaining) : limit;
    for (size_t i = 0; i < count; ++i) {
      output[i] = bytes_[(start + i) % Capacity];
    }
    next = start + count;
    return count;
  }

 private:
  uint8_t bytes_[Capacity] = {};
  uint64_t sequence_ = 0;
};

}  // namespace uart_rx
