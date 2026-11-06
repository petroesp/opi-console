#pragma once

#include <stddef.h>
#include <stdint.h>

namespace ws_uart {

constexpr uint8_t TEXT_OPCODE = 0x1;
constexpr uint8_t BINARY_OPCODE = 0x2;
constexpr uint8_t CONTINUATION_OPCODE = 0x0;

inline bool supportedOpcode(uint8_t opcode) {
  return opcode == TEXT_OPCODE || opcode == BINARY_OPCODE || opcode == CONTINUATION_OPCODE;
}

template <typename Uart>
size_t writeChunk(Uart& uart, uint8_t opcode, uint64_t frameLength, uint64_t offset,
                  const uint8_t* data, size_t length) {
  if (!supportedOpcode(opcode) || length == 0 || offset > frameLength ||
      length > frameLength - offset) {
    return 0;
  }
  return uart.write(data, length);
}

}  // namespace ws_uart
