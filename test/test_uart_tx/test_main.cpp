#include <unity.h>

#include <string>
#include <vector>

#include "../../src/ws_uart.h"
#include "../../src/uart_rx_buffer.h"

class FakeUart {
 public:
  size_t write(const uint8_t* data, size_t length) {
    const size_t written = length < maxWrite ? length : maxWrite;
    bytes.insert(bytes.end(), data, data + written);
    return written;
  }

  size_t maxWrite = static_cast<size_t>(-1);
  std::vector<uint8_t> bytes;
};

void testWritesWholeTextMessage() {
  FakeUart uart;
  const uint8_t data[] = {'l', 's', '\r'};

  TEST_ASSERT_EQUAL_UINT32(sizeof(data),
                           ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, sizeof(data), 0,
                                               data, sizeof(data)));
  TEST_ASSERT_EQUAL_STRING_LEN("ls\r", reinterpret_cast<const char*>(uart.bytes.data()), sizeof(data));
}

void testWritesFragmentedMessageInOrder() {
  FakeUart uart;
  const uint8_t first[] = {'e', 'c'};
  const uint8_t second[] = {'h', 'o', '\r'};

  TEST_ASSERT_EQUAL_UINT32(sizeof(first),
                           ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, 5, 0,
                                               first, sizeof(first)));
  TEST_ASSERT_EQUAL_UINT32(sizeof(second),
                           ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, 5, 2,
                                               second, sizeof(second)));
  TEST_ASSERT_EQUAL_STRING_LEN("echo\r", reinterpret_cast<const char*>(uart.bytes.data()), 5);
}

void testWritesWebSocketContinuationFrames() {
  FakeUart uart;
  const uint8_t firstFrame[] = {'p', 'w'};
  const uint8_t continuationFrame[] = {'d', '\r'};

  TEST_ASSERT_EQUAL_UINT32(sizeof(firstFrame),
                           ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, sizeof(firstFrame), 0,
                                               firstFrame, sizeof(firstFrame)));
  TEST_ASSERT_EQUAL_UINT32(sizeof(continuationFrame),
                           ws_uart::writeChunk(uart, ws_uart::CONTINUATION_OPCODE,
                                               sizeof(continuationFrame), 0,
                                               continuationFrame, sizeof(continuationFrame)));
  TEST_ASSERT_EQUAL_STRING_LEN("pwd\r", reinterpret_cast<const char*>(uart.bytes.data()), 4);
}

void testAcceptsLongBinaryMessages() {
  FakeUart uart;
  std::vector<uint8_t> data(1024, 0xA5);

  TEST_ASSERT_EQUAL_UINT32(data.size(),
                           ws_uart::writeChunk(uart, ws_uart::BINARY_OPCODE, data.size(), 0,
                                               data.data(), data.size()));
  TEST_ASSERT_EQUAL_UINT32(data.size(), uart.bytes.size());
}

void testRejectsUnsupportedAndInvalidChunks() {
  FakeUart uart;
  const uint8_t data[] = {'x'};

  TEST_ASSERT_EQUAL_UINT32(0, ws_uart::writeChunk(uart, 0x8, 1, 0, data, 1));
  TEST_ASSERT_EQUAL_UINT32(0, ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, 1, 1, data, 1));
  TEST_ASSERT_EQUAL_UINT32(0, ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, 1, 2, data, 1));
  TEST_ASSERT_EQUAL_UINT32(0, ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, 1, 0, data, 0));
  TEST_ASSERT_EQUAL_UINT32(0, uart.bytes.size());
}

void testReportsShortUartWrite() {
  FakeUart uart;
  uart.maxWrite = 2;
  const uint8_t data[] = {'a', 'b', 'c'};

  TEST_ASSERT_EQUAL_UINT32(2,
                           ws_uart::writeChunk(uart, ws_uart::TEXT_OPCODE, sizeof(data), 0,
                                               data, sizeof(data)));
}

void testReceiveBufferReadsNewBytesBySequence() {
  uart_rx::Buffer<8> rx;
  uint8_t output[4] = {};
  uint64_t next = 0;
  rx.push('a');
  rx.push('b');

  TEST_ASSERT_EQUAL_UINT32(2, rx.read(0, output, sizeof(output), next));
  TEST_ASSERT_EQUAL_UINT32(2, next);
  TEST_ASSERT_EQUAL_CHAR('a', output[0]);
  TEST_ASSERT_EQUAL_CHAR('b', output[1]);
}

void testReceiveBufferResumesAndLimitsRead() {
  uart_rx::Buffer<8> rx;
  uint8_t output[2] = {};
  uint64_t next = 0;
  rx.push('a');
  rx.push('b');
  rx.push('c');

  TEST_ASSERT_EQUAL_UINT32(2, rx.read(1, output, sizeof(output), next));
  TEST_ASSERT_EQUAL_UINT32(3, next);
  TEST_ASSERT_EQUAL_CHAR('b', output[0]);
  TEST_ASSERT_EQUAL_CHAR('c', output[1]);
}

void testReceiveBufferClampsOverrunToOldestByte() {
  uart_rx::Buffer<4> rx;
  uint8_t output[4] = {};
  uint64_t next = 0;
  for (uint8_t c = 'a'; c <= 'f'; ++c) rx.push(c);

  TEST_ASSERT_EQUAL_UINT32(4, rx.read(0, output, sizeof(output), next));
  TEST_ASSERT_EQUAL_UINT32(6, next);
  TEST_ASSERT_EQUAL_CHAR('c', output[0]);
  TEST_ASSERT_EQUAL_CHAR('f', output[3]);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(testWritesWholeTextMessage);
  RUN_TEST(testWritesFragmentedMessageInOrder);
  RUN_TEST(testWritesWebSocketContinuationFrames);
  RUN_TEST(testAcceptsLongBinaryMessages);
  RUN_TEST(testRejectsUnsupportedAndInvalidChunks);
  RUN_TEST(testReportsShortUartWrite);
  RUN_TEST(testReceiveBufferReadsNewBytesBySequence);
  RUN_TEST(testReceiveBufferResumesAndLimitsRead);
  RUN_TEST(testReceiveBufferClampsOverrunToOldestByte);
  return UNITY_END();
}
