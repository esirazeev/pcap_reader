#ifndef PCAP_READER_INCLUDE_PCAP_READER_FILE_CONTEXT_HPP
#define PCAP_READER_INCLUDE_PCAP_READER_FILE_CONTEXT_HPP

#include <bit>
#include <cstdint>

namespace pcap
{
enum class TimestampType : uint8_t
{
	undefined,
	nanoseconds,
	microseconds
};

struct FileContext
{
	FileContext() noexcept;
	FileContext(FileContext&&) noexcept;
	FileContext(const FileContext&) = default;
	FileContext& operator=(FileContext&&) noexcept;
	FileContext& operator=(const FileContext&) = default;

	TimestampType timestamp;
	std::endian endian;
	uint32_t maxPacketSize;
	uint32_t linkLayer;
	uint64_t size;
};
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_READER_TYPES_HPP
