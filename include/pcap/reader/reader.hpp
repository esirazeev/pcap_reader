#ifndef PCAP_READER_INCLUDE_PCAP_READER_HPP
#define PCAP_READER_INCLUDE_PCAP_READER_HPP

#include <expected>
#include <fstream>
#include <optional>
#include <span>
#include <string>

#include "file_context.hpp"
#include "pcap/raw_packet/raw_packet.hpp"

namespace pcap
{
class RawPacket;
struct PacketHeader;

class Reader final
{
public:
	explicit Reader(const std::string& fileName);
	Reader(const Reader&) = delete;
	Reader(Reader&&) noexcept;
	Reader& operator=(const Reader&) = delete;
	Reader& operator=(Reader&&) noexcept;
	~Reader() = default;

	/**
	 * @brief Reads the next packet from a file.
	 * 
	 * @return `True`, if not reached the end of the file, otherwise - false
	 */
	[[nodiscard]] bool readNextPacket(RawPacket& packet);

	/**
	 * @brief Returns the file size.
	 * 
	 * @return File size
	 */
	[[nodiscard]] uint64_t fileSize() const noexcept;

	/**
	 * @brief Returns the number of bytes read.
	 * 
	 * @return Number of bytes read
	 */
	[[nodiscard]] uint64_t readBytes() const noexcept;

	/**
	 * @brief Returns the number of packets read.
	 * 
	 * @return Number of packets read 
	 */
	[[nodiscard]] uint64_t readPackets() const noexcept;

private:
	bool readFileHeader();
	std::optional<PacketHeader> readPacketHeader();

	static uint64_t packetTimestampNs(const PacketHeader& header, TimestampType timestamp) noexcept;
	static bool validateFileHeader(std::span<const uint8_t> data) noexcept;
	static std::endian fileEndian(uint8_t byte) noexcept;
	static TimestampType timestampType(uint8_t byte) noexcept;

	std::ifstream file_;
	FileContext fileContext_;
	uint64_t readBytes_;
	uint64_t readPackets_;
};
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_READER_HPP
