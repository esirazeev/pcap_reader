#ifndef PCAP_READER_INCLUDE_PCAP_RAW_PACKET_HPP
#define PCAP_READER_INCLUDE_PCAP_RAW_PACKET_HPP

#include "byte_buffer/byte_buffer.hpp"

namespace pcap
{
class RawPacket final
{
public:
	RawPacket();
	RawPacket(const RawPacket&) = default;
	RawPacket(RawPacket&&);
	RawPacket& operator=(const RawPacket&) = default;
	RawPacket& operator=(RawPacket&&);
	~RawPacket() = default;

	/**
	 * @brief Overwrites the raw packet.
	 * 
	 * @param timestamp Raw packet timestamp (`nanoseconds`)
	 * @param linkLayer Raw packet link layer type
	 * @param file File object
   * @param size File data size
	 */
	void overwrite(uint64_t timestamp, uint32_t linkLayer, std::ifstream& file, uint32_t size);

	/**
	 * @brief Returns the raw packet timestamp (`nanoseconds`).
	 * 
	 * @return Raw packet timestamp
	 */
	[[nodiscard]] uint64_t timestamp() const noexcept;

	/**
	 * @brief Returns the raw packet link layer type.
	 * 
	 * @return Raw packet link layer type
	 */
	[[nodiscard]] uint32_t linkLayer() const noexcept;

	/**
	 * @brief Returns the raw packet data.
	 * 
	 * @return Raw packet data
	 */
	[[nodiscard]] std::span<const std::byte> data() const noexcept;

private:
	uint32_t linkLayer_;
	uint64_t timestamp_;
	byte_buffer::Buffer buffer_;
};
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_RAW_PACKET_HPP
