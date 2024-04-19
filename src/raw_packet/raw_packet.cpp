#include "pcap/raw_packet/raw_packet.hpp"

namespace pcap
{
RawPacket::RawPacket() : linkLayer_{}, timestamp_{} {}

RawPacket::RawPacket(RawPacket&& obj) : linkLayer_{}, timestamp_{}, buffer_{std::move(obj.buffer_)}
{
	std::swap(linkLayer_, obj.linkLayer_);
	std::swap(timestamp_, obj.timestamp_);
}

RawPacket& RawPacket::operator=(RawPacket&& obj)
{
	if (this != &obj)
	{
		timestamp_ = {};
		linkLayer_ = {};

		std::swap(linkLayer_, obj.linkLayer_);
		std::swap(timestamp_, obj.timestamp_);

		buffer_ = std::move(obj.buffer_);
	}

	return *this;
}

void RawPacket::overwrite(uint64_t timestamp, uint32_t linkLayer, std::ifstream& file, uint32_t size)
{
	timestamp_ = timestamp;
	linkLayer_ = linkLayer;
	buffer_.overwrite(file, size);
}

uint64_t RawPacket::timestamp() const noexcept
{
	return timestamp_;
}

uint32_t RawPacket::linkLayer() const noexcept
{
	return linkLayer_;
}

std::span<const std::byte> RawPacket::data() const noexcept
{
	return buffer_.data();
}
} // namespace pcap
