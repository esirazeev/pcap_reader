#include <utility>

#include "pcap/reader/file_context.hpp"

namespace pcap
{
FileContext::FileContext() noexcept : timestamp{TimestampType::undefined}, endian{std::endian::native}, maxPacketSize{}, linkLayer{}, size{} {}

FileContext::FileContext(FileContext&& obj) noexcept
	: timestamp{TimestampType::undefined}, endian{std::endian::native}, maxPacketSize{}, linkLayer{}, size{}
{
	std::swap(timestamp, obj.timestamp);
	std::swap(endian, obj.endian);
	std::swap(maxPacketSize, obj.maxPacketSize);
	std::swap(linkLayer, obj.linkLayer);
	std::swap(size, obj.size);
}

FileContext& FileContext::operator=(FileContext&& obj) noexcept
{
	if (this != &obj)
	{
		timestamp = TimestampType::undefined;
		endian = std::endian::native;
		maxPacketSize = {};
		linkLayer = {};
		size = {};

		std::swap(timestamp, obj.timestamp);
		std::swap(endian, obj.endian);
		std::swap(maxPacketSize, obj.maxPacketSize);
		std::swap(linkLayer, obj.linkLayer);
		std::swap(size, obj.size);
	}

	return *this;
}
} // namespace pcap
