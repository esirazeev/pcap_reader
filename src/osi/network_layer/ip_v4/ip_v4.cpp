#include "pcap/osi/network_layer/ip_v4/ip_v4.hpp"
#include "pcap/utils/byte_swap.hpp"

namespace pcap
{
namespace osi
{
namespace network_layer
{
int32_t IPv4::nextLayerType() const noexcept
{
	return header_.protocol;
}

void IPv4::bsawp(IPv4Header& header) noexcept
{
	if constexpr (std::endian::native != std::endian::little)
	{
		header.totalLength = bswap16(header.totalLength);
		header.identification = bswap16(header.identification);
		header.flagsOffset = bswap16(header.flagsOffset);
		header.checksum = bswap16(header.checksum);
		header.sourceAddress = bswap32(header.sourceAddress);
		header.destinationAddress = bswap32(header.destinationAddress);
	}
}
} // namespace network_layer
} // namespace osi
} // namespace pcap
