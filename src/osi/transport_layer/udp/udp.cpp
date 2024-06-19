#include "pcap/osi/transport_layer/udp/udp.hpp"
#include "pcap/utils/byte_swap.hpp"

namespace pcap
{
namespace osi
{
namespace transport_layer
{
int32_t Udp::nextLayerType() const noexcept
{
	return -1;
}

void Udp::bsawp(UdpHeader& header) noexcept
{
	if constexpr (std::endian::native != std::endian::little)
	{
		header.sourcePort = bswap16(header.sourcePort);
		header.destinationPort = bswap16(header.destinationPort);
		header.length = bswap16(header.length);
		header.checksum = bswap16(header.checksum);
	}
}
} // namespace transport_layer
} // namespace osi
} // namespace pcap
