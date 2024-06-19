#include "pcap/osi/data_link_layer/ethernet/ethernet.hpp"
#include "pcap/utils/byte_swap.hpp"

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
int32_t Ethernet::nextLayerType() const noexcept
{
	return header_.type;
}

void Ethernet::bsawp(EthernetHeader& header) noexcept
{
	if constexpr (std::endian::native != std::endian::little)
	{
		// TODO
		// swap destination
		// swap source
		header.type = bswap16(header.type);
	}
}
} // namespace data_link_layer
} // namespace osi
} // namespace pcap
