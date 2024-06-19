#ifndef PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HPP

#include <optional>
#include <span>

#include "header.hpp"
#include "pcap/osi/layer.hpp"

namespace pcap
{
namespace osi
{
namespace network_layer
{
class IPv4 final : public Layer<IPv4, IPv4Header>
{
public:
	int32_t nextLayerType() const noexcept;
	static void bsawp(IPv4Header& header) noexcept;
};
} // namespace network_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HPP
