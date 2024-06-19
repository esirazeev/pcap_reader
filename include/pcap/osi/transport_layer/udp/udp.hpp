#ifndef PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HPP

#include <optional>
#include <span>

#include "header.hpp"
#include "pcap/osi/layer.hpp"

namespace pcap
{
namespace osi
{
namespace transport_layer
{
class Udp final : public Layer<Udp, UdpHeader>
{
public:
	int32_t nextLayerType() const noexcept;
	static void bsawp(UdpHeader& header) noexcept;
};
} // namespace transport_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HPP
