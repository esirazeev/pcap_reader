#ifndef PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HPP

#include <optional>
#include <span>

#include "header.hpp"
#include "pcap/osi/layer.hpp"

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
class Ethernet final : public Layer<Ethernet, EthernetHeader>
{
public:
	int32_t nextLayerType() const noexcept;
	static void bsawp(EthernetHeader& header) noexcept;
};
} // namespace data_link_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HPP
