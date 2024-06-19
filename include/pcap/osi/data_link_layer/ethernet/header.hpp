#ifndef PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HEADER_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HEADER_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
#pragma pack(push, 1)
struct EthernetHeader
{
	uint8_t destination[6]{};
	uint8_t source[6]{};
	uint16_t type{};
};
#pragma pack(pop)
} // namespace data_link_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_ETHERNET_HEADER_HPP
