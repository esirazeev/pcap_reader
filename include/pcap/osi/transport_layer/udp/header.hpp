#ifndef PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HEADER_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HEADER_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace transport_layer
{
#pragma pack(push, 1)
struct UdpHeader
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;
};
#pragma pack(pop)
} // namespace transport_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UDP_HEADER_HPP
