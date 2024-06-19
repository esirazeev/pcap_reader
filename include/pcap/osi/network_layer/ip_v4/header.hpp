#ifndef PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HEADER_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HEADER_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace network_layer
{
#pragma pack(push, 1)
struct IPv4Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t headerLength : 4;
	uint8_t version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 4;
	uint8_t headerLength : 4;
#endif
	uint8_t serviceType;
	uint16_t totalLength;
	uint16_t identification;
	uint16_t flagsOffset;
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t sourceAddress;
	uint32_t destinationAddress;
};
#pragma pack(pop)
} // namespace network_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_IP_V4_HEADER_HPP
