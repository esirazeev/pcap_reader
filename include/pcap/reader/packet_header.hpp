#ifndef PCAP_READER_INCLUDE_PCAP_READER_PACKET_HEADER_HPP
#define PCAP_READER_INCLUDE_PCAP_READER_PACKET_HEADER_HPP

#include <cstdint>

namespace pcap
{
#pragma pack(push, 1)
struct PacketHeader
{
	uint32_t timestampSec;
	uint32_t timestampMicrosec;
	uint32_t currentLength;
	uint32_t orignalLength;
};
#pragma pack(pop)
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_READER_PACKET_HEADER_HPP
