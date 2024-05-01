#ifndef PCAP_READER_INCLUDE_PCAP_READER_FILE_HEADER_HPP
#define PCAP_READER_INCLUDE_PCAP_READER_FILE_HEADER_HPP

#include <cstdint>

namespace pcap
{
#pragma pack(push, 1)
struct FileHeader
{
	uint32_t magicNumber;
	uint16_t versionMajor;
	uint16_t versionMinor;
	uint32_t timeZone;
	uint32_t timestampAccuracy;
	uint32_t snapLength;
	uint32_t linkLayerType;
};
#pragma pack(pop)
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_READER_FILE_HEADER_HPP
