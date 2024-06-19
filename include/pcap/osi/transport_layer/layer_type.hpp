#ifndef PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_LAYER_TYPE_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_LAYER_TYPE_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace transport_layer
{
enum class LayerType : uint8_t
{
	udp = 0x11
};
} // namespace transport_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_LAYER_TYPE_HPP
