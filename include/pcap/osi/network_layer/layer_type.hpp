#ifndef PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_LAYER_TYPE_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_LAYER_TYPE_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace network_layer
{
enum class LayerType : uint8_t
{
	ip_v4 = 0x08
};
} // namespace network_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_NETWORK_LAYER_LAYER_TYPE_HPP
