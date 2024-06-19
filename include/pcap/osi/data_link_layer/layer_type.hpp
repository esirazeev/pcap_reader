#ifndef PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_LAYER_TYPE_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_LAYER_TYPE_HPP

#include <cstdint>

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
enum class LayerType : uint8_t
{
	ethernet = 0x01
};
} // namespace data_link_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_LAYER_TYPE_HPP
