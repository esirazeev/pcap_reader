#ifndef PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_UTILS_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_UTILS_HPP

#include <optional>
#include <variant>

#include "ethernet/ethernet.hpp"

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
using Layer_t = std::variant<Ethernet>;

std::optional<Layer_t> deserialize(uint32_t layerType, std::span<const std::byte> data) noexcept;
} // namespace data_link_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_DATA_LINK_LAYER_UTILS_HPP
