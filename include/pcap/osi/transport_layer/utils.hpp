#ifndef PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UTILS_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UTILS_HPP

#include <optional>
#include <variant>

#include "udp/udp.hpp"

namespace pcap
{
namespace osi
{
namespace transport_layer
{
using Layer_t = std::variant<Udp>;

std::optional<Layer_t> deserialize(uint32_t layerType, std::span<const std::byte> data) noexcept;
} // namespace transport_layer
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_TRANSPORT_LAYER_UTILS_HPP
