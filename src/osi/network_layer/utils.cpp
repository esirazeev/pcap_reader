#include "pcap/osi/network_layer/utils.hpp"
#include "pcap/osi/network_layer/layer_type.hpp"

namespace pcap
{
namespace osi
{
namespace network_layer
{
std::optional<Layer_t> deserialize(uint32_t layerType, std::span<const std::byte> data) noexcept
{
	switch (static_cast<LayerType>(layerType))
	{
	case LayerType::ip_v4:
		return IPv4::deserialize(data).and_then([](const auto& ip) { return std::optional<Layer_t>{static_cast<const IPv4&>(ip)}; });
	default:
		return std::nullopt;
	}
}
} // namespace network_layer
} // namespace osi
} // namespace pcap
