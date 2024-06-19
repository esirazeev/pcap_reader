#include "pcap/osi/transport_layer/utils.hpp"
#include "pcap/osi/transport_layer/layer_type.hpp"

namespace pcap
{
namespace osi
{
namespace transport_layer
{
std::optional<Layer_t> deserialize(uint32_t layerType, std::span<const std::byte> data) noexcept
{
	switch (static_cast<LayerType>(layerType))
	{
	case LayerType::udp:
		return Udp::deserialize(data).and_then([](const auto& udp) { return std::optional<Layer_t>{static_cast<const Udp&>(udp)}; });
	default:
		return std::nullopt;
	}
}
} // namespace transport_layer
} // namespace osi
} // namespace pcap
