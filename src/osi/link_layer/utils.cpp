#include "pcap/osi/data_link_layer/utils.hpp"
#include "pcap/osi/data_link_layer/layer_type.hpp"

namespace pcap
{
namespace osi
{
namespace data_link_layer
{
std::optional<Layer_t> deserialize(uint32_t layerType, std::span<const std::byte> data) noexcept
{
	switch (static_cast<LayerType>(layerType))
	{
	case LayerType::ethernet:
		return Ethernet::deserialize(data).and_then(
			[](const auto& eth) { return std::optional<Layer_t>{static_cast<const Ethernet&>(eth)}; });
	default:
		return std::nullopt;
	}
}
} // namespace data_link_layer
} // namespace osi
} // namespace pcap
