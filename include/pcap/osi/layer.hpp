#ifndef PCAP_READER_INCLUDE_PCAP_OSI_LAYER_HPP
#define PCAP_READER_INCLUDE_PCAP_OSI_LAYER_HPP

#include <cstring>
#include <optional>
#include <span>

namespace pcap
{
namespace osi
{
template <typename OSILayer, typename OSILayerHeader>
class Layer
{
public:
	static std::optional<Layer<OSILayer, OSILayerHeader>> deserialize(std::span<const std::byte> data) noexcept
	{
		OSILayerHeader header;

		if (data.size() < sizeof(OSILayerHeader)) [[unlikely]]
		{
			return std::nullopt;
		}

		std::memcpy(&header, data.data(), sizeof(OSILayerHeader));
		OSILayer::bsawp(header);

		return Layer<OSILayer, OSILayerHeader>{header, data};
	}

	const OSILayerHeader& header() const noexcept
	{
		return header_;
	}

	int32_t nextLayerType() const noexcept
	{
		return static_cast<const OSILayer&>(*this).nextLayerType();
	}

	std::span<const std::byte> payload() const noexcept
	{
		return payload_;
	}

protected:
	Layer(const OSILayerHeader& header, std::span<const std::byte> data) noexcept : header_{header}
	{
		payload_ = data.subspan(sizeof(OSILayerHeader), data.size() - sizeof(OSILayerHeader));
	}

	OSILayerHeader header_;
	std::span<const std::byte> payload_;
};
} // namespace osi
} // namespace pcap

#endif // PCAP_READER_INCLUDE_PCAP_OSI_LAYER_HPP
