#include <chrono>
#include <cstring>
#include <format>
#include <stdexcept>

#include "pcap/reader/file_header.hpp"
#include "pcap/reader/packet_header.hpp"
#include "pcap/raw_packet/raw_packet.hpp"
#include "pcap/utils/byte_swap.hpp"
#include "pcap/reader/reader.hpp"

static constexpr uint8_t magicNumberLittleEndianMicroseconds[]{0xd4, 0xc3, 0xb2, 0xa1};
static constexpr uint8_t magicNumberLittleEndianNanoseconds[]{0x4d, 0x3c, 0xb2, 0xa1};
static constexpr uint8_t magicNumberBigEndianMicroseconds[]{0xa1, 0xb2, 0xc3, 0xd4};
static constexpr uint8_t magicNumberBigEndianNanoseconds[]{0xa1, 0xb2, 0x3c, 0x4d};

namespace pcap
{
Reader::Reader(const std::string& fileName) : file_{fileName, std::ios_base::binary}, readBytes_{}, readPackets_{}
{
	if (not file_.is_open()) [[unlikely]]
	{
		throw std::runtime_error{std::format("pcap::Reader [error]: cannot open '{}': file does not exist", fileName)};
	}

	file_.seekg(std::ios::beg, std::ios::end);
	fileContext_.size = file_.tellg();
	file_.seekg(std::ios::beg, std::ios::beg);

	if (not readFileHeader()) [[unlikely]]
	{
		file_.close();
		throw std::runtime_error{"pcap::Reader [error]: file header validation faile: this is not a PCAP file"};
	}
}

Reader::Reader(Reader&& reader) noexcept : file_{std::move(reader.file_)}, fileContext_{std::move(reader.fileContext_)}, readBytes_{}, readPackets_{}
{
	std::swap(readBytes_, reader.readBytes_);
	std::swap(readPackets_, reader.readPackets_);
}

Reader& Reader::operator=(Reader&& reader) noexcept
{
	if (this != &reader)
	{
		file_ = std::move(reader.file_);
		fileContext_ = std::move(reader.fileContext_);

		readBytes_ = {};
		readPackets_ = {};

		std::swap(readBytes_, reader.readBytes_);
		std::swap(readPackets_, reader.readPackets_);
	}

	return *this;
}

bool Reader::readNextPacket(RawPacket& packet)
{
	if (readBytes_ == fileContext_.size) [[unlikely]]
	{
		return false;
	}

	const auto packetHeader{readPacketHeader()};

	if (not packetHeader) [[unlikely]]
	{
		file_.close();
		throw std::runtime_error("pcap::Reader [exception]: cannot read PCAP packet header: file corrupted");
	}

	packet.overwrite(packetTimestampNs(*packetHeader, fileContext_.timestamp), fileContext_.linkLayer, file_, packetHeader->currentLength);
	readBytes_ += packetHeader->currentLength;
	++readPackets_;

	return true;
}

uint64_t Reader::fileSize() const noexcept
{
	return fileContext_.size;
}

uint64_t Reader::readBytes() const noexcept
{
	return readBytes_;
}

uint64_t Reader::readPackets() const noexcept
{
	return readPackets_;
}

bool Reader::readFileHeader()
{
	uint8_t buffer[sizeof(FileHeader)]{};
	readBytes_ += file_.read(reinterpret_cast<char*>(buffer), sizeof(FileHeader)).gcount();

	if (not validateFileHeader({buffer, readBytes_})) [[unlikely]]
	{
		return false;
	}

	fileContext_.endian = fileEndian(buffer[0]);
	fileContext_.timestamp = timestampType(buffer[0]);

	FileHeader header{};
	std::memcpy(&header, buffer, sizeof(FileHeader));

	if (fileContext_.endian != std::endian::native)
	{
		header.magicNumber = bswap32(header.magicNumber);
		header.versionMajor = bswap16(header.versionMajor);
		header.versionMinor = bswap16(header.versionMinor);
		header.snapLength = bswap32(header.snapLength);
		header.linkLayerType = bswap32(header.linkLayerType);
	}

	fileContext_.maxPacketSize = header.snapLength;
	fileContext_.linkLayer = header.linkLayerType;

	return true;
}

std::optional<PacketHeader> Reader::readPacketHeader()
{
	PacketHeader header{};
	const auto curReadBytes{file_.read(reinterpret_cast<char*>(&header), sizeof(PacketHeader)).gcount()};

	if (curReadBytes != sizeof(PacketHeader)) [[unlikely]]
	{
		return std::nullopt;
	}

	readBytes_ += curReadBytes;

	if (fileContext_.endian != std::endian::native)
	{
		header.timestampSec = bswap32(header.timestampSec);
		header.timestampMicrosec = bswap32(header.timestampMicrosec);
		header.currentLength = bswap32(header.currentLength);
		header.orignalLength = bswap32(header.orignalLength);
	}

	return header;
}

uint64_t Reader::packetTimestampNs(const PacketHeader& header, TimestampType timestamp) noexcept
{
	return (std::chrono::seconds(header.timestampSec) + (timestamp == TimestampType::nanoseconds ?
								     std::chrono::nanoseconds(header.timestampMicrosec) :
								     std::chrono::microseconds(header.timestampMicrosec)))
		.count();
}

bool Reader::validateFileHeader(std::span<const uint8_t> data) noexcept
{
	if ((sizeof(FileHeader) == data.size()) and
	    (not std::memcmp(data.data(), magicNumberBigEndianMicroseconds, std::size(magicNumberBigEndianMicroseconds)) or
	     not std::memcmp(data.data(), magicNumberBigEndianNanoseconds, std::size(magicNumberBigEndianNanoseconds)) or
	     not std::memcmp(data.data(), magicNumberLittleEndianMicroseconds, std::size(magicNumberLittleEndianMicroseconds)) or
	     not std::memcmp(data.data(), magicNumberLittleEndianNanoseconds, std::size(magicNumberLittleEndianNanoseconds))))
	{
		return true;
	}

	return false;
}

std::endian Reader::fileEndian(uint8_t byte) noexcept
{
	return (byte == magicNumberLittleEndianMicroseconds[0] or byte == magicNumberLittleEndianNanoseconds[0]) ? std::endian::little :
														   std::endian::big;
}

TimestampType Reader::timestampType(uint8_t byte) noexcept
{
	return (byte == magicNumberLittleEndianMicroseconds[0] or byte == magicNumberBigEndianMicroseconds[0]) ? TimestampType::microseconds :
														 TimestampType::nanoseconds;
}
} // namespace pcap
