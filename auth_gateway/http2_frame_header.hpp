#ifndef NEOSYSTEM_HTTP2_HTTP2_FRAME_HEADER_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_FRAME_HEADER_HPP_

#include <arpa/inet.h>


namespace neosystem {
namespace http2 {

constexpr const uint32_t HTTP2_STREAM_HEADER_SIZE = 9;

enum class http2_frame_type : uint8_t {
	data = 0x0,
	headers = 0x1,
	priority = 0x2,
	rst_stream = 0x3,
	settings = 0x4,
	push_promise = 0x5,
	ping = 0x6,
	goaway = 0x7,
	window_update = 0x8,
	continuation = 0x9,
};

enum class http2_frame_flags : uint8_t {
	end_stream = 0x1,
	end_headers = 0x4,
	padded = 0x8,
	priority = 0x20,
	ack = 0x1,
};

class http2_frame_header {
private:
	uint32_t length_;
	uint8_t type_;
	uint8_t flags_;
	uint32_t stream_id_;

public:
	http2_frame_header(void) {
	}

	http2_frame_header(uint32_t length, uint8_t type, uint8_t flags, uint32_t stream_id)
		: length_(length), type_(type), flags_(flags), stream_id_(stream_id) {
	}

	void init(void) {
    	length_ = 0;
		type_ = 0;
		flags_ = 0;
		stream_id_ = 0;
		return;
	}

	void write_to_stream(std::ostream& stream) {
		uint8_t u = (length_ >> 16) & 0xff;
		stream.write((const char *) &u, 1);
		u = (length_ >> 8) & 0xff;
		stream.write((const char *) &u, 1);
		u = length_ & 0xff;
		stream.write((const char *) &u, 1);

		stream.write((const char *) &type_, 1);

		stream.write((const char *) &flags_, 1);

		uint32_t u32 = htonl(stream_id_);
		stream.write((const char *) &u32, 4);
		return;
	}

	bool read_from_buffer(const uint8_t *buffer, size_t buflen) {
		init();
		if (buflen < HTTP2_STREAM_HEADER_SIZE) return false;

		length_ = (buffer[0] << 16) + (buffer[1] << 8) + buffer[2];
		type_ = buffer[3];
		flags_ = buffer[4];
		stream_id_ = ntohl(*reinterpret_cast<const uint32_t*>(&buffer[5])) & 0x7FFFFFFF;
		return true;
	}

	uint32_t get_length(void) const { return length_; }
	uint8_t get_type(void) const { return type_; }
	uint8_t get_flags(void) const { return flags_; }
	uint32_t get_stream_id(void) const { return stream_id_; }
};

void get_goaway_frame(boost::asio::streambuf& buf, uint32_t stream_id, uint32_t error_code) {
	http2_frame_header h((uint32_t) sizeof(uint32_t) * 2, (uint8_t) http2_frame_type::goaway, 0x0, 0);

	std::ostream os(&buf);
	h.write_to_stream(os);

	uint32_t tmp = htonl(stream_id);
	os.write((const char *) &tmp, sizeof(uint32_t));
	tmp = htonl(error_code);
	os.write((const char *) &tmp, sizeof(uint32_t));
	return;
}

void get_rst_stream_frame(boost::asio::streambuf& buf, uint32_t stream_id, uint32_t error_code) {
	http2_frame_header h((uint32_t) sizeof(uint32_t), (uint8_t) http2_frame_type::rst_stream, 0x0, stream_id);

	std::ostream os(&buf);
	h.write_to_stream(os);

	uint32_t tmp = htonl(error_code);
	os.write((const char *) &tmp, sizeof(uint32_t));
	return;
}

}
}

#endif
