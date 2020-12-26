#include <cstring>

#include "http2_util.hpp"


namespace neosystem {
namespace http2 {

uint64_t get_int(int prefix, const uint8_t *p, std::size_t length, std::size_t& consume_length) {
	consume_length = 0;
	uint64_t result = 0;

	if (prefix < 0 || prefix > 8) return result;
	if (length <= 0) return result;

	uint8_t mask = (uint8_t) (0b11111111 >> (8 - prefix));
	uint8_t f = *p & mask;
	result = f;
	if (f < mask) {
		++consume_length;
		return result;
	}
	++consume_length;
	++p;
	for (std::size_t i = 1, m = 0; i < length; ++i) {
		uint8_t b = *p;
		if (m == 0) {
			result += (b & 127);
		} else {
			result += (b & 127) * (2 << (m - 1));
		}
		++consume_length;
		++p;
		m += 7;
		if ((b & 128) != 128) break;
	}
	return result;
}

void write_encode_int(std::ostream& stream, uint32_t value, int n) {
	uint8_t max = (uint8_t) ((2 << (n - 1)) - 1);
	if (value < max) {
		uint8_t u = (uint8_t) value;
		stream.write((const char *) &u, 1);
		return;
	}

	uint8_t u = (uint8_t) max;
	stream.write((const char *) &u, 1);

	uint32_t i = value - max;
	for (; i >= 128; ) {
		u = (uint8_t) (i % 128 + 128) | 0b10000000;
		stream.write((const char *) &u, 1);
		i = i / 128;
	}
	write_encode_int(stream, i, 8);
	return;
}

void write_http2_header(std::ostream& stream, const char *name, const char *value) {
	uint8_t u = 0;

	stream.write((const char *) &u, 1);

	write_encode_int(stream, (uint32_t) strlen(name), 7);
	stream.write(name, strlen(name));

	write_encode_int(stream, (uint32_t) strlen(value), 7);
	stream.write(value, strlen(value));
	return;
}

void write_http2_header2(std::ostream& stream, const std::string& name, const std::string& value) {
	uint8_t u = 0;

	stream.write((const char *) &u, 1);

	write_encode_int(stream, (uint32_t) name.size(), 7);
	for (char c: name) {
		char t = (char) std::tolower(c);
		stream.write(&t, 1);
	}

	write_encode_int(stream, (uint32_t) value.size(), 7);
	stream.write(value.c_str(), value.size());
	return;
}

}
}
