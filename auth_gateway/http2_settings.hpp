#ifndef NEOSYSTEM_HTTP2_HTTP2_SETTINGS_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_SETTINGS_HPP_

namespace neosystem {
namespace http2 {

struct http2_settings_param {
	uint16_t identifier;
	uint32_t value;
} __attribute__((__packed__));

constexpr const uint16_t SETTINGS_HEADER_TABLE_SIZE = 0x1;
constexpr const uint16_t SETTINGS_ENABLE_PUSH = 0x2;
constexpr const uint16_t SETTINGS_MAX_CONCURRENT_STREAMS = 0x3;
constexpr const uint16_t SETTINGS_INITIAL_WINDOW_SIZE = 0x4;
constexpr const uint16_t SETTINGS_MAX_FRAME_SIZE = 0x5;
constexpr const uint16_t SETTINGS_MAX_HEADER_LIST_SIZE = 0x6;

class http2_settings {
private:
	uint32_t header_table_size_;

	bool enable_push_;

	uint32_t max_concurrent_streams_;

	uint32_t initial_window_size_;

	uint32_t max_frame_size_;

	uint32_t max_header_list_size_;

public:
	http2_settings(void) :
		header_table_size_(4096),
		enable_push_(true),
		max_concurrent_streams_(1024),
		initial_window_size_(65535),
		max_frame_size_(16384),
		max_header_list_size_(0) {
	}

	uint32_t get_header_table_size(void) const { return header_table_size_; }
	void set_header_table_size(uint32_t header_table_size) { header_table_size_ = header_table_size; }

	bool get_enable_push(void) const { return enable_push_; }
	void set_enable_push(bool enable_push) { enable_push_ = enable_push; }

	uint32_t get_max_concurrent_streams(void) const { return max_concurrent_streams_; }
	void set_max_concurrent_streams(uint32_t max_concurrent_streams) { max_concurrent_streams_ = max_concurrent_streams; }

	uint32_t get_initial_window_size(void) const { return initial_window_size_; }
	void set_initial_window_size(uint32_t initial_window_size) { initial_window_size_ = initial_window_size; }

	uint32_t get_max_frame_size(void) const { return max_frame_size_; }
	void set_max_frame_size(uint32_t max_frame_size) { max_frame_size_ = max_frame_size; }

	uint32_t get_max_header_list_size(void) const { return max_header_list_size_; }
	void set_max_header_list_size(uint32_t max_header_list_size) { max_header_list_size_ = max_header_list_size; }
};

}
}

#endif
