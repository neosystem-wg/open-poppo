#ifndef NEOSYSTEM_HTTP_HTTP_COMMON_HPP_
#define NEOSYSTEM_HTTP_HTTP_COMMON_HPP_

#include <string>
#include <queue>
#include <memory>
#include <iostream>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <boost/container/pmr/polymorphic_allocator.hpp>
#include <boost/container/pmr/synchronized_pool_resource.hpp>
#include <boost/aligned_storage.hpp>


namespace neosystem {
namespace http {

constexpr const char *ERROR_400_HEADER = 
	"HTTP/1.0 400 Bad Request\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

constexpr const char *ERROR_503_HEADER = 
	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

constexpr const char *ERROR_404_HEADER = 
	"HTTP/1.0 404 Not Found\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

constexpr const char *ERROR_401_HEADER = 
	"HTTP/1.1 401 Unauthorized\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

constexpr const char *ERROR_403_HEADER = 
	"HTTP/1.1 403 Forbidden\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";


enum class http_method_type {
	GET,
	HEAD,
	POST,
	PUT,
	DELETE,
	OPTIONS,
	TRACE,
	CONNECT,
	PATCH,
	UNKNOWN
};

struct header {
	std::string name;
	std::string value;
};

using headers_type = std::vector<header>;


class url_info {
private:
	bool is_ssl_;

	std::string host_;

	std::string port_;

	std::string path_;

	std::string param_;

	bool init(const std::string&, int);

public:
	bool init(const std::string&);

	bool is_ssl(void) const { return is_ssl_; }
	const std::string& get_host(void) const { return host_; }
	const std::string& get_port(void) const { return port_; }
	const std::string& get_path(void) const { return path_; }
	const std::string& get_param(void) const { return param_; }
};


class recv_info {
public:
	bool complete_flag;

	bool is_chunked;

	bool has_content_length;
	std::size_t content_length;
	std::size_t complete_length;
	std::size_t chunk_offset;

	recv_info(void) : complete_flag(false), is_chunked(false), has_content_length(false), content_length(0), complete_length(0), chunk_offset(0) {
	}

	void init(void) {
		complete_flag = false;
		is_chunked = false;
		has_content_length = false;
		content_length = 0;
		complete_length = 0;
		chunk_offset = 0;
		return;
	}
};


class streambuf_cache : private boost::noncopyable {
public:
	using buf_type = std::unique_ptr<boost::asio::streambuf>;

private:
	std::size_t max_size_;
	std::vector<std::unique_ptr<boost::asio::streambuf>> cache_;

public:
	streambuf_cache(std::size_t max_size) : max_size_(max_size) {
		cache_.reserve(max_size);
		for (std::size_t i = 0; i < max_size / 2; ++i) {
			cache_.push_back(std::make_unique<boost::asio::streambuf>());
		}
	}

	std::unique_ptr<boost::asio::streambuf> get(void) {
		if (cache_.empty()) {
			return std::make_unique<boost::asio::streambuf>();
		}
		auto buf = std::move(*cache_.rbegin());
		cache_.pop_back();
		return buf;
	}

	std::unique_ptr<boost::asio::streambuf> move_buffer(boost::asio::streambuf& buf, std::size_t move_size) {
		auto tmp_stream = get();
		tmp_stream->prepare(move_size);
		std::ostream os(&(*tmp_stream));
		os.write(boost::asio::buffer_cast<const char *>(buf.data()), move_size);
		buf.consume(move_size);
		return tmp_stream;
	}

	void release(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (buf == nullptr) return;
		if (cache_.size() >= max_size_) return;
		if (buf->size() > 0) {
			//std::cout << "buf->size() > 0" << std::endl;
			buf->consume(buf->size());
		}
		cache_.push_back(std::move(buf));
		return;
	}

	std::unique_ptr<boost::asio::streambuf> get(const char *str) {
		std::size_t size = strlen(str);
		auto tmp_stream = get();
		tmp_stream->prepare(size);
		std::ostream os(&(*tmp_stream));
		os.write(str, size);
		return tmp_stream;
	}

	std::unique_ptr<boost::asio::streambuf> get_400(void) {
		return get(ERROR_400_HEADER);
	}

	std::unique_ptr<boost::asio::streambuf> get_503(void) {
		return get(ERROR_503_HEADER);
	}

	std::unique_ptr<boost::asio::streambuf> get_404(void) {
		return get(ERROR_404_HEADER);
	}

	std::unique_ptr<boost::asio::streambuf> get_401(void) {
		return get(ERROR_401_HEADER);
	}

	std::unique_ptr<boost::asio::streambuf> get_403(void) {
		return get(ERROR_403_HEADER);
	}
};


class write_queue {
private:
	using streambuf_type = std::unique_ptr<boost::asio::streambuf>;
	using queue_type = std::queue<streambuf_type>;

	bool waiting_flag_;
	queue_type q_;
	std::vector<streambuf_type> writing_;
	std::vector<boost::asio::const_buffer> buffers_;

public:
	write_queue(void) : waiting_flag_(false) {
	}

	queue_type::size_type get_count(void) const { 
		return q_.size();
	}

	bool push(std::unique_ptr<boost::asio::streambuf>& buf) {
		q_.push(std::move(buf));
		if (waiting_flag_) {
			return false;
		}
		waiting_flag_ = true;
		return true;
	}

	bool is_empty(void) const {
		return q_.empty();
	}

	std::vector<boost::asio::const_buffer>& get_buffers(void) {
		writing_.reserve(q_.size());

		while (!q_.empty()) {
			auto *buf = &(*(q_.front()));
			const char *p = boost::asio::buffer_cast<const char *>(buf->data());
			buffers_.push_back(boost::asio::buffer(p, buf->size()));

			auto tmp = std::move(q_.front());
			q_.pop();
			writing_.push_back(std::move(tmp));
		}
		waiting_flag_ = true;
		return buffers_;
	}

	void clear_writing_buffer(streambuf_cache& cache) {
		waiting_flag_ = false;
		for (auto& e : writing_) {
			auto tmp = std::move(e);
			cache.release(tmp);
		}
		writing_.clear();
		buffers_.clear();
		return;
	}

	boost::asio::streambuf *front(void) {
		if (q_.empty()) return nullptr;

		auto *buf = &(*(q_.front()));
		waiting_flag_ = true;
		return buf;
	}

	boost::asio::streambuf *pop(streambuf_cache& cache) {
		waiting_flag_ = false;
		// 先頭にあるのは今書き込んだバッファ
		auto tmp = std::move(q_.front());
		cache.release(tmp);
		q_.pop();
		if (q_.empty()) return nullptr;

		// 次
		auto *buf = &(*(q_.front()));
		waiting_flag_ = true;
		return buf;
	}
};


class socket_wrapper {
private:
	streambuf_cache& cache_;
	boost::asio::ip::tcp::socket& socket_;

	bool waiting_flag_;
	std::vector<std::unique_ptr<boost::asio::streambuf>> q_;
	std::vector<std::unique_ptr<boost::asio::streambuf>> writing_q_;
	std::vector<boost::asio::const_buffer> write_vector_;

	void move_buffers(void) {
		writing_q_ = std::move(q_);
		for (const auto& m: writing_q_) {
			write_vector_.push_back(boost::asio::buffer(m->data(), m->size()));
		}
		return;
	}

	template<typename T>
	void async_write_impl(T ptr, std::unique_ptr<boost::asio::streambuf> buf) {
		waiting_flag_ = true;
		move_buffers();
		if (buf != nullptr) {
			write_vector_.push_back(boost::asio::buffer(buf->data(), buf->size()));
			writing_q_.push_back(std::move(buf));
		}

		boost::asio::async_write(
				socket_, write_vector_, [ptr, this](const boost::system::error_code ec, std::size_t) {
			if (ec) {
				std::cout << "Error: " << ec.message() << std::endl;
			}
			write_vector_.clear();
			for (auto& m: writing_q_) {
				cache_.release(m);
			}
			writing_q_.clear();
			waiting_flag_ = false;
			if (q_.empty()) return;

			async_write_impl(ptr, nullptr);
			return;
		});
		return;
	}

public:
	socket_wrapper(streambuf_cache& cache, boost::asio::ip::tcp::socket& s) : cache_(cache), socket_(s), waiting_flag_(false) {
	}

	template<typename T>
	void async_write(T ptr, std::unique_ptr<boost::asio::streambuf> buf) {

		if (waiting_flag_) {
			// 現在書き込み中の場合は保存して終わり
			q_.push_back(std::move(buf));
			return;
		}

		async_write_impl(ptr, std::move(buf));
		return;
	}
};


template<typename T>
void set_send_buffer_size(T& t) {
	boost::asio::socket_base::send_buffer_size option;
	t.get_option(option);

	boost::asio::socket_base::send_buffer_size option2(option.value() * 5);
	t.set_option(option2);
	return;
}

template<typename T>
void set_receive_buffer_size(T& t) {
	boost::asio::socket_base::receive_buffer_size option;
	t.get_option(option);

	boost::asio::socket_base::receive_buffer_size option2(option.value() * 5);
	t.set_option(option2);
	return;
}

template<typename T>
void set_send_buffer_size(T& t, int s) {
	boost::asio::socket_base::send_buffer_size option(s);
	t.set_option(option);
	return;
}

template<typename T>
void set_receive_buffer_size(T& t, int s) {
	boost::asio::socket_base::receive_buffer_size option(s);
	t.set_option(option);
	return;
}

template <typename InputIterator>
std::size_t get_chunk_size(InputIterator begin, InputIterator end, std::size_t& size) {
	std::string tmp;
	bool r_flag = false;

	tmp.reserve(32);
	while (begin != end) {
		if (*begin == '\r') {
			r_flag = true;
			++begin;
			continue;
		} else if (r_flag && *begin == '\n') {
			size = strtol(tmp.c_str(), NULL, 16);
			return tmp.size();
		}
		tmp += *begin;
		++begin;
	}
	size = 0;
	return 0;
}


class handler_memory : private boost::noncopyable {
private:
	// Storage space used for handler-based custom memory allocation.
	boost::aligned_storage<1024> storage_;

	// Whether the handler-based custom allocation storage has been used.
	bool in_use_;

public:
	handler_memory(void) : in_use_(false) {
	}

	void *allocate(std::size_t size) {
		if (!in_use_ && size < storage_.size) {
			in_use_ = true;
			return storage_.address();
		} else {
			return ::operator new(size);
		}
	}

	void deallocate(void* pointer) {
		if (pointer == storage_.address()) {
			in_use_ = false;
		} else {
			::operator delete(pointer);
		}
	}
};

				
template <typename T>
class handler_allocator {
private:

public:
	typedef T value_type;
	handler_memory& memory_;

	explicit handler_allocator(handler_memory& mem) : memory_(mem) {
	}

	template <typename U>
	handler_allocator(const handler_allocator<U>& other) : memory_(other.memory_) {
	}

	template <typename U>
	struct rebind {
		typedef handler_allocator<U> other;
	};

	bool operator==(const handler_allocator& other) const {
		return &memory_ == &other.memory_;
	}

	bool operator!=(const handler_allocator& other) const {
		return &memory_ != &other.memory_;
	}

	T* allocate(std::size_t n) const {
		return static_cast<T*>(memory_.allocate(sizeof(T) * n));
	}

	void deallocate(T* p, std::size_t /*n*/) const {
		return memory_.deallocate(p);
	}

	//handler_memory& get_memory(void) { return memory_; }
};


template <typename Handler>
class custom_alloc_handler {
private:
	handler_memory& memory_;
	Handler handler_;

public:
	typedef handler_allocator<Handler> allocator_type;

	custom_alloc_handler(handler_memory& m, Handler h) : memory_(m), handler_(h) {
	}

	allocator_type get_allocator() const {
		return allocator_type(memory_);
	}

	template <typename Arg1>
	void operator()(Arg1 arg1) {
		handler_(arg1);
	}

	template <typename Arg1, typename Arg2>
	void operator()(Arg1 arg1, Arg2 arg2) {
		handler_(arg1, arg2);
	}
};


template <typename Handler>
inline custom_alloc_handler<Handler> make_custom_alloc_handler(handler_memory& m, Handler h) {
	return custom_alloc_handler<Handler>(m, h);
}

bool chunk_check(const std::string&);
void set_tcp_option(boost::asio::ip::tcp::socket&);
void parse_http_post(const std::string&, std::unordered_map<std::string, std::string>&);
bool generate_session_id(std::string&);
void parse_cookie(const std::string&, std::unordered_map<std::string, std::string>&);
void parse_http_url(const std::string&, std::unordered_map<std::string, std::string>&);
void parse_http_post(const std::string::const_iterator, const std::string::const_iterator, std::unordered_map<std::string, std::string>&);
void merge_headers(headers_type&, const headers_type&, const headers_type&);
void remove_get_parameter(const std::string&, std::string&);
void replace_path(const std::string&, const std::string&, const std::string&, std::string&);
const char *to_day_name(const struct tm&);
const char *to_month(const struct tm&);
const char *method_to_str(http_method_type);
http_method_type str_to_method(const std::string&);
void parse_http_post(const std::string&, std::unordered_map<std::string, std::string>&);

template<typename HeaderType>
bool need_csrf_check(const HeaderType& header) {
	switch (header.get_request_method()) {
	case http_method_type::POST:
	case http_method_type::PUT:
	case http_method_type::DELETE:
		return true;
	default:
		break;
	}
	return false;
}

template<typename HeaderType>
bool is_xfp_https(const HeaderType& request_header) {
	std::string h = request_header.find_header("X-Forwarded-Proto");
	if (h == "https") {
		return true;
	}
	return false;
}

}
}

#endif
