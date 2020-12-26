#include <ostream>

#include "json_writer.hpp"


namespace poppo {
namespace json {

static std::string create_escapes(const std::string&);


class value_writer : public boost::static_visitor<void> {
private:
	std::ostream& stream_;

public:
	value_writer(std::ostream& s) : stream_(s) {
	}

	~value_writer(void) {
	}

	void operator()(int i) {
		stream_ << i;
		return;
	}

	void operator()(double d) {
		stream_ << d;
		return;
	}
	void operator()(const std::string& str) {
		stream_ << "\"" << create_escapes(str) << "\"";
		return;
	}
	void operator()(struct bool_wrapper b) {
		stream_ << ((b.value) ? "true" : "false");
		return;
	}
	void operator()(const object_ptr_type& obj) {
		if (obj->size() > 0) {
			stream_ << *obj;
		} else {
			stream_ << "null";
		}
		return;
	}
	void operator()(const array_ptr_type& obj) {
		if (obj->size() > 0) {
			obj->write(stream_);
		} else {
			stream_ << "null";
		}
		return;
	}
	void operator()(const json_string& obj) {
		stream_ << obj.value;
		return;
	}
};

array::array(void) {
}

array::~array(void) {
}

array_ptr_type array::create(void) {
	return array_ptr_type(new array());
}

bool array::add(const value_type& value) {
	v_.push_back(value);
	return true;
}

void array::write(std::ostream& s) const {
	bool begin_flag = true;
	value_writer writer(s);

	s << "[";
	for (array_impl_type::const_iterator it = v_.begin(); it != v_.end(); ++it) {
		if (begin_flag == false) s << ",";

		boost::apply_visitor(writer, *it);
		begin_flag = false;
	}
	s << "]";
	return;
}

std::ostream& operator<<(std::ostream& s, const array& a) {
	a.write(s);
	return s;
}


object::object(void) {
}

object::~object(void) {
}

object_ptr_type object::create(void) {
	return object_ptr_type(new object());
}

void object::write(std::ostream& s) const {
	bool begin_flag = true;
	value_writer writer(s);

	s << "{";
	for (object_impl_type::const_iterator it = v_.begin(); it != v_.end(); ++it) {
		if (begin_flag == false) s << ",";
		if (it->first.empty() == false) {
			s << "\"" << it->first << "\":";  // 本当はこれもescapeしたほうがいいはず
		}
		boost::apply_visitor(writer, it->second);
		begin_flag = false;
	}
	s << "}";
	return;
}

bool object::add(const std::string& key, const value_type& value) {
	v_.push_back(std::make_pair(key, value));
	return true;
}

/*!
  escape処理

  @param[in] s エスケープする文字列

  @return エスケープ結果

  boostのjson_parser_write.hppから流用...
*/
static std::string create_escapes(const std::string& s) {
	std::string result;
	std::string::const_iterator b = s.begin();
	std::string::const_iterator e = s.end();

	while (b != e) {
		if (*b == '\b') {
			result += '\\', result += 'b';
		} else if (*b == '\f') {
			result += '\\', result += 'f';
		} else if (*b == '\n') {
			result += '\\', result += 'n';
		} else if (*b == '\r') {
			result += '\\', result += 'r';
		} else if (*b == '/') {
			result += '\\', result += '/';
		} else if (*b == '"') {
			result += '\\', result += '"';
		} else if (*b == '\\') {
			result += '\\', result += '\\';
		} else {
			result += *b;
		}
		++b;
	}
	return result;
}


std::ostream& operator<<(std::ostream& s, const object& obj) {
	obj.write(s);
	return s;
}

}
}
