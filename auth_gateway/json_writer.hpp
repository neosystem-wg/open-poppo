#ifndef NEOSYSTEM_JSON_JSON_WRITER_HPP_
#define NEOSYSTEM_JSON_JSON_WRITER_HPP_

#include <string>
#include <vector>
#include <memory>

#include <boost/variant.hpp>


namespace poppo {
namespace json {

/*!
  @brief bool型のwrapper

  boost::shared_ptr<> がboolにキャストできてしまい、visitorの実装漏れを検出できなくなるからこれで回避
 */
struct bool_wrapper {
	bool value;
};

struct json_string {
	std::string value;
};

class object;
using object_ptr_type = std::shared_ptr<object>;
class array;
using array_ptr_type = std::shared_ptr<array>;

typedef boost::variant<int, double, std::string, bool_wrapper, object_ptr_type, array_ptr_type, json_string> value_type;

class array {
private:
	using array_impl_type = std::vector<value_type>;

	array_impl_type v_;

	array(void);

public:
	static array_ptr_type create(void);
	~array(void);

	array_impl_type::size_type size(void) const { return v_.size(); }
	bool add(const value_type&);
	void write(std::ostream&) const;
};

class object {
private:
	typedef std::vector<std::pair<std::string, value_type> > object_impl_type;

	object_impl_type v_;

	object(void);

public:
	static object_ptr_type create(void);
	~object(void);

	object_impl_type::size_type size(void) const { return v_.size(); }
	bool add(const std::string&, const value_type&);
	void write(std::ostream&) const;
};

std::ostream& operator<<(std::ostream&, const object&);

}
}

#endif
