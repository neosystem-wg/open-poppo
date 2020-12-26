#ifndef NEOSYSTEM_JSON_JSON_READER_HPP_
#define NEOSYSTEM_JSON_JSON_READER_HPP_

#include <boost/property_tree/ptree.hpp>


namespace poppo {
namespace json {

/*!
  パースエラーの例外クラス
 */
class parser_error : std::exception {
private:
	std::string message_;

public:
	parser_error(const parser_error&);
	explicit parser_error(const std::string&);
	virtual ~parser_error(void);

	parser_error& operator=(const parser_error&);
	virtual const char *what(void) const noexcept { return message_.c_str(); }
};

void json_read(std::istream&, boost::property_tree::ptree&);

}
}

#endif
