#define BOOST_SPIRIT_USE_PHOENIX_V3

#include <boost/variant.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/qi_string.hpp>
#include <boost/lexical_cast.hpp>

#include "json_reader.hpp"


namespace poppo {
namespace json {

parser_error::parser_error(const parser_error& e) {
	*this = e;
}

parser_error::parser_error(const std::string& m)
	: message_(m) {
}

parser_error::~parser_error(void) {
}

parser_error& parser_error::operator=(const parser_error& e) {
	message_ = e.message_;
	return *this;
}


namespace qi = boost::spirit::qi;
namespace phoenix = boost::phoenix;

template<typename Iterator>
struct skipper_impl : public qi::grammar< Iterator > {
	qi::rule< Iterator > skip;

	skipper_impl() : skipper_impl::base_type(skip, "") {
		skip = qi::string("//") >> *(qi::char_ - '\r' - '\n') >> (qi::char_('\r') | qi::char_('\n') | qi::eoi)
			| qi::string("/*") >> *(qi::char_ - qi::string("*/")) >> (qi::string("*/") | qi::eoi)
			| qi::space
			;
    }
};

typedef skipper_impl<boost::spirit::istream_iterator> skipper;

typedef struct _json_null_type {} json_null_type;
typedef boost::variant<std::string, int, bool, json_null_type, boost::property_tree::ptree> value_type;

struct value_transrator : boost::static_visitor<void> {
	boost::property_tree::ptree& pt_;

	value_transrator(boost::property_tree::ptree& pt) : pt_(pt) {
	}

	void operator()(const std::string& v) {
		pt_.push_back(std::make_pair("", boost::property_tree::ptree(v)));
	}
	void operator()(int v) {
		pt_.push_back(std::make_pair("", boost::property_tree::ptree(boost::lexical_cast< std::string >(v))));
	}
	void operator()(bool v) {
		pt_.push_back(std::make_pair("", boost::property_tree::ptree((v == false) ? "false" : "true")));
	}
	void operator()(const json_null_type&) {
		pt_.push_back(std::make_pair("", boost::property_tree::ptree("")));
	}
	void operator()(const boost::property_tree::ptree& v) {
		pt_.push_back(std::make_pair("", v));
	}
};

void add_value_to_ptree(boost::property_tree::ptree& pt, const value_type& v) {
	value_transrator visitor(pt);
	boost::apply_visitor(visitor, v);
	return;
}


struct pair_transrator : boost::static_visitor<void> {
	boost::property_tree::ptree& pt_;
	const std::string& key_;

	pair_transrator(boost::property_tree::ptree& pt, const std::string& key) : pt_(pt), key_(key) {
	}

	void operator()(const std::string& v) {
		pt_.put(key_, v);
	}
	void operator()(int v) {
		pt_.put(key_, v);
	}
	void operator()(bool v) {
		pt_.put(key_, (v == false) ? "false" : "true");
	}
	void operator()(const json_null_type&) {
		pt_.put(key_, "");
	}
	void operator()(const boost::property_tree::ptree& v) {
		pt_.add_child(key_, v);
	}
};

void add_pair_to_ptree(boost::property_tree::ptree& pt, const std::pair<std::string, value_type>& v) {
	pair_transrator visitor(pt, v.first);
	boost::apply_visitor(visitor, v.second);
	return;
}


template<typename Iterator, typename Skipper>
struct grammar : qi::grammar<Iterator, boost::property_tree::ptree(), Skipper> {
	qi::rule<Iterator, boost::property_tree::ptree(), Skipper> input, object, array;
	qi::rule<Iterator, value_type(), Skipper> value;
	qi::rule<Iterator, char()> escape, character;
	qi::rule<Iterator, std::string()> string_rule;
	qi::rule<Iterator, std::pair<std::string, value_type>(), Skipper > member;

	grammar(void) : grammar::base_type(input) {
		input = (object | array)[qi::_val = qi::_1]
			;
		object = qi::char_('{')[qi::_val = phoenix::construct< boost::property_tree::ptree >()] >> 
			(qi::char_('}') | ((member[phoenix::bind(&add_pair_to_ptree, qi::_val, qi::_1)] % ',') >> '}'))
			;
		array = qi::char_('[')[qi::_val = phoenix::construct< boost::property_tree::ptree >()] >> 
			(qi::char_(']') | ((value[phoenix::bind(&add_value_to_ptree, qi::_val, qi::_1)] % ',') >> ']'))
			;
		member = (string_rule >> ':' >> value)[qi::_val = phoenix::construct<std::pair<std::string, value_type> >(qi::_1, qi::_2)]
			;
		value = string_rule[qi::_val = qi::_1]
			| qi::int_[qi::_val = qi::_1]
			| qi::string("true")[qi::_val = static_cast<bool>(true)]
			| qi::string("false")[qi::_val = static_cast<bool>(false)]
			| qi::string("null")[qi::_val = json_null_type()]
			| object[qi::_val = qi::_1]
			| array[qi::_val = qi::_1]
			;
		string_rule = '\"' >> (qi::as_string[*(character)])[qi::_val = qi::_1] >> '\"'
			;
		character = (qi::char_ - "\\" - "\"")[qi::_val = qi::_1]
			| (qi::char_("\\") >> escape)[qi::_val = qi::_2]
			;
		escape = qi::char_('\"')[qi::_val = qi::_1]
			| qi::char_('\\')[qi::_val = qi::_1]
			| qi::char_('b')[qi::_val = '\b']
			| qi::char_('f')[qi::_val = '\f']
			| qi::char_('n')[qi::_val = '\n']
			| qi::char_('r')[qi::_val = '\r']
			| qi::char_('t')[qi::_val = '\t']
			| qi::char_('/')[qi::_val = qi::_1]
			// 手抜き対策... (´・ω・｀)
			| 'u' >> qi::string("0009")[qi::_val = '\t']
			| 'u' >> qi::uint_parser<unsigned long, 16, 4, 4>()[qi::_val = ' ']
			;
	}
};


/*!
  jsonのパース

  @param[in] stream 入力
  @param[out] pt 結果
 */
void json_read(std::istream& stream, boost::property_tree::ptree& pt) {
	boost::spirit::istream_iterator first(stream), last;

	stream.unsetf(std::ios_base::skipws);
	grammar< boost::spirit::istream_iterator, skipper > g;
	if (boost::spirit::qi::phrase_parse(first, last, g, skipper(), pt) == false) {
		throw parser_error("parse fialed.");
	}
	return;
}

}
}
