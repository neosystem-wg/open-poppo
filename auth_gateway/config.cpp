#include <iostream>
#include <filesystem>
#include <regex>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/algorithm/string.hpp>

#include "common.hpp"
#include "config.hpp"


namespace poppo {
namespace auth_gateway {

constexpr const char *CSRF_COOKIE_NAME = "korat_csrf_token";
constexpr const char *CSRF_HEADER_NAME = "x-korat-csrf-token";
constexpr const int SESSION_TIMEOUT_MINUTES = 72 * 60;

using namespace neosystem::wg;

const char *bool_to_string(bool b) {
	return (b) ? "on" : "off";
}

void replace_env(std::string& result, const std::string& s) {
	std::regex r("\\$\\{env:(\\w+)\\}");

	auto words_begin = std::sregex_iterator(s.begin(), s.end(), r);
	auto words_end = std::sregex_iterator();

	if (words_begin == words_end) {
		result = s;
		return;
	}

	std::smatch match;
	for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
		match = *i;
		result += match.prefix();

		if (match.size() < 2) continue;

		const char *env = getenv(match[1].str().c_str());
		if (env == nullptr) continue;
		result += env;
	}
	result += match.suffix();
	return;
}

template<typename T>
T get_config(const std::vector<T>& v, const std::string& path) {
	const char *p = path.c_str();
	for (auto it = v.begin(), end = v.end(); it != end; ++it) {
		std::size_t length = (*it)->get_request_path().size();
		if ((*it)->is_match()) {
			if (path == (*it)->get_request_path()) {
				return *it;
			}
		} else if ((*it)->is_regex()) {
			 std::regex re((*it)->get_request_path());
			 if (std::regex_match(path, re)) {
				 return *it;
			 }
		} else {
			if (strncmp(p, (*it)->get_request_path().c_str(), length) == 0) {
				return *it;
			}
		}
	}
	return nullptr;
}

template<typename T>
T get_config_for_callback(const std::vector<T>& v, const std::string& path) {
	std::size_t pos = path.find("?");
	std::size_t length = (pos == std::string::npos) ? path.size() : pos;
	for (auto it = v.begin(), end = v.end(); it != end; ++it) {
		if (path.compare(0, length, (*it)->get_callback_url_info().get_path()) == 0) {
			return *it;
		}
	}
	return nullptr;
}

config::config(void) : log_level_(log::log_level_type::DEBUG), log_size_(2 * 1024 * 1024),
	log_count_(16), port_(14142), backlog_(1024), header_output_(false), ssl_port_(0), enable_cookie_secure_(true), login_success_redirect_("/top"),
	no_login_redirect_("/login"), cache_size_(1024), streambuf_cache_size_(1024), csrf_cookie_name_(CSRF_COOKIE_NAME), csrf_header_name_(CSRF_HEADER_NAME),
	session_timeout_minutes_(SESSION_TIMEOUT_MINUTES), enable_http2_(false), enable_access_log_(false), enable_auth_history_(false),
	logout_path_("/logout") {
}

proxy_config::ptr_type config::get_proxy_config(const std::string& host, const std::string& path) const {
	for (const auto& c: host_proxy_configs_) {
		if (c.first == host) {
			return get_config(c.second, path);
		}
	}
	return get_config(proxy_configs_, path);
}

static_page_config::ptr_type config::get_static_page_config(const std::string& path) const {
	return get_config(static_page_configs_, path);
}

oauth1_server_config::ptr_type config::get_oauth1_server_config(const std::string& path) const {
	return get_config(oauth1_server_configs_, path);
}

oauth1_server_config::ptr_type config::get_oauth1_server_config_for_callback(const std::string& path) const {
	return get_config_for_callback(oauth1_server_configs_, path);
}

oauth2_server_config::ptr_type config::get_oauth2_server_config(const std::string& path) const {
	return get_config(oauth2_server_configs_, path);
}

oauth2_server_config::ptr_type config::get_oauth2_server_config_for_callback(const std::string& path) const {
	return get_config_for_callback(oauth2_server_configs_, path);
}

bool config::load(const std::string& path) {
	using namespace boost::property_tree;

	ptree pt;
	std::string tmp;

	try {
		read_info(path, pt);
	} catch (const boost::property_tree::info_parser::info_parser_error& e) {
		std::cerr << e.what() << std::endl;
		return false;
	}

	port_ = pt.get("port", static_cast<short>(14142));
	backlog_ = pt.get("backlog", 1024);
	tmp = pt.get("header_output", "off");
	if (tmp == "on") {
		header_output_ = true;
	} else {
		header_output_ = false;
	}

	static_resource_dir_ = pt.get("static_resource_dir", "/var/www/");

	log_file_name_ = pt.get("log.file_name", "stdout");
	log_level_ = log::string_to_level(pt.get("log.level", "DEBUG"));
	log_size_ = pt.get("log.size", 2 * 1024 * 1024);
	log_count_ = pt.get("log.count", 8);

	// poppo接続先
	poppo_url_ = pt.get("poppo", "http://localhost:8084/Users");
	if (poppo_url_info_.init(poppo_url_) == false) return false;

	// proxy設定
	if (load_proxy_config(proxy_configs_, pt) == false) return false;

	// static page設定
	if (load_static_page_config(pt) == false) return false;

	// oauth設定
	if (load_oauth1_server_config(pt) == false) return false;

	// oauth2設定
	if (load_oauth2_server_config(pt) == false) return false;

	tmp = pt.get("session_redis_server", "");
	if (tmp != "") {
		std::vector<std::string> parts;
		boost::split(parts, tmp, boost::is_any_of(":"));
		session_redis_server_ = parts[0];
		std::cout << tmp << ", " << parts[0] << std::endl;
		if (parts.size() >= 2) {
			session_redis_server_port_ = parts[1];
		} else {
			session_redis_server_port_ = "6379";
		}
	}

	login_success_redirect_ = pt.get("login_success_redirect", "/top");
	no_login_redirect_ = pt.get("no_login_redirect", "/login");
	cookie_domain_ = pt.get("cookie_domain", "");

	// host設定
	if (load_host_config(pt) == false) return false;

	csrf_cookie_name_ = pt.get("csrf_cookie_name", CSRF_COOKIE_NAME);
	csrf_header_name_ = pt.get("csrf_header_name", CSRF_HEADER_NAME);

	session_timeout_minutes_ = pt.get("session_timeout_minutes", SESSION_TIMEOUT_MINUTES);

	tmp = pt.get("http2", "off");
	if (tmp == "on") {
		enable_http2_ = true;
	} else {
		enable_http2_ = false;
	}

	// HTTPS
	ssl_port_ = pt.get("ssl_port", static_cast<short>(0));
	if (ssl_port_ > 0) {
		tmp = pt.get<std::string>("cert_file", "");
		if (tmp == "") return false;
		replace_env(cert_file_, tmp);
		tmp = pt.get<std::string>("key_file", "");
		if (tmp == "") return false;
		replace_env(key_file_, tmp);

		tmp = pt.get<std::string>("enable_cookie_secure", "on");
		if (tmp == "on") {
			enable_cookie_secure_ = true;
		} else if (tmp == "off") {
			enable_cookie_secure_ = false;
		}
	}

	tmp = pt.get("access_log", "off");
	if (tmp == "on") {
		enable_access_log_ = true;
	} else {
		enable_access_log_ = false;
	}

	tmp = pt.get("auth_history", "off");
	if (tmp == "on") {
		enable_auth_history_ = true;
	} else {
		enable_auth_history_ = false;
	}
	return true;
}

bool config::load_oauth1_server_config(const boost::property_tree::ptree& pt) {
	auto opt = pt.get_child_optional("oauth");
	if (!opt) return true;

	auto child = opt.get();
	auto end = child.end();
	for (auto it = child.begin(); it != end; ++it) {
		auto ptr = std::make_shared<oauth1_server_config>();
		if (ptr->init(it->first, it->second) == false) {
			std::cerr << "invalid proxy config" << std::endl;
			return false;
		}
		oauth1_server_configs_.push_back(ptr);
	}

	// 長さ順でsort
	std::sort(oauth1_server_configs_.begin(), oauth1_server_configs_.end(),
			[](const oauth1_server_config::ptr_type& l, const oauth1_server_config::ptr_type& r) {
		return l->get_request_path().size() < r->get_request_path().size();
	});
	return true;
}

bool config::load_oauth2_server_config(const boost::property_tree::ptree& pt) {
	auto opt = pt.get_child_optional("oauth2");
	if (!opt) return true;

	auto child = opt.get();
	auto end = child.end();
	for (auto it = child.begin(); it != end; ++it) {
		auto ptr = std::make_shared<oauth2_server_config>();
		if (ptr->init(it->first, it->second) == false) {
			std::cerr << "invalid proxy config" << std::endl;
			return false;
		}
		oauth2_server_configs_.push_back(ptr);
	}

	// 長さ順でsort
	std::sort(oauth2_server_configs_.begin(), oauth2_server_configs_.end(),
			[](const oauth2_server_config::ptr_type& l, const oauth2_server_config::ptr_type& r) {
		return l->get_request_path().size() < r->get_request_path().size();
	});
	return true;
}

bool config::load_static_page_config(const boost::property_tree::ptree& pt) {
	auto opt = pt.get_child_optional("page");
	if (!opt) return true;

	auto child = opt.get();
	auto end = child.end();
	for (auto it = child.begin(); it != end; ++it) {
		auto ptr = std::make_shared<static_page_config>();
		if (ptr->init(it->first, it->second) == false) {
			std::cerr << "invalid proxy config" << std::endl;
			return false;
		}
		static_page_configs_.push_back(ptr);
	}

	// 長さ順でsort
	std::sort(static_page_configs_.begin(), static_page_configs_.end(),
			[](const static_page_config::ptr_type& l, const static_page_config::ptr_type& r) {
		return l->get_request_path().size() < r->get_request_path().size();
	});
	return true;
}

bool config::load_host_config(const boost::property_tree::ptree& pt) {
	auto opt = pt.get_child_optional("host");
	if (!opt) return true;

	auto child = opt.get();
	auto end = child.end();
	for (auto it = child.begin(); it != end; ++it) {
		auto host = it->first;
		proxy_configs_type configs;
		if (load_proxy_config(configs, it->second) == false) {
			std::cerr << "invalid proxy config" << std::endl;
			return false;
		}
		host_proxy_configs_.push_back(std::pair<std::string, proxy_configs_type>(host, std::move(configs)));
	}
	return true;
}

bool config::load_proxy_config(proxy_configs_type& configs, const boost::property_tree::ptree& pt) {
	auto opt = pt.get_child_optional("proxy");
	if (!opt) return true;

	auto child = opt.get();
	auto end = child.end();
	for (auto it = child.begin(); it != end; ++it) {
		auto ptr = std::make_shared<proxy_config>();
		if (ptr->init(it->first, it->second) == false) {
			std::cerr << "invalid proxy config" << std::endl;
			return false;
		}
		configs.push_back(ptr);
	}

	// 長さ順でsort
	std::sort(configs.begin(), configs.end(),
			[](const proxy_config::ptr_type& l, const proxy_config::ptr_type& r) {
		return l->get_request_path().size() > r->get_request_path().size();
	});
	return true;
}

bool config::is_static_request(const std::string& request_path, std::filesystem::path& result) const {
	// TODO
	if (strncmp(request_path.c_str(), "/static/", 8) != 0) {
		return false;
	}

	std::error_code ec;
	std::filesystem::path tmp(request_path.c_str() + 8);
	tmp /= static_resource_dir_;
	std::filesystem::path p(std::filesystem::canonical(tmp, ec));
	if (ec) {
		std::cout << static_resource_dir_ << "/" << request_path << std::endl;
		return false;
	}

	if (strncmp(p.c_str(), static_resource_dir_.c_str(), static_resource_dir_.native().size()) == 0) {
		result = std::move(p);
		return true;
	}
	return false;
}

void config::dump(std::ostream& stream) const {
	stream << "log level: " << log::level_to_string(log_level_) << std::endl;
	stream << "port: " << port_ << std::endl;
	stream << "session_redis_server: " << session_redis_server_ << ":" << session_redis_server_port_ << std::endl;
	stream << "backlog: " << backlog_ << std::endl;
	stream << "login_success_redirect: " << login_success_redirect_ << std::endl;
	stream << "no_login_redirect: " << no_login_redirect_ << std::endl;
	stream << "cookie_domain: " << cookie_domain_ << std::endl;
	stream << "csrf_cookie_name: " << csrf_cookie_name_ << std::endl;
	stream << "csrf_header_name: " << csrf_header_name_ << std::endl;

	stream << "proxy configs: " << proxy_configs_.size() << std::endl;
	std::for_each(proxy_configs_.begin(), proxy_configs_.end(), [&stream](const proxy_config::ptr_type& p) {
		p->dump(stream);
	});

	stream << "host proxy configs: " << host_proxy_configs_.size() << std::endl;
	std::for_each(host_proxy_configs_.begin(), host_proxy_configs_.end(), [&stream](const std::pair<std::string, proxy_configs_type>& p) {
		stream << "  " << p.first << std::endl;
		for (auto& conf: p.second) {
			conf->dump("    ", stream);
		}
	});

	stream << "static page configs: " << static_page_configs_.size() << std::endl;
	std::for_each(static_page_configs_.begin(), static_page_configs_.end(), [&stream](const static_page_config::ptr_type& p) {
		p->dump(stream);
	});

	stream << "oauth1 server configs: " << oauth1_server_configs_.size() << std::endl;
	std::for_each(oauth1_server_configs_.begin(), oauth1_server_configs_.end(), [&stream](const oauth1_server_config::ptr_type& p) {
		p->dump(stream);
	});

	stream << "oauth2 server configs: " << oauth2_server_configs_.size() << std::endl;
	std::for_each(oauth2_server_configs_.begin(), oauth2_server_configs_.end(), [&stream](const oauth2_server_config::ptr_type& p) {
		p->dump(stream);
	});

	stream << "session_timeout_minutes: " << session_timeout_minutes_ << std::endl;
	stream << "http2: " << bool_to_string(enable_http2_) << std::endl;
	stream << "access_log: " << bool_to_string(enable_access_log_) << std::endl;
	stream << "auth_history: " << bool_to_string(enable_auth_history_) << std::endl;
	stream << "enable_cookie_secure: " << enable_cookie_secure_ << std::endl;
	return;
}


bool static_page_config::init(const std::string& request_path, const boost::property_tree::ptree& pt) {
	request_path_ = request_path;

	auto opt = pt.get_optional<std::string>("path");
	path_ = opt.get();

	match_ = false;
	regex_ = false;
	return true;
}

void static_page_config::dump(std::ostream& stream) const {
	const char *sp = "    ";
	stream << "  request_path: " << request_path_ << std::endl;
	stream << sp << "path: " << path_ << std::endl;
	return;
}

bool proxy_config::init(const std::string& request_path, const boost::property_tree::ptree& pt) {
	request_path_ = request_path;

	auto host_opt = pt.get_optional<std::string>("host");
	if (!host_opt) return false;

	std::string tmp(host_opt.get());
	replace_env(host_, tmp);
	if (host_ == "") return false;

	port_ = pt.get<std::string>("port", "80");

	path_ = pt.get<std::string>("path", "");

	tmp = pt.get("auth", "off");
	if (tmp == "on") {
		need_auth_ = true;
	} else {
		need_auth_ = false;
	}

	tmp = pt.get("csrf_check", "off");
	if (tmp == "on") {
		need_csrf_check_ = true;
	} else {
		need_csrf_check_ = false;
	}

	replace_pos_ = path_.find("{poppo_id}");
	need_replace_poppo_id_ = (replace_pos_ == std::string::npos) ? false : true;

	auto cors_opt = pt.get_child_optional("cors");
	if (cors_opt) {
		cors_config_ = std::make_shared<cors_config>();
		if (cors_config_->init(cors_opt.get()) == false) return false;
	}

	tmp = pt.get<std::string>("match", "0");
	match_ = (tmp == "1") ? true : false;

	tmp = pt.get<std::string>("regex", "0");
	regex_ = (tmp == "1") ? true : false;

	tmp = pt.get<std::string>("response_401", "0");
	response_401_ = (tmp == "1") ? true : false;
	return true;
}

void proxy_config::dump(std::ostream& stream) const {
	const char *sp = "  ";
	dump(sp, stream);
	return;
}

void proxy_config::dump(const char *sp, std::ostream& stream) const {
	stream << sp << "request_path: " << request_path_ << std::endl;
	stream << sp << "  host: " << host_ << std::endl;
	stream << sp << "  port: " << port_ << std::endl;
	stream << sp << "  path: " << ((path_ == "") ? "<empty>" : path_) << std::endl;
	stream << sp << "  auth: " << need_auth_ << std::endl;
	stream << sp << "  match: " << match_ << std::endl;
	stream << sp << "  regex: " << regex_ << std::endl;
	stream << sp << "  response_401: " << response_401_ << std::endl;
	stream << sp << "  csrf_check: " << need_csrf_check_ << std::endl;
	stream << sp << "  replace_poppo_id: " << need_replace_poppo_id_ << std::endl;
	if (cors_config_ != nullptr) cors_config_->dump(sp, stream);
	return;
}

bool oauth1_server_config::init(const std::string& request_path, const boost::property_tree::ptree& pt) {
	request_path_ = request_path;

	auto opt = pt.get_optional<std::string>("key");
	if (!opt) return false;
	key_ = opt.get();

	opt = pt.get_optional<std::string>("consumer_key");
	if (!opt) return false;
	consumer_key_ = opt.get();

	opt = pt.get_optional<std::string>("request_token_url");
	if (!opt) return false;
	request_token_url_ = opt.get();
	if (request_token_url_info_.init(request_token_url_) == false) return false;

	opt = pt.get_optional<std::string>("callback_url");
	if (!opt) return false;
	callback_url_ = opt.get();
	if (callback_url_info_.init(callback_url_) == false) return false;

	opt = pt.get_optional<std::string>("access_token_url");
	if (!opt) return false;
	access_token_url_ = opt.get();
	if (access_token_url_info_.init(access_token_url_) == false) return false;

	opt = pt.get_optional<std::string>("authenticate_url");
	if (!opt) return false;
	authenticate_url_ = opt.get();

	match_ = false;
	regex_ = false;
	return true;
}

void oauth1_server_config::dump(std::ostream& stream) const {
	const char *sp = "    ";
	stream << "  request_path: " << request_path_ << std::endl;
	stream << sp << "key: " << key_ << std::endl;
	stream << sp << "consumer_key: " << consumer_key_ << std::endl;
	stream << sp << "request_token_url: " << request_token_url_ << std::endl;
	stream << sp << "callback_url: " << callback_url_ << std::endl;
	stream << sp << "access_token_url: " << access_token_url_ << std::endl;
	return;
}

oauth2_server_config::oauth2_server_config(void) : auth_provider_(auth_provider::UNKNOWN), match_(false), regex_(false) {
}

bool oauth2_server_config::init(const std::string& request_path, const boost::property_tree::ptree& pt) {
	request_path_ = request_path;

	auto opt = pt.get_optional<std::string>("auth_provider");
	if (!opt) return false;
	auth_provider_ = string_to_auth_provider(opt.get().c_str());

	opt = pt.get_optional<std::string>("client_id");
	if (!opt) return false;
	client_id_ = opt.get();

	opt = pt.get_optional<std::string>("client_secret");
	if (!opt) return false;
	client_secret_ = opt.get();

	opt = pt.get_optional<std::string>("user_authorization_url");
	if (!opt) return false;
	user_authorization_url_ = opt.get();
	if (user_authorization_url_info_.init(user_authorization_url_) == false) return false;

	opt = pt.get_optional<std::string>("access_token_url");
	if (!opt) return false;
	access_token_url_ = opt.get();
	if (access_token_url_info_.init(access_token_url_) == false) return false;

	opt = pt.get_optional<std::string>("scope");
	if (!opt) return false;
	scope_ = opt.get();

	opt = pt.get_optional<std::string>("user_info_url");
	if (!opt) return false;
	user_info_url_ = opt.get();
	if (user_info_url_info_.init(user_info_url_) == false) return false;

	opt = pt.get_optional<std::string>("callback_url");
	if (!opt) return false;
	callback_url_ = opt.get();
	if (callback_url_info_.init(callback_url_) == false) return false;

	match_ = false;
	regex_ = false;
	return true;
}

void oauth2_server_config::dump(std::ostream& stream) const {
	const char *sp = "    ";
	stream << "  request_path: " << request_path_ << std::endl;
	stream << sp << "auth_provider: " << auth_provider_to_string(auth_provider_) << std::endl;
	stream << sp << "client_id: " << client_id_ << std::endl;
	stream << sp << "client_secret: " << client_secret_ << std::endl;
	stream << sp << "user_authorization_url: " << user_authorization_url_ << std::endl;
	stream << sp << "access_token_url: " << access_token_url_ << std::endl;
	stream << sp << "user_info_url: " << user_info_url_ << std::endl;
	stream << sp << "callback_url: " << callback_url_ << std::endl;
	stream << sp << "scope: " << scope_ << std::endl;
	return;
}


cors_config::cors_config(void) : allow_credentials_(false), max_age_(864000) {
}

bool cors_config::init(const boost::property_tree::ptree& pt) {
	int tmp = pt.get("allow_credentials", 0);
	allow_credentials_ = (tmp == 0) ? false : true;

	std::string tmp_str = pt.get("allow_origin", "");
	boost::split(allow_origin_list_, tmp_str, boost::is_any_of(","));
	
	allow_methods_ = pt.get("allow_methods", "");

	allow_headers_ = pt.get("allow_headers", "");

	max_age_ = pt.get("max_age", 864000);
	return true;
}

void cors_config::dump(const char *sp, std::ostream& stream) const {
	stream << sp << "cors" << std::endl;
	stream << sp << "  allow origin:" << std::endl;
	for (const auto& s : allow_origin_list_) {
		stream << sp << "    " << s << std::endl;
	}
	stream << sp << "  allow methods:" << allow_methods_ << std::endl;
	stream << sp << "  allow headers:" << allow_headers_ << std::endl;
	stream << sp << "  max_age: " << max_age_ << std::endl;
	return;
}


std::ostream& operator<<(std::ostream& stream, const config& c) {
	c.dump(stream);
	return stream;
}

}
}
