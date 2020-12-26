#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_CONFIG_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_CONFIG_HPP_

#include <string>
#include <vector>
#include <memory>
#include <filesystem>

#include <boost/property_tree/ptree.hpp>
	
#include "common.hpp"
#include "log.hpp"
#include "http_common.hpp"
#include "auth.hpp"


namespace poppo {
namespace auth_gateway {

class cors_config {
public:
	using ptr_type = std::shared_ptr<cors_config>;

private:
	bool allow_credentials_;

	std::vector<std::string> allow_origin_list_;

	std::string allow_methods_;

	std::string allow_headers_;

	int max_age_;

public:
	cors_config(void);
	bool init(const boost::property_tree::ptree&);
	void dump(const char *, std::ostream&) const;

	bool is_allow_credentials(void) const { return allow_credentials_; }
	const std::vector<std::string>& get_allow_origin_list(void) const { return allow_origin_list_; }
	bool is_allow_origin(const std::string& origin) const {
		for (const auto& allow : allow_origin_list_) {
			if (origin == allow) return true;
		}
		return false;
	}

	const std::string& get_allow_methods(void) const { return allow_methods_; }
	bool has_allow_methods(void) const { return (allow_methods_.empty()) ? false : true; }

	const std::string& get_allow_headers(void) const { return allow_headers_; }
	bool has_allow_headers(void) const { return (allow_headers_.empty()) ? false : true; }

	int get_max_age(void) const { return max_age_; }
};


class oauth1_server_config {
public:
	using ptr_type = std::shared_ptr<oauth1_server_config>;

private:
	std::string request_path_;

	std::string key_;
	std::string consumer_key_;

	std::string request_token_url_;
	neosystem::http::url_info request_token_url_info_;

	std::string callback_url_;
	neosystem::http::url_info callback_url_info_;

	std::string access_token_url_;
	neosystem::http::url_info access_token_url_info_;

	std::string authenticate_url_;

	bool match_;
	bool regex_;

public:
	bool init(const std::string&, const boost::property_tree::ptree&);
	void dump(std::ostream&) const;

	const std::string& get_request_path(void) const { return request_path_; }
	const std::string& get_key(void) const { return key_; }
	const std::string& get_consumer_key(void) const { return consumer_key_; }

	const std::string& get_request_token_url(void) const { return request_token_url_; }
	const neosystem::http::url_info& get_request_token_url_info(void) const { return request_token_url_info_; }

	const std::string& get_callback_url(void) const { return callback_url_; }
	const neosystem::http::url_info& get_callback_url_info(void) const { return callback_url_info_; }

	const std::string& get_access_token_url(void) const { return access_token_url_; }
	const neosystem::http::url_info& get_access_token_url_info(void) const { return access_token_url_info_; }

	const std::string& get_authenticate_url(void) const { return authenticate_url_; }

	bool is_match(void) const { return match_; }
	bool is_regex(void) const { return regex_; }
};


class oauth2_server_config {
public:
	using ptr_type = std::shared_ptr<oauth2_server_config>;

private:
	std::string request_path_;
	auth_provider auth_provider_;

	std::string client_id_;
	std::string client_secret_;

	std::string user_authorization_url_;
	neosystem::http::url_info user_authorization_url_info_;

	std::string access_token_url_;
	neosystem::http::url_info access_token_url_info_;

	std::string user_info_url_;
	neosystem::http::url_info user_info_url_info_;

	std::string callback_url_;
	neosystem::http::url_info callback_url_info_;

	std::string scope_;

	bool match_;
	bool regex_;

public:
	oauth2_server_config(void);
	bool init(const std::string&, const boost::property_tree::ptree&);
	void dump(std::ostream&) const;

	const std::string& get_request_path(void) const { return request_path_; }
	auth_provider get_auth_provider(void) const { return auth_provider_; }

	const std::string& get_client_id(void) const { return client_id_; }
	const std::string& get_client_secret(void) const { return client_secret_; }

	const std::string& get_user_authorization_url(void) const { return user_authorization_url_; }
	const neosystem::http::url_info& get_user_authorization_url_info(void) const { return user_authorization_url_info_; }

	const std::string& get_access_token_url(void) const { return access_token_url_; }
	const neosystem::http::url_info& get_access_token_url_info(void) const { return access_token_url_info_; }

	const std::string& get_callback_url(void) const { return callback_url_; }
	const neosystem::http::url_info& get_callback_url_info(void) const { return callback_url_info_; }

	const std::string& get_scope(void) const { return scope_; }

	const std::string& get_user_info_url(void) const { return user_info_url_; }
	const neosystem::http::url_info& get_user_info_url_info(void) const { return user_info_url_info_; }

	bool is_match(void) const { return match_; }
	bool is_regex(void) const { return regex_; }
};


class static_page_config {
public:
	using ptr_type = std::shared_ptr<static_page_config>;

private:
	std::string request_path_;
	std::string path_;

	bool match_;
	bool regex_;

public:
	bool init(const std::string&, const boost::property_tree::ptree&);
	void dump(std::ostream&) const;

	const std::string& get_request_path(void) const { return request_path_; }
	const std::string& get_path(void) const { return path_; }

	bool is_match(void) const { return match_; }
	bool is_regex(void) const { return regex_; }
};


class proxy_config {
public:
	using ptr_type = std::shared_ptr<proxy_config>;

private:
	std::string request_path_;
	std::string host_;
	std::string port_;
	std::string path_;
	bool need_auth_;
	bool need_csrf_check_;
	bool need_replace_poppo_id_;
	std::string::size_type replace_pos_;
	cors_config::ptr_type cors_config_;
	bool match_;
	bool regex_;
	bool response_401_;

public:
	bool init(const std::string&, const boost::property_tree::ptree&);
	void dump(const char *, std::ostream&) const;
	void dump(std::ostream&) const;

	const std::string& get_request_path(void) const { return request_path_; }
	const std::string& get_host(void) const { return host_; }
	const std::string& get_port(void) const { return port_; }
	const std::string& get_path(void) const { return path_; }
	bool need_auth(void) const { return need_auth_; }
	bool need_csrf_check(void) const { return need_csrf_check_; }
	bool need_replace_poppo_id(void) const { return need_replace_poppo_id_; }
	std::string::size_type get_replace_pos(void) const { return replace_pos_; }
	bool has_cors_config(void) const { return (cors_config_ == nullptr) ? false : true; }
	cors_config::ptr_type get_cors_config(void) const { return cors_config_; }
	bool is_match(void) const { return match_; }
	bool is_regex(void) const { return regex_; }
	bool is_response_401(void) const { return response_401_; }
};


class config {
private:
	using proxy_configs_type = std::vector<proxy_config::ptr_type>;
	neosystem::wg::log::log_level_type log_level_;  //!< log level
	std::string log_file_name_;
	int log_size_;            //!< ローテーションサイズ
	int log_count_;           //!< ローテーション数
	short port_;              //!< accept port
	int backlog_;
	bool header_output_;
	std::filesystem::path static_resource_dir_;

	short ssl_port_;
	std::string cert_file_;
	std::string key_file_;

	std::string poppo_url_;
	neosystem::http::url_info poppo_url_info_;

	std::string cookie_domain_;
	bool enable_cookie_secure_;

	proxy_configs_type proxy_configs_;
	std::vector<std::pair<std::string, proxy_configs_type>> host_proxy_configs_;
	std::vector<static_page_config::ptr_type> static_page_configs_;
	std::vector<oauth1_server_config::ptr_type> oauth1_server_configs_;
	std::vector<oauth2_server_config::ptr_type> oauth2_server_configs_;

	// session保存
	std::string session_redis_server_;
	std::string session_redis_server_port_;

	// ログイン成功後のリダイレクト先
	std::string login_success_redirect_;
	// ログインしていない場合のリダイレクト先
	std::string no_login_redirect_;

	// キャッシュサイズ
	std::size_t cache_size_;
	// streambufのキャッシュサイズ
	std::size_t streambuf_cache_size_;

	// CSRFトークン(cookie)
	std::string csrf_cookie_name_;
	// CSRFトークン(header)
	std::string csrf_header_name_;

	int session_timeout_minutes_;

	bool enable_http2_;

	bool enable_access_log_;

	bool enable_auth_history_;

	std::string logout_path_;

	bool load_proxy_config(proxy_configs_type&, const boost::property_tree::ptree&);
	bool load_host_config(const boost::property_tree::ptree& pt);
	bool load_static_page_config(const boost::property_tree::ptree&);
	bool load_oauth1_server_config(const boost::property_tree::ptree&);
	bool load_oauth2_server_config(const boost::property_tree::ptree&);

public:
	config(void);

	bool load(const std::string&);
	void dump(std::ostream&) const;
	bool is_static_request(const std::string&, std::filesystem::path&) const;

	short get_port(void) const { return port_; }
	const std::string& get_log_file_name(void) const { return log_file_name_; }
	neosystem::wg::log::log_level_type get_log_level(void) const { return log_level_; }
	int get_log_size(void) const { return log_size_; }
	int get_log_count(void) const { return log_count_; }
	int get_backlog(void) const { return backlog_; }
	bool is_header_output_enable(void) const { return header_output_; }

	short get_ssl_port(void) const { return ssl_port_; }
	const std::string& get_cert_file(void) const { return cert_file_; }
	const std::string& get_key_file(void) const { return key_file_; }

	proxy_config::ptr_type get_proxy_config(const std::string&, const std::string&) const;
	static_page_config::ptr_type get_static_page_config(const std::string&) const;
	oauth1_server_config::ptr_type get_oauth1_server_config(const std::string&) const;
	oauth1_server_config::ptr_type get_oauth1_server_config_for_callback(const std::string&) const;
	oauth2_server_config::ptr_type get_oauth2_server_config(const std::string&) const;
	oauth2_server_config::ptr_type get_oauth2_server_config_for_callback(const std::string&) const;

	const std::string& get_poppo_url(void) const { return poppo_url_; }
	const neosystem::http::url_info& get_poppo_url_info(void) const { return poppo_url_info_; }

	bool is_session_save_enabled(void) const { return (session_redis_server_ == "") ? false : true; }
	const std::string& get_session_redis_server(void) const { return session_redis_server_; }
	const std::string& get_session_redis_server_port(void) const { return session_redis_server_port_; }

	const std::string& get_login_success_redirect(void) const { return login_success_redirect_; }
	const std::string& get_no_login_redirect(void) const { return no_login_redirect_; }

	std::size_t get_cache_size(void) const { return cache_size_; }
	std::size_t get_streambuf_cache_size(void) const { return streambuf_cache_size_; }

	const std::string& get_cookie_domain(void) const { return cookie_domain_; }
	bool is_enable_cookie_secure(void) const { return enable_cookie_secure_; }

	const std::string& get_csrf_cookie_name(void) const { return csrf_cookie_name_; }
	const std::string& get_csrf_header_name(void) const { return csrf_header_name_; }

	int get_session_timeout_minutes(void) const { return session_timeout_minutes_; }

	bool get_enable_http2(void) const { return enable_http2_; }
	bool get_enable_access_log(void) const { return enable_access_log_; }
	bool get_enable_auth_history(void) const { return enable_auth_history_; }

	const std::string& get_logout_path(void) const { return logout_path_; }
};

std::ostream& operator<<(std::ostream&, const config&);

}
}

#endif
