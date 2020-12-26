#include <iostream>
#include <chrono>

#include <openssl/hmac.h>

#include "oauth1.hpp"
#include "common.hpp"
#include "config.hpp"


namespace poppo {
namespace auth_gateway {

namespace util = neosystem::util;

void append_authorize_header2(const oauth1_server_config& conf, std::ostream& stream2, const std::string& oauth_verifier, const std::string& oauth_token) {
	std::string nonce;
	util::generate_nonce(nonce);
	std::string key = conf.get_key() + "&" + oauth_token;
	const std::string& consumer_key = conf.get_consumer_key();

	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

	const std::string& request_url = conf.get_access_token_url();
	std::string encoded_request_url;
	util::urlencode(request_url, encoded_request_url);

	std::stringstream param;
	param
		<< "oauth_consumer_key=" << consumer_key << "&"
		<< "oauth_nonce=" << nonce << "&"
		<< "oauth_signature_method=HMAC-SHA1&"
		<< "oauth_timestamp=" << timestamp << "&"
		<< "oauth_token=" << oauth_token << "&"
		<< "oauth_verifier=" << oauth_verifier << "&"
		<< "oauth_version=1.0"
		;
	std::string encoded_param;
	util::urlencode(param.str(), encoded_param);

	std::string data = "POST&" + encoded_request_url + "&" + encoded_param;

	unsigned char res[SHA_DIGEST_LENGTH + 1];
	unsigned int reslen;

	if (!HMAC(EVP_sha1(), key.c_str(), (int) key.size(), (const unsigned char *) data.c_str(), data.size(), res, &reslen)) {
		std::cerr << S_ << "error" << std::endl;
		return;
	}
	std::string signature;
	util::encode_base64(res, reslen, signature);
	std::string encoded_signature;
	util::urlencode(signature, encoded_signature);

	std::stringstream stream;
	stream << "Authorization: OAuth oauth_nonce=\"" << nonce << "\", oauth_token=\"" << oauth_token << "\", ";
	stream << "oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" << timestamp << "\", oauth_verifier=\"" << oauth_verifier << "\", ";
	stream << "oauth_consumer_key=\"" << consumer_key << "\", oauth_signature=\"" << encoded_signature << "\", oauth_version=\"1.0\"";

	stream2 << stream.str() << "\r\n";
	return;
}

void append_authorize_header(const oauth1_server_config& conf, std::ostream& stream2) {
	std::string nonce;
	util::generate_nonce(nonce);
	std::string key = conf.get_key() + "&";
	const std::string& consumer_key = conf.get_consumer_key();

	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

	const std::string& request_url = conf.get_request_token_url();
	std::string encoded_request_url;
	util::urlencode(request_url, encoded_request_url);

	const std::string& callback = conf.get_callback_url();
	std::string encoded_callback;
	util::urlencode(callback, encoded_callback);

	std::stringstream param;
	param
		<< "oauth_callback=" << encoded_callback << "&"
		<< "oauth_consumer_key=" << consumer_key << "&"
		<< "oauth_nonce=" << nonce << "&"
		<< "oauth_signature_method=HMAC-SHA1&"
		<< "oauth_timestamp=" << timestamp << "&"
		<< "oauth_version=1.0"
		;
	std::string encoded_param;
	util::urlencode(param.str(), encoded_param);

	std::string data = "POST&" + encoded_request_url + "&" + encoded_param;

	unsigned char res[SHA_DIGEST_LENGTH + 1];
	unsigned int reslen;

	if (!HMAC(EVP_sha1(), key.c_str(), (int) key.size(), (const unsigned char *) data.c_str(), data.size(), res, &reslen)) {
		std::cerr << S_ << "error" << std::endl;
		return;
	}
	std::string signature;
	util::encode_base64(res, reslen, signature);
	std::string encoded_signature;
	util::urlencode(signature, encoded_signature);

	std::stringstream stream;
	stream << "Authorization: OAuth oauth_nonce=\"" << nonce << "\", oauth_callback=\"" << encoded_callback << "\", ";
	stream << "oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" << timestamp << "\", ";
	stream << "oauth_consumer_key=\"" << consumer_key << "\", oauth_signature=\"" << encoded_signature << "\", oauth_version=\"1.0\"";

	stream2 << stream.str() << "\r\n";
	return;
}

}
}
