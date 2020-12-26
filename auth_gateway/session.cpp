#include "session.hpp"
#include "common.hpp"
#include "json_reader.hpp"
#include "json_writer.hpp"


namespace poppo {
namespace auth_gateway {

session::session(void) : last_access_time_(std::chrono::system_clock::now()) {
}

session_ptr_type session::create(void) {
	return std::make_shared<session>();
}

session_ptr_type session::create_from_string(const std::string& str) {
	auto p = std::make_shared<session>();
	std::stringstream stream(str);
	try {
		boost::property_tree::ptree pt;
		json::json_read(stream, pt);
		p->external_id_ = pt.get("external_id", "");
		p->state_ = pt.get("state", "");
		p->request_token_ = pt.get("request_token", "");
		p->poppo_id_ = pt.get("poppo_id", "");
		p->csrf_token_ = pt.get("csrf_token", "");
	} catch (const json::parser_error&) {
		std::cerr << S_ << "Invalid json: " << str << std::endl;
	}
	return p;
}

void session::set_request_token(const std::string& s) {
	write_lock lock(mutex_);
	request_token_ = s;
	return;
}

std::string session::get_request_token(void) const {
	read_lock lock(mutex_);
	return request_token_;
}

void session::set_access_token(const std::string& s) {
	write_lock lock(mutex_);
	access_token_ = s;
	return;
}

std::string session::get_access_token(void) const {
	read_lock lock(mutex_);
	return access_token_;
}

void session::set_external_id(const std::string& s) {
	write_lock lock(mutex_);
	external_id_ = s;
	return;
}

std::string session::get_external_id(void) const {
	read_lock lock(mutex_);
	return external_id_;
}

void session::set_poppo_id(const std::string& s) {
	write_lock lock(mutex_);
	poppo_id_ = s;
	return;
}

std::string session::get_poppo_id(void) const {
	read_lock lock(mutex_);
	return poppo_id_;
}

void session::set_oauth1_config(const oauth1_server_config::ptr_type& c) {
	write_lock lock(mutex_);
	oauth1_config_ = c;
	return;
}

oauth1_server_config::ptr_type session::get_oauth1_config(void) const {
	read_lock lock(mutex_);
	return oauth1_config_;
}

void session::set_csrf_token(const std::string& s) {
	write_lock lock(mutex_);
	csrf_token_ = s;
	return;
}

std::string session::get_csrf_token(void) const {
	read_lock lock(mutex_);
	return csrf_token_;
}

void session::set_state(const std::string& s) {
	write_lock lock(mutex_);
	state_ = s;
	return;
}

std::string session::get_state(void) const {
	read_lock lock(mutex_);
	return state_;
}

void session::update_last_access_time(void) {
	write_lock lock(mutex_);
	last_access_time_ = std::chrono::system_clock::now();
	return;
}

void session::to_string(std::string& value) const {
	read_lock lock(mutex_);

	auto req = json::object::create();
	req->add("external_id", external_id_);
	req->add("state", state_);
	req->add("request_token", request_token_);
	req->add("poppo_id", poppo_id_);
	req->add("csrf_token", csrf_token_);

	std::stringstream stream;
	stream << (*req);
	value = stream.str();
	return;
}

}
}
