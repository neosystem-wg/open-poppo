#include <unordered_map>

#include "http2_static_headers_table.hpp"


namespace neosystem {
namespace http2 {

static std::unordered_map<uint32_t, neosystem::http::header> g_table;


void init_http2_static_headers_table(void) {
	if (!g_table.empty()) return;

	g_table[1] = {":authority", ""};
	g_table[2] = {":method", "GET"};
	g_table[3] = {":method", "POST"};
	g_table[4] = {":path", "/"};
	g_table[5] = {":path", "/index.html"};
	g_table[6] = {":scheme", "http"};
	g_table[7] = {":scheme", "https"};
	g_table[8] = {":status", "200"};
	g_table[9] = {":status", "204"};
	g_table[10] = {":status", "206"};
	g_table[11] = {":status", "304"};
	g_table[12] = {":status", "400"};
	g_table[13] = {":status", "404"};
	g_table[14] = {":status", "500"};
	g_table[15] = {"accept-charset", ""};
	g_table[16] = {"accept-encoding", "gzip, deflate"};
	g_table[17] = {"accept-language", ""};
	g_table[18] = {"accept-ranges", ""};
	g_table[19] = {"accept", ""};
	g_table[20] = {"access-control-allow-origin", ""};
	g_table[21] = {"age", ""};
	g_table[22] = {"allow", ""};
	g_table[23] = {"authorization", ""};
	g_table[24] = {"cache-control", ""};
	g_table[25] = {"content-disposition", ""};
	g_table[26] = {"content-encoding", ""};
	g_table[27] = {"content-language", ""};
	g_table[28] = {"content-length", ""};
	g_table[29] = {"content-location", ""};
	g_table[30] = {"content-range", ""};
	g_table[31] = {"content-type", ""};
	g_table[32] = {"cookie", ""};
	g_table[33] = {"date", ""};
	g_table[34] = {"etag", ""};
	g_table[35] = {"expect", ""};
	g_table[36] = {"expires", ""};
	g_table[37] = {"from", ""};
	g_table[38] = {"host", ""};
	g_table[39] = {"if-match", ""};
	g_table[40] = {"if-modified-since", ""};
	g_table[41] = {"if-none-match", ""};
	g_table[42] = {"if-range", ""};
	g_table[43] = {"if-unmodified-since", ""};
	g_table[44] = {"last-modified", ""};
	g_table[45] = {"link", ""};
	g_table[46] = {"location", ""};
	g_table[47] = {"max-forwards", ""};
	g_table[48] = {"proxy-authenticate", ""};
	g_table[49] = {"proxy-authorization", ""};
	g_table[50] = {"range", ""};
	g_table[51] = {"referer", ""};
	g_table[52] = {"refresh", ""};
	g_table[53] = {"retry-after", ""};
	g_table[54] = {"server", ""};
	g_table[55] = {"set-cookie", ""};
	g_table[56] = {"strict-transport-security", ""};
	g_table[57] = {"transfer-encoding", ""};
	g_table[58] = {"user-agent", ""};
	g_table[59] = {"vary", ""};
	g_table[60] = {"via", ""};
	g_table[61] = {"www-authenticate", ""};
	return;
}

const neosystem::http::header *find_http2_static_headers_table(uint32_t key) {
	auto it = g_table.find(key);
	if (it == g_table.end()) {
		return nullptr;
	}
	return &(it->second);
}

std::size_t get_http2_static_headers_table_size(void) {
	return g_table.size();
}

}
}
