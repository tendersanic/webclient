#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ip/udp.hpp>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <array>
#include <string>
#include <sstream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

// --- Helper functions ---
uint32_t random_transaction_id() {
    return rand() & 0xFFFFFFFF;
}

std::array<unsigned char, 20> generate_peer_id() {
    std::array<unsigned char, 20> peer_id;
    std::string prefix = "-PC0001-";
    for (int i = 0; i < 8; ++i) peer_id[i] = prefix[i];
    for (int i = 8; i < 20; ++i) peer_id[i] = '0' + rand() % 10;
    return peer_id;
}

// Convert hex string to byte array
std::array<unsigned char, 20> hex_to_bytes(const std::string &hex) {
    std::array<unsigned char, 20> bytes{};
    for (int i = 0; i < 20; ++i)
        bytes[i] = std::stoi(hex.substr(i*2, 2), nullptr, 16);
    return bytes;
}

// --- Tracker UDP request ---
std::string query_tracker(const std::string &tracker_host, const std::string &info_hash_hex) {
    asio::io_context io_context;
    udp::socket socket(io_context);
    socket.open(udp::v4());

    udp::resolver resolver(io_context);
    udp::endpoint tracker_endpoint = *resolver.resolve(udp::v4(), tracker_host, "1337").begin();

    // --- Connect request ---
    std::vector<unsigned char> connect_request(16);
    uint64_t protocol_id = 0x41727101980;
    uint32_t action = 0;
    uint32_t transaction_id = random_transaction_id();

    for (int i = 0; i < 8; i++) connect_request[i] = (protocol_id >> (56 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) connect_request[8+i] = (action >> (24 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) connect_request[12+i] = (transaction_id >> (24 - i*8)) & 0xFF;

    socket.send_to(asio::buffer(connect_request), tracker_endpoint);

    std::vector<unsigned char> response(16);
    udp::endpoint sender_endpoint;
    size_t len = socket.receive_from(asio::buffer(response), sender_endpoint);

    uint64_t connection_id = 0;
    for (int i = 0; i < 8; i++) connection_id = (connection_id << 8) | response[8 + i];

    // --- Announce request ---
    std::vector<unsigned char> announce_request(98);
    for (int i = 0; i < 8; i++) announce_request[i] = (connection_id >> (56 - i*8)) & 0xFF;
    action = 1;
    for (int i = 0; i < 4; i++) announce_request[8+i] = (action >> (24 - i*8)) & 0xFF;
    transaction_id = random_transaction_id();
    for (int i = 0; i < 4; i++) announce_request[12+i] = (transaction_id >> (24 - i*8)) & 0xFF;

    auto info_hash_bytes = hex_to_bytes(info_hash_hex);
    for (int i = 0; i < 20; ++i) announce_request[16+i] = info_hash_bytes[i];

    auto peer_id = generate_peer_id();
    for (int i = 0; i < 20; ++i) announce_request[36+i] = peer_id[i];

    uint64_t downloaded = 0, left = 129241752, uploaded = 0;
    for (int i = 0; i < 8; i++) {
        announce_request[56+i] = (downloaded >> (56 - i*8)) & 0xFF;
        announce_request[64+i] = (left >> (56 - i*8)) & 0xFF;
        announce_request[72+i] = (uploaded >> (56 - i*8)) & 0xFF;
    }

    for (int i = 0; i < 4; i++) announce_request[80+i] = (1 >> (24 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) announce_request[84+i] = 0;
    uint32_t key = rand();
    for (int i = 0; i < 4; i++) announce_request[88+i] = (key >> (24 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) announce_request[92+i] = (0xFFFFFFFF >> (24 - i*8)) & 0xFF;
    uint16_t port = 6881;
    announce_request[96] = (port >> 8) & 0xFF;
    announce_request[97] = port & 0xFF;

    socket.send_to(asio::buffer(announce_request), tracker_endpoint);

    std::vector<unsigned char> announce_response(1024);
    len = socket.receive_from(asio::buffer(announce_response), sender_endpoint);

    std::ostringstream oss;
    oss << "Peers:\n";
    for (size_t i = 20; i+6 <= len; i += 6) {
        oss << (int)announce_response[i] << "."
            << (int)announce_response[i+1] << "."
            << (int)announce_response[i+2] << "."
            << (int)announce_response[i+3] << ":"
            << ((announce_response[i+4] << 8) | announce_response[i+5]) << "\n";
    }

    return oss.str();
}

// --- HTTP server ---
// --- HTTP server ---
void run_server(short port) {
    asio::io_context ioc{1};
    tcp::acceptor acceptor{ioc, {tcp::v4(), port}};

    for (;;) {
        tcp::socket socket{ioc};
        acceptor.accept(socket);

        try {
            // Declare the Beast buffer BEFORE reading
            beast::flat_buffer buffer;

            // Read HTTP request
            http::request<http::string_body> req;
            http::read(socket, buffer, req);

            // Parse query: /?tracker=tracker.opentrackr.org&infohash=ce25ee59735f9f971e1216fb467fa9578400997d
            std::string tracker_host, info_hash;
            std::string query = req.target().to_string();

            size_t t_pos = query.find("tracker=");
            size_t i_pos = query.find("infohash=");
            if (t_pos != std::string::npos && i_pos != std::string::npos) {
                tracker_host = query.substr(t_pos + 8, query.find('&', t_pos) - (t_pos + 8));
                info_hash = query.substr(i_pos + 9);
            }

            std::string body = "Invalid parameters";
            if (!tracker_host.empty() && !info_hash.empty()) {
                body = query_tracker(tracker_host, info_hash);
            }

            // Build HTTP response
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "text/plain");
            res.body() = body;
            res.prepare_payload();

            // Send response
            http::write(socket, res);
        } catch (std::exception &e) {
            std::cerr << "Error handling request: " << e.what() << std::endl;
        }
    }
}



int main() {
    srand(time(nullptr));
    run_server(8080);
}
