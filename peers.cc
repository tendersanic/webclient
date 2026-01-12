#include <boost/asio.hpp>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <array>

using boost::asio::ip::udp;

// Generate random transaction ID
uint32_t random_transaction_id() {
    return rand() & 0xFFFFFFFF;
}

// Generate peer ID, 20 bytes (e.g., "-PC0001-XXXXXXXXXXXX")
std::array<unsigned char, 20> generate_peer_id() {
    std::array<unsigned char, 20> peer_id;
    std::string prefix = "-PC0001-";
    for (int i = 0; i < 8; ++i) peer_id[i] = prefix[i];
    for (int i = 8; i < 20; ++i) peer_id[i] = '0' + rand() % 10;
    return peer_id;
}

int main() {
    srand(time(nullptr));
    boost::asio::io_context io_context;
    udp::socket socket(io_context);
    socket.open(udp::v4());

    // Resolve tracker hostname
    udp::resolver resolver(io_context);
    udp::endpoint tracker_endpoint = *resolver.resolve(udp::v4(), "tracker.opentrackr.org", "1337").begin();

    // --- Connect Request ---
    std::vector<unsigned char> connect_request(16);
    uint64_t protocol_id = 0x41727101980;
    uint32_t action = 0;
    uint32_t transaction_id = random_transaction_id();

    for (int i = 0; i < 8; i++) connect_request[i] = (protocol_id >> (56 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) connect_request[8+i] = (action >> (24 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) connect_request[12+i] = (transaction_id >> (24 - i*8)) & 0xFF;

    socket.send_to(boost::asio::buffer(connect_request), tracker_endpoint);

    std::vector<unsigned char> response(16);
    udp::endpoint sender_endpoint;
    size_t len = socket.receive_from(boost::asio::buffer(response), sender_endpoint);

    // Parse connection ID
    uint64_t connection_id = 0;
    for (int i = 0; i < 8; i++) connection_id = (connection_id << 8) | response[8 + i];
    std::cout << "Connection ID: " << connection_id << "\n";

    // --- Announce Request ---
    std::vector<unsigned char> announce_request(98);
    for (int i = 0; i < 8; i++) announce_request[i] = (connection_id >> (56 - i*8)) & 0xFF;

    action = 1;
    for (int i = 0; i < 4; i++) announce_request[8+i] = (action >> (24 - i*8)) & 0xFF;

    transaction_id = random_transaction_id();
    for (int i = 0; i < 4; i++) announce_request[12+i] = (transaction_id >> (24 - i*8)) & 0xFF;

    // Info hash magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec&dn=Tears+of+Steel&tr=udp%3A%2F%2Fexplodie.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Ftracker.empire-js.us%3A1337&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=wss%3A%2F%2Ftracker.btorrent.xyz&tr=wss%3A%2F%2Ftracker.fastcast.nz&tr=wss%3A%2F%2Ftracker.openwebtorrent.com&ws=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2F&xs=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2Ftears-of-steel.torrent
    std::string info_hash_hex = "ce25ee59735f9f971e1216fb467fa9578400997d";
    for (int i = 0; i < 20; ++i) announce_request[16+i] = std::stoi(info_hash_hex.substr(i*2, 2), nullptr, 16);

    // Peer ID
    auto peer_id = generate_peer_id();
    for (int i = 0; i < 20; i++) announce_request[36+i] = peer_id[i];

    // downloaded, left, uploaded
    uint64_t downloaded = 0, left = 129241752, uploaded = 0; // total size of your torrent
    for (int i = 0; i < 8; i++) {
        announce_request[56+i] = (downloaded >> (56 - i*8)) & 0xFF;
        announce_request[64+i] = (left >> (56 - i*8)) & 0xFF;
        announce_request[72+i] = (uploaded >> (56 - i*8)) & 0xFF;
    }

    // Event = 1 (started)
    for (int i = 0; i < 4; i++) announce_request[80+i] = (1 >> (24 - i*8)) & 0xFF;

    // IP = 0, key = random, num_want = -1, port = 6881
    for (int i = 0; i < 4; i++) announce_request[84+i] = 0;
    uint32_t key = rand();
    for (int i = 0; i < 4; i++) announce_request[88+i] = (key >> (24 - i*8)) & 0xFF;
    for (int i = 0; i < 4; i++) announce_request[92+i] = (0xFFFFFFFF >> (24 - i*8)) & 0xFF; // -1
    uint16_t port = 6881;
    announce_request[96] = (port >> 8) & 0xFF;
    announce_request[97] = port & 0xFF;

    // Send announce
    socket.send_to(boost::asio::buffer(announce_request), tracker_endpoint);

    std::vector<unsigned char> announce_response(1024);
    len = socket.receive_from(boost::asio::buffer(announce_response), sender_endpoint);

    // Parse peers (each 6 bytes)
    std::cout << "Peers:\n";
    for (size_t i = 20; i+6 <= len; i += 6) {
        std::cout << (int)announce_response[i] << "."
                  << (int)announce_response[i+1] << "."
                  << (int)announce_response[i+2] << "."
                  << (int)announce_response[i+3] << ":"
                  << ((announce_response[i+4] << 8) | announce_response[i+5]) << "\n";
    }

    return 0;
}
