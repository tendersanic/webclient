#include <boost/asio.hpp>
#include <iostream>
#include <array>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <bitset>

using boost::asio::ip::tcp;

int main() {
    srand(time(nullptr));

    std::string peer_ip = "83.56.202.99";
    uint16_t peer_port = 28280;

    // info hash (20 bytes, hex-encoded)
    std::string info_hash_hex = "08ada5a7a6183aae1e09d831df6748d566095a10";

    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);

        tcp::endpoint endpoint(boost::asio::ip::make_address(peer_ip), peer_port);
        socket.connect(endpoint);
        std::cout << "Connected to peer " << peer_ip << ":" << peer_port << "\n";

        // --- Build handshake ---
        std::array<unsigned char, 68> handshake{};
        std::string pstr = "BitTorrent protocol";
        handshake[0] = static_cast<unsigned char>(pstr.size());

        // pstr
        for (size_t i = 0; i < pstr.size(); ++i)
            handshake[1 + i] = static_cast<unsigned char>(pstr[i]);

        // reserved bytes (8 bytes) — keep zeros
        for (int i = 0; i < 8; ++i)
            handshake[20 + i] = 0x00;

        // info_hash (convert hex to bytes)
        for (int i = 0; i < 20; ++i)
            handshake[28 + i] = static_cast<unsigned char>(
                std::stoi(info_hash_hex.substr(i * 2, 2), nullptr, 16));

        // peer_id (-BA0001-XXXXXXXXXXXX)
        std::string peer_id = "-BA0001-";
        for (int i = 0; i < 12; ++i)
            peer_id += '0' + rand() % 10;

        for (int i = 0; i < 20; ++i)
            handshake[48 + i] = static_cast<unsigned char>(peer_id[i]);

        // Send handshake
        boost::asio::write(socket, boost::asio::buffer(handshake));
        std::cout << "Handshake sent\n";

        // Receive exactly 68 bytes for handshake
        std::array<unsigned char, 68> peer_handshake{};
        size_t bytes_received = 0;
        while (bytes_received < 68) {
            bytes_received += socket.read_some(
                boost::asio::buffer(peer_handshake.data() + bytes_received, 68 - bytes_received));
        }

        std::cout << "Received handshake (" << bytes_received << " bytes):\n";
        for (size_t i = 0; i < bytes_received; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(peer_handshake[i]) << " ";
            if ((i + 1) % 16 == 0) std::cout << "\n";
        }
        std::cout << "\n";


        // --- Read next message --- (bitfield)
        std::array<unsigned char, 4096> msg_buffer; // big enough buffer
        size_t msg_len = socket.read_some(boost::asio::buffer(msg_buffer));

        if (msg_len < 5) {
            std::cerr << "Message too short\n";
            return 1;
        }

        // First 4 bytes: length prefix
        uint32_t length = (msg_buffer[0] << 24) | (msg_buffer[1] << 16) |
                        (msg_buffer[2] << 8) | msg_buffer[3];

        unsigned char msg_id = msg_buffer[4];
        std::cout << "Message ID: " << (int)msg_id << ", length: " << length << "\n";

        if (msg_id == 5) { // bitfield
            std::cout << "Bitfield (" << (length - 1) << " bytes): ";
            for (size_t i = 5; i < 4 + length; ++i) {
                std::cout << std::bitset<8>(msg_buffer[i]) << " ";
            }
            std::cout << "\n";
        } else {
            std::cout << "Not a bitfield message.\n";
        }


    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}
