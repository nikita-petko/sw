#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

void print_hex_dump(const std::string_view label, const uint8_t* data, size_t length) {
    std::cout << "[DUMP] " << label << " (" << length << " bytes):\n  ";
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0 && i + 1 < length) {
            std::cout << "\n  ";
        }
    }
    std::cout << std::dec << "\n";
}

// Common WSA error codes that FormatMessage's system text doesn't always name explicitly.
const char* wsa_symbolic_name(int code) {
    switch (code) {
        case WSAECONNRESET: return "WSAECONNRESET";
        case WSAECONNREFUSED: return "WSAECONNREFUSED";
        case WSAECONNABORTED: return "WSAECONNABORTED";
        case WSAETIMEDOUT: return "WSAETIMEDOUT";
        case WSAENETUNREACH: return "WSAENETUNREACH";
        case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH";
        case WSAEADDRINUSE: return "WSAEADDRINUSE";
        case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
        case WSAENOTCONN: return "WSAENOTCONN";
        case WSAEWOULDBLOCK: return "WSAEWOULDBLOCK";
        case WSAEINVAL: return "WSAEINVAL";
        case WSAEACCES: return "WSAEACCES";
        case WSAEAFNOSUPPORT: return "WSAEAFNOSUPPORT";
        case WSAENETDOWN: return "WSAENETDOWN";
        case WSAESHUTDOWN: return "WSAESHUTDOWN";
        default: return nullptr;
    }
}

// Formats a Winsock error code as "<code> (<SYMBOLIC_NAME>: <system message>)".
std::string wsa_error_string(int code) {
    char* system_msg = nullptr;
    DWORD len = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                nullptr, static_cast<DWORD>(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                reinterpret_cast<LPSTR>(&system_msg), 0, nullptr);
    std::string text = "unknown error";
    if (len > 0 && system_msg != nullptr) {
        text.assign(system_msg, len);
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    }
    if (system_msg != nullptr) LocalFree(system_msg);

    const char* symbolic = wsa_symbolic_name(code);
    std::string result = std::to_string(code) + " (";
    if (symbolic != nullptr) result += std::string(symbolic) + ": ";
    result += text + ")";
    return result;
}

struct WinsockScope {
    WSADATA wsa_data{};
    bool initialized = false;

    WinsockScope() {
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0) {
            initialized = true;
        }
    }

    ~WinsockScope() {
        if (initialized) {
            WSACleanup();
        }
    }
};

bool send_exact(SOCKET sock, const uint8_t* buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        int bytes_sent = send(sock, reinterpret_cast<const char*>(buffer + total_sent),
                              static_cast<int>(length - total_sent), 0);
        if (bytes_sent <= 0) {
            std::cerr << "[ERROR] send failed with socket error: " << wsa_error_string(WSAGetLastError()) << "\n";
            return false;
        }
        total_sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

bool recv_exact(SOCKET sock, uint8_t* buffer, size_t length) {
    size_t total_recvd = 0;
    while (total_recvd < length) {
        int bytes_recvd = recv(sock, reinterpret_cast<char*>(buffer + total_recvd),
                              static_cast<int>(length - total_recvd), 0);
        if (bytes_recvd <= 0) {
            std::cerr << "[ERROR] recv failed or connection closed with error: " << wsa_error_string(WSAGetLastError()) << "\n";
            return false;
        }
        total_recvd += static_cast<size_t>(bytes_recvd);
    }
    return true;
}

int run_client(const std::string& host, uint16_t port) {
    WinsockScope wsa;
    if (!wsa.initialized) {
        std::cerr << "[ERROR] Failed to initialize Winsock.\n";
        return 1;
    }

    std::cout << "[CLIENT] Connecting to " << host << ":" << port << "...\n";

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Failed to create socket: " << wsa_error_string(WSAGetLastError()) << "\n";
        return 1;
    }

    BOOL nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "[ERROR] Invalid IP address format: " << host << "\n";
        closesocket(sock);
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection failed to " << host << ":" << port << " (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[CLIENT] Connected to server.\n";

    // Step 1: Send 6-byte null probe (Packet 3)
    const uint8_t client_probe[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::cout << "[CLIENT -> SERVER] Sending 6-byte connection probe (Packet 3)...\n";
    print_hex_dump("Client Probe", client_probe, sizeof(client_probe));
    if (!send_exact(sock, client_probe, sizeof(client_probe))) {
        closesocket(sock);
        return 1;
    }

    // Step 2: Receive 36-byte Server Challenge (Packet 4)
    uint8_t server_challenge[36] = {0};
    std::cout << "[SERVER -> CLIENT] Waiting for 36-byte server challenge (Packet 4)...\n";
    if (!recv_exact(sock, server_challenge, sizeof(server_challenge))) {
        closesocket(sock);
        return 1;
    }
    print_hex_dump("Server Challenge Frame", server_challenge, sizeof(server_challenge));

    // Verify header opcode 0x46 and salt length 0x20
    if (server_challenge[0] != 0x46 || server_challenge[3] != 0x20) {
        std::cerr << "[WARNING] Server challenge header differs from expected template (Opcode=0x"
                  << std::hex << static_cast<int>(server_challenge[0]) << ", Len=0x"
                  << static_cast<int>(server_challenge[3]) << std::dec << ")\n";
    }

    // Step 3: Send 8-byte TLS Upgrade Request Command (Packet 6)
    // Note: Packet 5 in pcap captures was a TCP-level retransmission/dup-ACK packet,
    // not a separate application message. Sending a second 6-byte null probe causes
    // the server to reset the connection (WSAECONNRESET).
    const uint8_t upgrade_req[8] = {0x0E, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
    std::cout << "[CLIENT -> SERVER] Sending 8-byte TLS upgrade request command (Packet 6)...\n";
    print_hex_dump("Client TLS Upgrade Command", upgrade_req, sizeof(upgrade_req));
    if (!send_exact(sock, upgrade_req, sizeof(upgrade_req))) {
        closesocket(sock);
        return 1;
    }

    // Step 4: Receive 3-byte Server Confirmation Signal (Packet 8)
    uint8_t server_confirm[3] = {0};
    std::cout << "[SERVER -> CLIENT] Waiting for 3-byte server confirmation (Packet 8)...\n";
    if (!recv_exact(sock, server_confirm, sizeof(server_confirm))) {
        closesocket(sock);
        return 1;
    }
    print_hex_dump("Server Confirmation Signal", server_confirm, sizeof(server_confirm));

    if (server_confirm[0] == 0x04 && server_confirm[2] == 0x01) {
        std::cout << "[SUCCESS] Pre-TLS Plaintext Handshake simulation completed successfully!\n";
        std::cout << "[INFO] Socket is now ready for TLS ClientHello negotiation.\n";
    } else {
        std::cerr << "[WARNING] Server confirmation status unexpected.\n";
    }

    closesocket(sock);
    return 0;
}

int run_server(const std::string& host, uint16_t port) {
    WinsockScope wsa;
    if (!wsa.initialized) {
        std::cerr << "[ERROR] Failed to initialize Winsock.\n";
        return 1;
    }

    std::cout << "[SERVER] Binding listener on " << host << ":" << port << "...\n";

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Failed to create listen socket: " << wsa_error_string(WSAGetLastError()) << "\n";
        return 1;
    }

    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &bind_addr.sin_addr) <= 0) {
        std::cerr << "[ERROR] Invalid IP address format: " << host << "\n";
        closesocket(listen_sock);
        return 1;
    }

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed on " << host << ":" << port << " (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(listen_sock);
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Listen failed (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(listen_sock);
        return 1;
    }

    std::cout << "[SERVER] Waiting for incoming client connection...\n";

    sockaddr_in client_addr{};
    int client_addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Accept failed (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(listen_sock);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "[SERVER] Accepted client connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    // Step 1: Receive 6-byte null probe (Packet 3)
    uint8_t client_probe[6] = {0};
    std::cout << "[CLIENT -> SERVER] Waiting for 6-byte connection probe (Packet 3)...\n";
    if (!recv_exact(client_sock, client_probe, sizeof(client_probe))) {
        closesocket(client_sock);
        closesocket(listen_sock);
        return 1;
    }
    print_hex_dump("Client Connection Probe", client_probe, sizeof(client_probe));

    // Step 2: Send 36-byte Server Challenge Frame (Packet 4)
    uint8_t server_challenge[36] = {0x46, 0x01, 0x02, 0x20}; // Opcode 0x46, Ver 0x01, Flags 0x02, Len 0x20 (32 bytes salt)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (size_t i = 4; i < 36; ++i) {
        server_challenge[i] = static_cast<uint8_t>(dis(gen));
    }

    std::cout << "[SERVER -> CLIENT] Sending 36-byte server challenge frame (Packet 4)...\n";
    print_hex_dump("Server Challenge Frame", server_challenge, sizeof(server_challenge));
    if (!send_exact(client_sock, server_challenge, sizeof(server_challenge))) {
        closesocket(client_sock);
        closesocket(listen_sock);
        return 1;
    }

    // Step 3: Receive 8-byte TLS Upgrade Request Command (Packet 6)
    uint8_t upgrade_req[8] = {0};
    std::cout << "[CLIENT -> SERVER] Waiting for 8-byte TLS upgrade request command (Packet 6)...\n";
    if (!recv_exact(client_sock, upgrade_req, sizeof(upgrade_req))) {
        closesocket(client_sock);
        closesocket(listen_sock);
        return 1;
    }
    print_hex_dump("Client TLS Upgrade Command", upgrade_req, sizeof(upgrade_req));

    // Step 4: Send 3-byte Server Confirmation Signal (Packet 8)
    const uint8_t server_confirm[3] = {0x04, 0x00, 0x01};
    std::cout << "[SERVER -> CLIENT] Sending 3-byte server confirmation signal (Packet 8)...\n";
    print_hex_dump("Server Confirmation Signal", server_confirm, sizeof(server_confirm));
    if (!send_exact(client_sock, server_confirm, sizeof(server_confirm))) {
        closesocket(client_sock);
        closesocket(listen_sock);
        return 1;
    }

    std::cout << "[SUCCESS] Server-side Pre-TLS Plaintext Handshake simulation completed successfully!\n";
    std::cout << "[INFO] Socket is now ready for TLS ClientHello negotiation.\n";

    closesocket(client_sock);
    closesocket(listen_sock);
    return 0;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -m, --mode <client|server>  Execution mode (default: client)\n"
              << "  -h, --host <ip_address>     IP address to connect or bind (default: 127.0.0.1)\n"
              << "  -p, --port <port_number>    Port number (default: 55000)\n"
              << "  --help                      Show this help message\n";
}

} // namespace

int main(int argc, char* argv[]) {
    std::string mode = "client";
    std::string host = "127.0.0.1";
    uint16_t port = 55000;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            mode = argv[++i];
        } else if ((arg == "-h" || arg == "--host") && i + 1 < argc) {
            host = argv[++i];
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }

    if (mode == "client") {
        return run_client(host, port);
    } else if (mode == "server") {
        return run_server(host, port);
    } else {
        std::cerr << "[ERROR] Invalid mode: " << mode << " (must be 'client' or 'server')\n";
        print_usage(argv[0]);
        return 1;
    }
}
