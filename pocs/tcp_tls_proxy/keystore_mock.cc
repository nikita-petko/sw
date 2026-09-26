// PoC: mock/instrument the public-key-store service (34.78.88.218:27015)
// connection sequence: the pre-TLS plaintext handshake (see
// plaintext_handshake_sim.cc) followed by a real TLS 1.2 session, with
// optional SSLKEYLOGFILE support so a simultaneous packet capture can be
// decrypted in Wireshark.
//
// Server mode terminates TLS locally with an ephemeral, self-signed
// EC (P-256) certificate so this can be pointed at by a test client without
// needing Ubisoft's private key. Client mode performs a real TLS handshake
// against any host (including the real public-key-store service); because
// the client independently derives the session secrets during a normal
// ECDHE handshake, SSLKEYLOGFILE works there too without needing the
// server's cooperation or private key.
//
// SSLKEYLOGFILE follows the standard NSS Key Log Format used by Firefox,
// Chrome, curl, and Wireshark: if the environment variable is set, lines are
// appended to that file every time OpenSSL derives new session secrets.

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

std::vector<uint8_t> parse_hex(const std::string& text) {
    std::vector<uint8_t> bytes;
    std::string digits;
    for (char c : text) {
        if (isxdigit(static_cast<unsigned char>(c))) digits.push_back(c);
    }
    for (size_t i = 0; i + 1 < digits.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(digits.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

// --- SSLKEYLOGFILE support -------------------------------------------------

FILE* g_keylog_file = nullptr;

void keylog_callback(const SSL* /*ssl*/, const char* line) {
    if (g_keylog_file == nullptr) return;
    std::fprintf(g_keylog_file, "%s\n", line);
    std::fflush(g_keylog_file);
}

// Opens the file named by SSLKEYLOGFILE (if set) and registers the OpenSSL
// keylog callback on ctx. Returns false only on a hard error (env var set
// but file could not be opened); returns true (with keylogging disabled) if
// the env var is simply absent.
bool maybe_enable_ssl_keylog(SSL_CTX* ctx) {
    const char* path = std::getenv("SSLKEYLOGFILE");
    if (path == nullptr || path[0] == '\0') {
        std::cout << "[INFO] SSLKEYLOGFILE is not set; TLS session secrets will not be logged.\n";
        return true;
    }

    g_keylog_file = std::fopen(path, "a");
    if (g_keylog_file == nullptr) {
        std::cerr << "[ERROR] SSLKEYLOGFILE is set to '" << path << "' but the file could not be opened for append.\n";
        return false;
    }

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    std::cout << "[INFO] SSLKEYLOGFILE detected: appending TLS session secrets to '" << path << "'.\n";
    return true;
}

void log_openssl_errors(const char* context) {
    unsigned long err;
    bool any = false;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OPENSSL] " << context << ": " << buf << "\n";
        any = true;
    }
    if (!any) {
        std::cerr << "[OPENSSL] " << context << ": no error queued (likely a transport-level failure; see socket error below)\n";
    }
}

const char* ssl_error_symbolic_name(int code) {
    switch (code) {
        case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
        default: return "SSL_ERROR_UNKNOWN";
    }
}

// Prints the OpenSSL error queue plus, for SSL_ERROR_SYSCALL (the common case
// when the peer resets/closes the TCP connection mid-handshake), the
// underlying Winsock error in human-readable form.
void log_ssl_error(SSL* ssl, int ret, const char* context) {
    int ssl_err = SSL_get_error(ssl, ret);
    std::cerr << "[OPENSSL] " << context << " failed: " << ssl_error_symbolic_name(ssl_err) << " (" << ssl_err << ")\n";
    log_openssl_errors(context);
    if (ssl_err == SSL_ERROR_SYSCALL) {
        std::cerr << "[OPENSSL] " << context << ": underlying socket error: " << wsa_error_string(WSAGetLastError()) << "\n";
    }
}

// --- Ephemeral self-signed EC certificate (server mode only) --------------
// Mirrors the ECDHE-ECDSA cipher suite (0xC02C) observed in the real
// public-key-store TLS handshake; the game client is never expected to trust
// this certificate, it exists only so a local test client can complete a
// real TLS handshake against this mock.

struct GeneratedIdentity {
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;

    ~GeneratedIdentity() {
        if (cert != nullptr) X509_free(cert);
        if (pkey != nullptr) EVP_PKEY_free(pkey);
    }
};

bool generate_self_signed_identity(GeneratedIdentity& identity) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (pctx == nullptr || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &identity.pkey) <= 0) {
        if (pctx != nullptr) EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    identity.cert = X509_new();
    X509_set_version(identity.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(identity.cert), 1);
    X509_gmtime_adj(X509_get_notBefore(identity.cert), 0);
    X509_gmtime_adj(X509_get_notAfter(identity.cert), 60L * 60 * 24 * 365);
    X509_set_pubkey(identity.cert, identity.pkey);

    X509_NAME* name = X509_get_subject_name(identity.cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("keystore-mock.local"), -1, -1, 0);
    X509_set_issuer_name(identity.cert, name);

    return X509_sign(identity.cert, identity.pkey, EVP_sha256()) != 0;
}

// --- Shared pre-TLS plaintext handshake replay -----------------------------
// Observed against the real public-key-store host (34.78.88.218:27015) as
// exactly 3 PSH segments, with no leading client probe: the server sends the
// 36-byte challenge unprompted immediately after the TCP handshake, the
// client replies with the 8-byte upgrade command, and the server replies
// with the 3-byte confirmation. See
// research/division1_networking_architecture_pcap_analysis.md Section 4.

bool client_pretls_handshake(SOCKET sock) {
    uint8_t server_challenge[36] = {0};
    std::cout << "[SERVER -> CLIENT] Waiting for 36-byte server challenge...\n";
    if (!recv_exact(sock, server_challenge, sizeof(server_challenge))) return false;
    print_hex_dump("Server Challenge Frame", server_challenge, sizeof(server_challenge));

    const uint8_t upgrade_req[8] = {0x0E, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
    std::cout << "[CLIENT -> SERVER] Sending 8-byte TLS upgrade request command...\n";
    if (!send_exact(sock, upgrade_req, sizeof(upgrade_req))) return false;

    uint8_t server_confirm[3] = {0};
    std::cout << "[SERVER -> CLIENT] Waiting for 3-byte server confirmation...\n";
    if (!recv_exact(sock, server_confirm, sizeof(server_confirm))) return false;
    print_hex_dump("Server Confirmation Signal", server_confirm, sizeof(server_confirm));
    return true;
}

bool server_pretls_handshake(SOCKET client_sock) {
    uint8_t server_challenge[36] = {0x46, 0x01, 0x02, 0x20};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (size_t i = 4; i < sizeof(server_challenge); ++i) {
        server_challenge[i] = static_cast<uint8_t>(dis(gen));
    }
    std::cout << "[SERVER -> CLIENT] Sending 36-byte server challenge frame...\n";
    if (!send_exact(client_sock, server_challenge, sizeof(server_challenge))) return false;

    uint8_t upgrade_req[8] = {0};
    std::cout << "[CLIENT -> SERVER] Waiting for 8-byte TLS upgrade request command...\n";
    if (!recv_exact(client_sock, upgrade_req, sizeof(upgrade_req))) return false;
    print_hex_dump("Client TLS Upgrade Command", upgrade_req, sizeof(upgrade_req));

    const uint8_t server_confirm[3] = {0x04, 0x00, 0x01};
    std::cout << "[SERVER -> CLIENT] Sending 3-byte server confirmation signal...\n";
    return send_exact(client_sock, server_confirm, sizeof(server_confirm));
}

// --- Modes ------------------------------------------------------------------

int run_client(const std::string& host, uint16_t port, bool skip_pretls, const std::vector<uint8_t>& send_hex) {
    WinsockScope wsa;
    if (!wsa.initialized) {
        std::cerr << "[ERROR] Failed to initialize Winsock.\n";
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Failed to create socket: " << wsa_error_string(WSAGetLastError()) << "\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "[ERROR] Invalid IP address format: " << host << "\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[CLIENT] Connecting to " << host << ":" << port << "...\n";
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection failed (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[CLIENT] Connected to server. Setting TCP_NODELAY...\n";
    int flag = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Failed to set TCP_NODELAY: " << wsa_error_string(WSAGetLastError()) << "\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[CLIENT] TCP_NODELAY set successfully.\n";

    if (!skip_pretls && !client_pretls_handshake(sock)) {
        closesocket(sock);
        return 1;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);  // research tool: not validating server identity
    if (!maybe_enable_ssl_keylog(ctx)) {
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(sock));  // Windows SOCKET truncated to int; fine for real socket handles

    std::cout << "[CLIENT] Starting TLS handshake...\n";
    int connect_ret = SSL_connect(ssl);
    if (connect_ret != 1) {
        log_ssl_error(ssl, connect_ret, "SSL_connect");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 1;
    }
    std::cout << "[SUCCESS] TLS handshake complete. Cipher: " << SSL_get_cipher(ssl)
              << ", Protocol: " << SSL_get_version(ssl) << "\n";

    if (!send_hex.empty()) {
        std::cout << "[CLIENT -> SERVER] Sending scripted TLS application payload...\n";
        print_hex_dump("Application Payload", send_hex.data(), send_hex.size());
        SSL_write(ssl, send_hex.data(), static_cast<int>(send_hex.size()));
    }

    uint8_t buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0) {
        print_hex_dump("Decrypted Application Data From Server", buf, static_cast<size_t>(n));
    } else {
        std::cout << "[INFO] No further application data received (connection closed or idle).\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);
    return 0;
}

int run_server(const std::string& host, uint16_t port, bool skip_pretls, const std::vector<uint8_t>& send_hex) {
    WinsockScope wsa;
    if (!wsa.initialized) {
        std::cerr << "[ERROR] Failed to initialize Winsock.\n";
        return 1;
    }

    GeneratedIdentity identity;
    if (!generate_self_signed_identity(identity)) {
        log_openssl_errors("generate_self_signed_identity");
        return 1;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");
    SSL_CTX_use_certificate(ctx, identity.cert);
    SSL_CTX_use_PrivateKey(ctx, identity.pkey);
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[ERROR] Generated certificate/private key mismatch.\n";
        SSL_CTX_free(ctx);
        return 1;
    }
    if (!maybe_enable_ssl_keylog(ctx)) {
        SSL_CTX_free(ctx);
        return 1;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Failed to create listen socket: " << wsa_error_string(WSAGetLastError()) << "\n";
        SSL_CTX_free(ctx);
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
        SSL_CTX_free(ctx);
        return 1;
    }
    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR ||
        listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind/listen failed on " << host << ":" << port << " (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "[SERVER] Mock public-key-store listening on " << host << ":" << port << "...\n";
    sockaddr_in client_addr{};
    int client_addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Accept failed (" << wsa_error_string(WSAGetLastError()) << ")\n";
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "[SERVER] Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    if (!skip_pretls && !server_pretls_handshake(client_sock)) {
        closesocket(client_sock);
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(client_sock));

    std::cout << "[SERVER] Starting TLS handshake...\n";
    int accept_ret = SSL_accept(ssl);
    if (accept_ret != 1) {
        log_ssl_error(ssl, accept_ret, "SSL_accept");
        SSL_free(ssl);
        closesocket(client_sock);
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    std::cout << "[SUCCESS] TLS handshake complete. Cipher: " << SSL_get_cipher(ssl)
              << ", Protocol: " << SSL_get_version(ssl) << "\n";

    uint8_t buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0) {
        print_hex_dump("Decrypted Application Data From Client", buf, static_cast<size_t>(n));
    } else {
        std::cout << "[INFO] No application data received from client.\n";
    }

    if (!send_hex.empty()) {
        std::cout << "[SERVER -> CLIENT] Sending scripted TLS application payload...\n";
        print_hex_dump("Application Payload", send_hex.data(), send_hex.size());
        SSL_write(ssl, send_hex.data(), static_cast<int>(send_hex.size()));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client_sock);
    closesocket(listen_sock);
    SSL_CTX_free(ctx);
    return 0;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Mocks/instruments the public-key-store pre-TLS handshake + TLS 1.2\n"
              << "session (see research/division1_networking_architecture_pcap_analysis.md).\n\n"
              << "Options:\n"
              << "  -m, --mode <client|server>   Execution mode (default: client)\n"
              << "  -h, --host <ip_address>      IP address to connect or bind (default: 127.0.0.1)\n"
              << "  -p, --port <port_number>     Port number (default: 27015)\n"
              << "  --skip-pretls                Skip the plaintext pre-TLS handshake, go straight to TLS\n"
              << "  --send-hex <hex bytes>       Send these bytes as TLS application data after the handshake\n"
              << "  --help                       Show this help message\n\n"
              << "If the SSLKEYLOGFILE environment variable is set, TLS session secrets are\n"
              << "appended to that file in NSS Key Log Format, decryptable in Wireshark.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string mode = "client";
    std::string host = "127.0.0.1";
    uint16_t port = 27015;
    bool skip_pretls = false;
    std::vector<uint8_t> send_hex;

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
        } else if (arg == "--skip-pretls") {
            skip_pretls = true;
        } else if (arg == "--send-hex" && i + 1 < argc) {
            send_hex = parse_hex(argv[++i]);
        }
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (mode == "client") {
        return run_client(host, port, skip_pretls, send_hex);
    } else if (mode == "server") {
        return run_server(host, port, skip_pretls, send_hex);
    } else {
        std::cerr << "[ERROR] Invalid mode: " << mode << " (must be 'client' or 'server')\n";
        print_usage(argv[0]);
        return 1;
    }
}
