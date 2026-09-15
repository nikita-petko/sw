// PoC Phase 0 test harness for pocs/tls_segment_removal.md.
//
// Runs a TLS 1.2 client or server that continuously exchanges application
// data with its peer in "bursts": each burst is one or more TLS records
// (SSL_write calls) whose ciphertext is accumulated in a memory BIO and then
// flushed to the socket in a single send() call, so that (subject to MTU) a
// burst tends to land on the wire as one coalesced TCP payload containing
// several TLS records back-to-back -- the exact packet shape the segment
// removal filter (see pocs/tls_segment_removal.md Sections 6-8) needs to be
// exercised against.
//
// Each burst independently and randomly picks one of three generation
// patterns so a single run produces the full variety called for by the PoC:
//   - "close":  record count and sizes cluster tightly around a moving
//               baseline (small jitter), simulating a steady stream of
//               similarly-shaped messages.
//   - "random": record count and each record's size are drawn uniformly
//               from the configured range, independent of prior bursts.
//   - "far":    record count and sizes alternate between the two extremes
//               of the configured range, maximizing burst-to-burst and
//               record-to-record variance.
//
// If the SSLKEYLOGFILE environment variable is set, TLS session secrets are
// appended to that file in NSS Key Log Format, decryptable in Wireshark, so
// a simultaneous packet capture can be correlated back to the logged burst
// plan (pattern, record count, per-record size) printed to stdout.

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

std::atomic<bool> g_running{true};

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        g_running.store(false);
        return TRUE;
    }
    return FALSE;
}

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
    WinsockScope() { initialized = WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0; }
    ~WinsockScope() { if (initialized) WSACleanup(); }
};

bool send_exact(SOCKET sock, const uint8_t* buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        int bytes_sent = send(sock, reinterpret_cast<const char*>(buffer + total_sent),
                               static_cast<int>(length - total_sent), 0);
        if (bytes_sent <= 0) {
            std::cerr << "[ERROR] send failed: " << wsa_error_string(WSAGetLastError()) << "\n";
            return false;
        }
        total_sent += static_cast<size_t>(bytes_sent);
    }
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
        std::cerr << "[OPENSSL] " << context << ": no error queued (likely a transport-level failure)\n";
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

void log_ssl_error(SSL* ssl, int ret, const char* context) {
    int ssl_err = SSL_get_error(ssl, ret);
    std::cerr << "[OPENSSL] " << context << " failed: " << ssl_error_symbolic_name(ssl_err) << " (" << ssl_err << ")\n";
    log_openssl_errors(context);
    if (ssl_err == SSL_ERROR_SYSCALL) {
        std::cerr << "[OPENSSL] " << context << ": underlying socket error: " << wsa_error_string(WSAGetLastError()) << "\n";
    }
}

FILE* g_keylog_file = nullptr;

void keylog_callback(const SSL* /*ssl*/, const char* line) {
    if (g_keylog_file == nullptr) return;
    std::fprintf(g_keylog_file, "%s\n", line);
    std::fflush(g_keylog_file);
}

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

// --- Ephemeral self-signed EC certificate (server mode only) ---------------

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
                                reinterpret_cast<const unsigned char*>("segment-removal-traffic-gen.local"), -1, -1, 0);
    X509_set_issuer_name(identity.cert, name);
    return X509_sign(identity.cert, identity.pkey, EVP_sha256()) != 0;
}

// --- BIO-pair plumbing between the SSL object and the raw socket ----------
// SSL reads/writes go through `internal`; `network` is where the resulting
// ciphertext (or, for inbound data, the bytes to be decrypted) is pumped to
// and from the actual socket by hand. This lets several SSL_write calls
// accumulate ciphertext before a single send() flushes them as one payload.

struct BioPair {
    BIO* internal = nullptr;
    BIO* network = nullptr;
};

bool make_bio_pair(BioPair& pair, size_t bufsize = 32 * 1024) {
    return BIO_new_bio_pair(&pair.internal, bufsize, &pair.network, bufsize) == 1;
}

bool flush_network_bio_to_socket(SOCKET sock, BIO* network_bio) {
    uint8_t buf[16384];
    for (;;) {
        int n = BIO_read(network_bio, buf, sizeof(buf));
        if (n <= 0) break;
        if (!send_exact(sock, buf, static_cast<size_t>(n))) return false;
    }
    return true;
}

enum class PumpResult { ok, would_block, closed, error };

PumpResult pump_socket_to_network_bio(SOCKET sock, BIO* network_bio) {
    uint8_t buf[16384];
    int n = recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (n > 0) {
        BIO_write(network_bio, buf, n);
        return PumpResult::ok;
    }
    if (n == 0) return PumpResult::closed;
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK ? PumpResult::would_block : PumpResult::error;
}

bool pump_handshake(SOCKET sock, SSL* ssl, BIO* network_bio, bool is_server) {
    for (;;) {
        int ret = is_server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (!flush_network_bio_to_socket(sock, network_bio)) return false;
        if (ret == 1) return true;

        int err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            log_ssl_error(ssl, ret, is_server ? "SSL_accept" : "SSL_connect");
            return false;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        timeval tv{1, 0};
        if (select(0, &rfds, nullptr, nullptr, &tv) <= 0) continue;
        PumpResult pr = pump_socket_to_network_bio(sock, network_bio);
        if (pr == PumpResult::closed || pr == PumpResult::error) {
            std::cerr << "[ERROR] connection lost during handshake\n";
            return false;
        }
    }
}

// --- Burst plan generation --------------------------------------------------

enum class BurstPattern { close, random_pattern, spread };

const char* pattern_name(BurstPattern p) {
    switch (p) {
        case BurstPattern::close: return "close";
        case BurstPattern::random_pattern: return "random";
        case BurstPattern::spread: return "far";
    }
    return "?";
}

struct GeneratorConfig {
    size_t min_size = 16;
    size_t max_size = 1400;
    int min_records = 1;
    int max_records = 8;
    int interval_min_ms = 200;
    int interval_max_ms = 1000;
    int bursts_per_flush = 2;
    int min_send_gap_ms = 100;
    BurstPattern forced_pattern = BurstPattern::random_pattern;
    bool force_pattern = false;
};

struct GeneratorState {
    std::mt19937 rng;
    int last_count = 3;
};

struct BurstPlan {
    BurstPattern pattern;
    std::vector<size_t> record_sizes;
};

BurstPlan plan_next_burst(GeneratorState& st, const GeneratorConfig& cfg) {
    BurstPattern pattern = cfg.forced_pattern;
    if (!cfg.force_pattern) {
        std::uniform_int_distribution<int> pick(0, 2);
        pattern = static_cast<BurstPattern>(pick(st.rng));
    }

    int count = cfg.min_records;
    switch (pattern) {
        case BurstPattern::close: {
            std::uniform_int_distribution<int> jitter(-1, 1);
            count = std::clamp(st.last_count + jitter(st.rng), cfg.min_records, cfg.max_records);
            break;
        }
        case BurstPattern::spread: {
            std::bernoulli_distribution coin(0.5);
            count = coin(st.rng) ? cfg.min_records : cfg.max_records;
            break;
        }
        case BurstPattern::random_pattern: {
            std::uniform_int_distribution<int> cnt(cfg.min_records, cfg.max_records);
            count = cnt(st.rng);
            break;
        }
    }
    st.last_count = count;

    std::vector<size_t> sizes;
    sizes.reserve(static_cast<size_t>(count));
    if (pattern == BurstPattern::close) {
        std::uniform_int_distribution<size_t> base_dist(cfg.min_size, cfg.max_size);
        size_t base = base_dist(st.rng);
        long long span = static_cast<long long>(std::max<size_t>(1, (cfg.max_size - cfg.min_size) / 20));
        std::uniform_int_distribution<long long> jitter(-span, span);
        for (int i = 0; i < count; ++i) {
            long long v = std::clamp<long long>(static_cast<long long>(base) + jitter(st.rng),
                                                 static_cast<long long>(cfg.min_size), static_cast<long long>(cfg.max_size));
            sizes.push_back(static_cast<size_t>(v));
        }
    } else if (pattern == BurstPattern::spread) {
        std::bernoulli_distribution coin(0.5);
        for (int i = 0; i < count; ++i) sizes.push_back(coin(st.rng) ? cfg.min_size : cfg.max_size);
    } else {
        std::uniform_int_distribution<size_t> dist(cfg.min_size, cfg.max_size);
        for (int i = 0; i < count; ++i) sizes.push_back(dist(st.rng));
    }

    return BurstPlan{pattern, std::move(sizes)};
}

// Encrypts one burst's records into the network BIO without flushing, so the
// caller can accumulate several bursts before a single socket send(). If the
// BIO pair's fixed-size buffer fills up mid-burst, the accumulated ciphertext
// is flushed to the socket immediately so the write can be retried instead of
// failing the whole burst with SSL_ERROR_WANT_WRITE.
bool write_burst(const char* role, SSL* ssl, SOCKET sock, BIO* network_bio, std::mt19937& rng, const BurstPlan& plan,
                  uint64_t burst_index, std::vector<uint8_t>& scratch) {
    std::cout << "[" << role << " TX] burst #" << burst_index << " pattern=" << pattern_name(plan.pattern)
              << " records=" << plan.record_sizes.size() << " sizes=[";
    for (size_t i = 0; i < plan.record_sizes.size(); ++i) {
        std::cout << plan.record_sizes[i] << (i + 1 < plan.record_sizes.size() ? "," : "");
    }
    std::cout << "]\n";

    std::uniform_int_distribution<int> byte_dist(0, 255);
    for (size_t sz : plan.record_sizes) {
        scratch.resize(sz);
        for (auto& b : scratch) b = static_cast<uint8_t>(byte_dist(rng));
        for (;;) {
            int ret = SSL_write(ssl, scratch.data(), static_cast<int>(scratch.size()));
            if (ret > 0) break;
            if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_WRITE) {
                if (!flush_network_bio_to_socket(sock, network_bio)) return false;
                continue;
            }
            log_ssl_error(ssl, ret, "SSL_write");
            return false;
        }
    }
    return true;
}

// Drains every currently-decodable plaintext record; returns false only on a
// fatal (non-WANT_READ) SSL error.
bool drain_ssl_read(SSL* ssl, uint64_t& total_bytes, uint64_t& read_calls) {
    uint8_t buf[16384];
    for (;;) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            total_bytes += static_cast<uint64_t>(n);
            ++read_calls;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ) return true;
        if (err == SSL_ERROR_ZERO_RETURN) return true;  // peer sent close_notify
        log_ssl_error(ssl, n, "SSL_read");
        return false;
    }
}

// --- Connection setup --------------------------------------------------------

bool set_nonblocking(SOCKET sock) {
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
}

int run_loop(const char* role, SOCKET sock, SSL* ssl, BIO* network_bio, const GeneratorConfig& cfg, int duration_seconds) {
    using clock = std::chrono::steady_clock;
    GeneratorState st{std::mt19937(std::random_device{}())};
    std::vector<uint8_t> scratch;

    uint64_t burst_index = 0;
    uint64_t rx_bytes = 0;
    uint64_t rx_reads = 0;

    auto start = clock::now();
    auto next_send = start;
    auto last_send = start - std::chrono::milliseconds(cfg.min_send_gap_ms);
    auto next_stats = start + std::chrono::seconds(1);
    std::uniform_int_distribution<int> interval_dist(cfg.interval_min_ms, cfg.interval_max_ms);

    while (g_running.load()) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        timeval tv{0, 5000};
        int sel = select(0, &rfds, nullptr, nullptr, &tv);
        bool received_this_iteration = false;
        if (sel > 0 && FD_ISSET(sock, &rfds)) {
            PumpResult pr = pump_socket_to_network_bio(sock, network_bio);
            if (pr == PumpResult::closed) {
                std::cout << "[" << role << "] peer closed the connection\n";
                break;
            }
            if (pr == PumpResult::error) {
                std::cerr << "[ERROR] recv failed: " << wsa_error_string(WSAGetLastError()) << "\n";
                break;
            }
            if (pr == PumpResult::ok) {
                uint64_t reads_before = rx_reads;
                if (!drain_ssl_read(ssl, rx_bytes, rx_reads)) break;
                received_this_iteration = rx_reads > reads_before;
            }
        }

        auto now = clock::now();
        // Reply immediately after receiving so our own outgoing data segment
        // carries the ACK for it, instead of the peer seeing a standalone
        // ACK packet emitted by the delayed-ACK timer before the next
        // scheduled burst. min_send_gap_ms still throttles the reply-on-
        // receive path so a fast back-and-forth can't turn into a flood.
        bool gap_elapsed = now - last_send >= std::chrono::milliseconds(cfg.min_send_gap_ms);
        if ((received_this_iteration && gap_elapsed) || now >= next_send) {
            for (int i = 0; i < cfg.bursts_per_flush; ++i) {
                BurstPlan plan = plan_next_burst(st, cfg);
                if (!write_burst(role, ssl, sock, network_bio, st.rng, plan, ++burst_index, scratch)) return 1;
            }
            if (!flush_network_bio_to_socket(sock, network_bio)) break;
            last_send = now;
            next_send = now + std::chrono::milliseconds(interval_dist(st.rng));
        }
        if (now >= next_stats) {
            std::cout << "[" << role << " STATS] tx_bursts=" << burst_index << " rx_bytes=" << rx_bytes
                      << " rx_read_calls=" << rx_reads << "\n";
            next_stats = now + std::chrono::seconds(1);
        }
        if (duration_seconds > 0 &&
            std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= duration_seconds) {
            std::cout << "[" << role << "] configured duration elapsed, shutting down\n";
            break;
        }
    }
    return 0;
}

int run_client(const std::string& host, uint16_t port, const GeneratorConfig& cfg, int duration_seconds) {
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

    std::cout << "[CLIENT] Connecting to " << host << ":" << port << "...\n";
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection failed: " << wsa_error_string(WSAGetLastError()) << "\n";
        closesocket(sock);
        return 1;
    }
    std::cout << "[CLIENT] Connected. Continuing with TLS handshake...\n";

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);  // research tool: not validating server identity
    if (!maybe_enable_ssl_keylog(ctx)) {
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 1;
    }

    BioPair bio;
    if (!make_bio_pair(bio)) {
        log_openssl_errors("BIO_new_bio_pair");
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 1;
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio.internal, bio.internal);

    if (!set_nonblocking(sock) || !pump_handshake(sock, ssl, bio.network, /*is_server=*/false)) {
        SSL_free(ssl);
        BIO_free(bio.network);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 1;
    }
    std::cout << "[SUCCESS] TLS handshake complete. Cipher: " << SSL_get_cipher(ssl)
              << ", Protocol: " << SSL_get_version(ssl) << "\n";

    int rc = run_loop("CLIENT", sock, ssl, bio.network, cfg, duration_seconds);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    BIO_free(bio.network);
    SSL_CTX_free(ctx);
    closesocket(sock);
    return rc;
}

int run_server(const std::string& host, uint16_t port, const GeneratorConfig& cfg, int duration_seconds) {
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
        std::cerr << "[ERROR] Bind/listen failed on " << host << ":" << port << " (" << wsa_error_string(WSAGetLastError())
                   << ")\n";
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "[SERVER] Listening on " << host << ":" << port << "...\n";
    sockaddr_in client_addr{};
    int client_addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Accept failed: " << wsa_error_string(WSAGetLastError()) << "\n";
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "[SERVER] Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";
    BOOL nodelay = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    BioPair bio;
    if (!make_bio_pair(bio)) {
        log_openssl_errors("BIO_new_bio_pair");
        closesocket(client_sock);
        closesocket(listen_sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio.internal, bio.internal);

    int rc = 0;
    if (!set_nonblocking(client_sock) || !pump_handshake(client_sock, ssl, bio.network, /*is_server=*/true)) {
        rc = 1;
    } else {
        std::cout << "[SUCCESS] TLS handshake complete. Cipher: " << SSL_get_cipher(ssl)
                  << ", Protocol: " << SSL_get_version(ssl) << "\n";
        rc = run_loop("SERVER", client_sock, ssl, bio.network, cfg, duration_seconds);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    BIO_free(bio.network);
    closesocket(client_sock);
    closesocket(listen_sock);
    SSL_CTX_free(ctx);
    return rc;
}

void print_usage(const char* prog) {
    std::cout
        << "Usage: " << prog << " [options]\n\n"
        << "Continuously exchanges TLS 1.2 application data as bursts of one or more\n"
        << "coalesced records of varying size, per pocs/tls_segment_removal.md Phase 0.\n\n"
        << "Options:\n"
        << "  -m, --mode <client|server>     Execution mode (default: client)\n"
        << "  -h, --host <ip_address>        IP address to connect or bind (default: 127.0.0.1)\n"
        << "  -p, --port <port_number>       Port number (default: 45300)\n"
        << "  --min-size <bytes>             Minimum plaintext record size (default: 16)\n"
        << "  --max-size <bytes>              Maximum plaintext record size (default: 1400)\n"
        << "  --min-records <n>               Minimum records per burst (default: 1)\n"
        << "  --max-records <n>               Maximum records per burst (default: 8)\n"
        << "  --interval-min-ms <n>           Minimum delay between bursts (default: 200)\n"
        << "  --interval-max-ms <n>           Maximum delay between bursts (default: 1000)\n"
        << "  --bursts-per-flush <n>          Bursts written before one socket send() (default: 2)\n"
        << "  --min-send-gap-ms <n>           Minimum time between any two sends (default: 100)\n"
        << "  --pattern <close|random|far>    Force one burst pattern instead of picking\n"
        << "                                  randomly per burst (default: random per burst)\n"
        << "  --duration-seconds <n>          Stop after n seconds; 0 = run until Ctrl+C (default: 0)\n"
        << "  --help                          Show this help message\n\n"
        << "If the SSLKEYLOGFILE environment variable is set, TLS session secrets are\n"
        << "appended to that file in NSS Key Log Format, decryptable in Wireshark.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string mode = "client";
    std::string host = "127.0.0.1";
    uint16_t port = 45300;
    GeneratorConfig cfg;
    int duration_seconds = 0;

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
        } else if (arg == "--min-size" && i + 1 < argc) {
            cfg.min_size = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (arg == "--max-size" && i + 1 < argc) {
            cfg.max_size = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (arg == "--min-records" && i + 1 < argc) {
            cfg.min_records = std::stoi(argv[++i]);
        } else if (arg == "--max-records" && i + 1 < argc) {
            cfg.max_records = std::stoi(argv[++i]);
        } else if (arg == "--interval-min-ms" && i + 1 < argc) {
            cfg.interval_min_ms = std::stoi(argv[++i]);
        } else if (arg == "--interval-max-ms" && i + 1 < argc) {
            cfg.interval_max_ms = std::stoi(argv[++i]);
        } else if (arg == "--bursts-per-flush" && i + 1 < argc) {
            cfg.bursts_per_flush = std::stoi(argv[++i]);
        } else if (arg == "--min-send-gap-ms" && i + 1 < argc) {
            cfg.min_send_gap_ms = std::stoi(argv[++i]);
        } else if (arg == "--pattern" && i + 1 < argc) {
            std::string p = argv[++i];
            cfg.force_pattern = true;
            if (p == "close") cfg.forced_pattern = BurstPattern::close;
            else if (p == "far") cfg.forced_pattern = BurstPattern::spread;
            else cfg.forced_pattern = BurstPattern::random_pattern;
        } else if (arg == "--duration-seconds" && i + 1 < argc) {
            duration_seconds = std::stoi(argv[++i]);
        }
    }

    if (cfg.min_size == 0 || cfg.min_size > cfg.max_size || cfg.min_records < 1 || cfg.min_records > cfg.max_records) {
        std::cerr << "[ERROR] Invalid size/record range (need 1 <= min_size <= max_size and 1 <= min_records <= "
                      "max_records)\n";
        return 1;
    }
    if (cfg.bursts_per_flush < 1) {
        std::cerr << "[ERROR] --bursts-per-flush must be >= 1\n";
        return 1;
    }
    if (cfg.min_send_gap_ms < 0) {
        std::cerr << "[ERROR] --min-send-gap-ms must be >= 0\n";
        return 1;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (mode == "client") {
        return run_client(host, port, cfg, duration_seconds);
    } else if (mode == "server") {
        return run_server(host, port, cfg, duration_seconds);
    } else {
        std::cerr << "[ERROR] Invalid mode: " << mode << " (must be 'client' or 'server')\n";
        print_usage(argv[0]);
        return 1;
    }
}
