#pragma once
#include "common.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// ─────────────────────────────────────────────────────────────────────────────
// apex/tls.hpp — mTLS for peer communication
// ─────────────────────────────────────────────────────────────────────────────
//  Provides TLS context management and secure socket wrapping for peer-to-peer
//  communication. Supports mutual TLS authentication with certificate validation.
// ─────────────────────────────────────────────────────────────────────────────

namespace apex {

class TLSContext {
public:
    struct Config {
        std::string cert_path;      // Path to node's certificate
        std::string key_path;       // Path to node's private key
        std::string ca_path;        // Path to CA certificate for peer verification
        bool verify_peers = true;   // Enable peer certificate verification
        std::string cipher_suite = "TLS_AES_256_GCM_SHA384";
    };

    explicit TLSContext(Config cfg) : cfg_(std::move(cfg)) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ctx_ = SSL_CTX_new(TLS_server_method());
        if (!ctx_) {
            LOG_ERROR("TLS: failed to create SSL_CTX");
            throw std::runtime_error("SSL_CTX creation failed");
        }

        // Set TLS 1.3 minimum
        SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

        // Load certificates
        if (!cfg_.cert_path.empty() && !cfg_.key_path.empty()) {
            if (SSL_CTX_use_certificate_file(ctx_, cfg_.cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
                log_ssl_error("TLS: failed to load certificate");
                throw std::runtime_error("Certificate load failed");
            }
            if (SSL_CTX_use_PrivateKey_file(ctx_, cfg_.key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
                log_ssl_error("TLS: failed to load private key");
                throw std::runtime_error("Private key load failed");
            }
            if (!SSL_CTX_check_private_key(ctx_)) {
                LOG_ERROR("TLS: private key does not match certificate");
                throw std::runtime_error("Key/cert mismatch");
            }
        }

        // Configure peer verification
        if (cfg_.verify_peers && !cfg_.ca_path.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, cfg_.ca_path.c_str(), nullptr) <= 0) {
                log_ssl_error("TLS: failed to load CA certificates");
                throw std::runtime_error("CA load failed");
            }
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        } else {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        }

        // Set cipher suites
        if (SSL_CTX_set_ciphersuites(ctx_, cfg_.cipher_suite.c_str()) != 1) {
            LOG_WARN("TLS: cipher suite '%s' not available, using defaults", cfg_.cipher_suite.c_str());
        }

        LOG_INFO("TLS context initialized: cert=%s key=%s ca=%s verify=%d",
                 cfg_.cert_path.c_str(), cfg_.key_path.c_str(), 
                 cfg_.ca_path.c_str(), cfg_.verify_peers);
    }

    ~TLSContext() {
        if (ctx_) {
            SSL_CTX_free(ctx_);
        }
        EVP_cleanup();
        ERR_free_strings();
    }

    SSL_CTX* native() const noexcept { return ctx_; }

    // Create a new SSL connection object
    SSL* create_ssl() const noexcept {
        return SSL_new(ctx_);
    }

private:
    Config cfg_;
    SSL_CTX* ctx_ = nullptr;

    void log_ssl_error(const char* prefix) const {
        char buf[256];
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            LOG_ERROR("%s: %s", prefix, buf);
        }
    }
};

// TLS-enabled connection wrapper
class TLSConnection {
public:
    explicit TLSConnection(SSL* ssl) : ssl_(ssl) {
        SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_set_connect_state(ssl_);
    }

    ~TLSConnection() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
    }

    // Non-copyable
    TLSConnection(const TLSConnection&) = delete;
    TLSConnection& operator=(const TLSConnection&) = delete;

    // Movable
    TLSConnection(TLSConnection&& other) noexcept : ssl_(other.ssl_) {
        other.ssl_ = nullptr;
    }

    TLSConnection& operator=(TLSConnection&& other) noexcept {
        if (this != &other) {
            if (ssl_) SSL_free(ssl_);
            ssl_ = other.ssl_;
            other.ssl_ = nullptr;
        }
        return *this;
    }

    // Perform TLS handshake
    Result<void> handshake() noexcept {
        int ret = SSL_do_handshake(ssl_);
        if (ret <= 0) {
            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return Result<void>::ok(); // In progress
            }
            LOG_ERROR("TLS handshake failed: %s", ssl_error_str(err));
            return Result<void>::err(Errc::IoError);
        }

        // Verify peer certificate if required
        if (SSL_get_verify_result(ssl_) != X509_V_OK) {
            LOG_ERROR("TLS: peer certificate verification failed");
            return Result<void>::err(Errc::IoError);
        }

        LOG_INFO("TLS handshake completed");
        handshake_complete_ = true;
        return Result<void>::ok();
    }

    bool is_handshake_complete() const noexcept { return handshake_complete_; }

    // Read data through TLS
    ssize_t read(void* buf, size_t len) noexcept {
        if (!handshake_complete_) return -1;
        int ret = SSL_read(ssl_, buf, static_cast<int>(len));
        if (ret <= 0) {
            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
                return -1;
            }
            return -1;
        }
        return ret;
    }

    // Write data through TLS
    ssize_t write(const void* buf, size_t len) noexcept {
        if (!handshake_complete_) return -1;
        int ret = SSL_write(ssl_, buf, static_cast<int>(len));
        if (ret <= 0) {
            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
                return -1;
            }
            return -1;
        }
        return ret;
    }

    // Get pending bytes to read
    size_t pending() const noexcept {
        return SSL_pending(ssl_);
    }

    // Get underlying file descriptor
    int fd() const noexcept {
        return SSL_get_fd(ssl_);
    }

    // Set the underlying file descriptor
    void set_fd(int fd) noexcept {
        SSL_set_fd(ssl_, fd);
    }

    // Get peer certificate subject
    std::string peer_subject() const noexcept {
        X509* cert = SSL_get_peer_certificate(ssl_);
        if (!cert) return "";
        
        char buf[256];
        X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
        X509_free(cert);
        return buf;
    }

    // Get peer certificate issuer
    std::string peer_issuer() const noexcept {
        X509* cert = SSL_get_peer_certificate(ssl_);
        if (!cert) return "";
        
        char buf[256];
        X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
        X509_free(cert);
        return buf;
    }

    SSL* native() const noexcept { return ssl_; }

private:
    SSL* ssl_ = nullptr;
    bool handshake_complete_ = false;

    static const char* ssl_error_str(int err) {
        switch (err) {
            case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
            case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
            case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
            case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
            case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
            case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
            default: return "SSL_ERROR_UNKNOWN";
        }
    }
};

} // namespace apex
