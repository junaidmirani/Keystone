#pragma once
#include "common.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <random>

// ─────────────────────────────────────────────────────────────────────────────
// apex/auth.hpp — Token-based authentication
// ─────────────────────────────────────────────────────────────────────────────
//  Provides simple token-based authentication for client connections.
//  Tokens are opaque strings that map to authenticated identities with
//  optional permissions and expiration times.
// ─────────────────────────────────────────────────────────────────────────────

namespace apex {

// Token permissions bitmask
enum class TokenPermission : uint32_t {
    None      = 0,
    Read      = (1 << 0),  // GET, METRICS
    Write     = (1 << 1),  // PUT, DEL
    Admin     = (1 << 2),  // All operations
    All       = Read | Write | Admin
};

inline TokenPermission operator|(TokenPermission a, TokenPermission b) {
    return static_cast<TokenPermission>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline TokenPermission operator&(TokenPermission a, TokenPermission b) {
    return static_cast<TokenPermission>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool has_permission(TokenPermission perms, TokenPermission required) {
    return (static_cast<uint32_t>(perms) & static_cast<uint32_t>(required)) != 0;
}

// Token information
struct TokenInfo {
    std::string id;              // Token identifier
    std::string subject;         // User/service name
    TokenPermission permissions; // Granted permissions
    uint64_t created_at;         // Creation timestamp (ms since epoch)
    uint64_t expires_at;         // Expiration timestamp (ms since epoch), 0 = never
    bool active = true;          // Whether token is currently valid

    bool is_expired() const noexcept {
        if (expires_at == 0) return false;
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return now > expires_at;
    }

    bool is_valid() const noexcept {
        return active && !is_expired();
    }
};

// Token generation result
struct TokenResult {
    std::string token;  // The actual token string (for create only)
    TokenInfo info;     // Token metadata
    Errc error = Errc::Ok;

    static TokenResult ok(const std::string& t, TokenInfo i) {
        return TokenResult{t, i, Errc::Ok};
    }

    static TokenResult err(Errc e) {
        TokenResult r;
        r.error = e;
        return r;
    }

    bool is_ok() const noexcept { return error == Errc::Ok; }
    bool is_err() const noexcept { return error != Errc::Ok; }
};

// Token manager for authentication
class TokenManager {
public:
    TokenManager() : rng_(std::random_device{}()) {}

    // Create a new token
    TokenResult create_token(const std::string& subject,
                             TokenPermission permissions,
                             std::chrono::hours ttl = std::chrono::hours(24)) {
        std::string token = generate_token();
        
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        TokenInfo info;
        info.id = compute_token_id(token);
        info.subject = subject;
        info.permissions = permissions;
        info.created_at = now;
        info.expires_at = ttl.count() > 0 ? now + std::chrono::duration_cast<std::chrono::milliseconds>(ttl).count() : 0;
        info.active = true;

        {
            std::unique_lock lock(mutex_);
            tokens_[info.id] = info;
        }

        LOG_INFO("Auth: created token for '%s' with permissions=%u ttl=%ldh",
                 subject.c_str(), static_cast<uint32_t>(permissions), 
                 static_cast<long>(ttl.count()));

        return TokenResult::ok(token, info);
    }

    // Validate a token and return its info
    Result<TokenInfo> validate_token(const std::string& token) noexcept {
        std::string token_id = compute_token_id(token);

        std::shared_lock lock(mutex_);
        auto it = tokens_.find(token_id);
        if (it == tokens_.end()) {
            return Result<TokenInfo>::err(Errc::NotFound);
        }

        const TokenInfo& info = it->second;
        if (!info.is_valid()) {
            if (!info.active) {
                LOG_DEBUG("Auth: token '%s' is revoked", token_id.substr(0, 8).c_str());
            } else {
                LOG_DEBUG("Auth: token '%s' is expired", token_id.substr(0, 8).c_str());
            }
            return Result<TokenInfo>::err(Errc::Timeout);
        }

        return Result<TokenInfo>::ok(info);
    }

    // Revoke a token
    Result<void> revoke_token(const std::string& token) noexcept {
        std::string token_id = compute_token_id(token);

        std::unique_lock lock(mutex_);
        auto it = tokens_.find(token_id);
        if (it == tokens_.end()) {
            return Result<void>::err(Errc::NotFound);
        }

        it->second.active = false;
        LOG_INFO("Auth: revoked token '%s'", token_id.substr(0, 8).c_str());
        return Result<void>::ok();
    }

    // Check if a token has specific permission
    Result<bool> check_permission(const std::string& token, TokenPermission required) noexcept {
        auto result = validate_token(token);
        if (result.is_err()) {
            return Result<bool>::err(result.error());
        }

        bool allowed = has_permission(result.value().permissions, required);
        if (!allowed) {
            LOG_WARN("Auth: permission denied for token '%s' required=%u",
                     compute_token_id(token).substr(0, 8).c_str(),
                     static_cast<uint32_t>(required));
        }
        return Result<bool>::ok(allowed);
    }

    // Get count of active tokens (for metrics)
    size_t active_token_count() const noexcept {
        std::shared_lock lock(mutex_);
        size_t count = 0;
        for (const auto& [id, info] : tokens_) {
            if (info.is_valid()) count++;
        }
        return count;
    }

    // Cleanup expired tokens (call periodically)
    void cleanup_expired() noexcept {
        std::unique_lock lock(mutex_);
        auto before = tokens_.size();
        
        auto it = tokens_.begin();
        while (it != tokens_.end()) {
            if (!it->second.is_valid()) {
                it = tokens_.erase(it);
            } else {
                ++it;
            }
        }

        if (before != tokens_.size()) {
            LOG_INFO("Auth: cleaned up %zu expired/revoked tokens", before - tokens_.size());
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, TokenInfo> tokens_;
    std::mt19937_64 rng_;

    // Generate a random token (32 bytes = 64 hex chars)
    std::string generate_token() {
        static const char hex[] = "0123456789abcdef";
        std::string token;
        token.reserve(64);

        std::uniform_int_distribution<uint32_t> dist(0, 15);
        for (int i = 0; i < 64; i++) {
            token.push_back(hex[dist(rng_)]);
        }

        return token;
    }

    // Compute token ID (first 16 chars of SHA256-like hash simulation)
    // In production, use proper cryptographic hash
    std::string compute_token_id(const std::string& token) {
        // Simple hash: XOR folding + hex encoding
        uint64_t h1 = 0xcbf29ce484222325ULL;
        uint64_t h2 = 0x100000001b3ULL;
        
        for (char c : token) {
            h1 ^= static_cast<uint64_t>(c);
            h1 *= h2;
            h2 ^= h1 >> 17;
        }

        char buf[17];
        snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h1);
        return buf;
    }
};

// Global token manager instance
inline TokenManager g_auth;

} // namespace apex
