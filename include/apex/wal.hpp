#pragma once
#include <future>
#include "protocol.hpp"
#include "common.hpp"

// ── §11  LogEntry ─────────────────────────────────────────────────────────────
// Forward-declared in protocol.hpp, defined here.
struct LogEntry
{
    uint64_t term = 0;
    uint64_t index = 0;
    Cmd op = Cmd::PUT;
    std::string key;
    std::string val;
};

// ── Durability modes ──────────────────────────────────────────────────────────
enum class DurabilityMode : uint8_t
{
    Unsafe = 0,  // No fsync — fastest, lose data on crash
    Durable = 1, // fdatasync after leader commit batch (default)
    Strict = 2,  // fdatasync on every follower append
};

// ── §9  WAL ───────────────────────────────────────────────────────────────────
//
//  Record format:
//    [MAGIC:4=0xAEC0FFEE][data_len:4][CRC32:4][DATA:data_len]
//    DATA = [term:8][index:8][op:1][key_len:4][key][val_len:4][val]
//
//  Group-commit protocol:
//    Writers call append() which serializes the record and pushes it into
//    the pending_ queue.  A background flush thread (or the caller in
//    synchronous mode) drains the queue, writes all records with a single
//    writev(), and calls fdatasync() once for the batch.
//    Waiters block on a condition variable until their entry's index is
//    confirmed flushed.
// ─────────────────────────────────────────────────────────────────────────────
class WAL
{
public:
    static constexpr uint32_t MAGIC = 0xAEC0FFEEu;

    struct Config
    {
        DurabilityMode durability = DurabilityMode::Durable;
        int flush_interval_ms = 2; // group-commit window
        int max_batch_size = 256;  // max entries per flush
    };

    // explicit WAL(Config cfg = {}) : cfg_(cfg) {}
    explicit WAL(Config cfg) : cfg_(cfg) {}
    WAL() : cfg_() {}
    ~WAL()
    {
        stop_flush_thread();
        close();
    }

    Result<void> open(const std::string &path) noexcept
    {
        path_ = path;
        fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (fd_ < 0)
        {
            LOG_ERROR("WAL open(%s): %s", path.c_str(), strerror(errno));
            return Result<void>::err(Errc::IoError);
        }
        if (lseek(fd_, 0, SEEK_END) < 0)
            return Result<void>::err(Errc::IoError);

        if (cfg_.durability == DurabilityMode::Durable)
        {
            start_flush_thread();
        }
        LOG_INFO("WAL opened: %s  durability=%s  flush_ms=%d",
                 path.c_str(),
                 cfg_.durability == DurabilityMode::Unsafe ? "unsafe" : cfg_.durability == DurabilityMode::Durable ? "durable"
                                                                                                                   : "strict",
                 cfg_.flush_interval_ms);
        return Result<void>::ok();
    }

    void close() noexcept
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    // ── Append an entry ───────────────────────────────────────────────────────
    //
    //  Durable mode: entry is pushed to the pending queue; caller blocks
    //  until the flush thread has committed the batch containing this entry.
    //  Strict / Unsafe: synchronous write, optional fsync.
    Result<void> append(const LogEntry &e) noexcept
    {
        if (cfg_.durability == DurabilityMode::Durable)
        {
            return append_group_commit(e);
        }
        return append_sync(e, cfg_.durability == DurabilityMode::Strict);
    }

    Result<void> replay(std::function<void(const LogEntry &)> cb) noexcept
    {
        if (lseek(fd_, 0, SEEK_SET) < 0)
            return Result<void>::err(Errc::IoError);
        uint64_t records = 0;
        for (;;)
        {
            uint8_t rec_hdr[12];
            ssize_t n = read(fd_, rec_hdr, 12);
            if (n == 0)
                break;
            if (n != 12)
            {
                LOG_WARN("WAL: truncated header at %llu", (unsigned long long)records);
                break;
            }
            uint32_t magic_be, len_be, crc_be;
            memcpy(&magic_be, rec_hdr + 0, 4);
            memcpy(&len_be, rec_hdr + 4, 4);
            memcpy(&crc_be, rec_hdr + 8, 4);
            if (ntohl(magic_be) != MAGIC)
            {
                LOG_ERROR("WAL: bad magic at record %llu", (unsigned long long)records);
                return Result<void>::err(Errc::Corrupt);
            }
            uint32_t data_len = ntohl(len_be), expected = ntohl(crc_be);
            std::vector<uint8_t> data(data_len);
            if ((uint32_t)read(fd_, data.data(), data_len) != data_len)
            {
                LOG_WARN("WAL: truncated data at %llu", (unsigned long long)records);
                break;
            }
            if (crc32(data.data(), data_len) != expected)
            {
                LOG_ERROR("WAL: CRC mismatch at record %llu", (unsigned long long)records);
                return Result<void>::err(Errc::Corrupt);
            }
            ByteReader r(data.data(), data_len);
            LogEntry le;
            le.term = r.u64();
            le.index = r.u64();
            le.op = static_cast<Cmd>(r.u8());
            le.key = r.str();
            le.val = r.str();
            cb(le);
            ++records;
        }
        LOG_INFO("WAL replay: %llu records", (unsigned long long)records);
        return Result<void>::ok();
    }

    Result<void> truncate_after(uint64_t keep_through) noexcept
    {
        std::string tmp = path_ + ".tmp";
        int tmp_fd = ::open(tmp.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (tmp_fd < 0)
            return Result<void>::err(Errc::IoError);
        int rd_fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
        if (rd_fd < 0)
        {
            ::close(tmp_fd);
            return Result<void>::err(Errc::IoError);
        }
        std::lock_guard lk(mtx_);
        for (;;)
        {
            uint8_t rec_hdr[12];
            if (read(rd_fd, rec_hdr, 12) != 12)
                break;
            uint32_t len_be;
            memcpy(&len_be, rec_hdr + 4, 4);
            uint32_t data_len = ntohl(len_be);
            std::vector<uint8_t> data(data_len);
            if ((uint32_t)read(rd_fd, data.data(), data_len) != data_len)
                break;
            uint64_t entry_idx = 0;
            if (data_len >= 16)
            {
                memcpy(&entry_idx, data.data() + 8, 8);
                entry_idx = be64toh(entry_idx);
            }
            if (entry_idx > keep_through)
                continue;
            if (write(tmp_fd, rec_hdr, 12) != 12)
                break;
            if ((uint32_t)write(tmp_fd, data.data(), data_len) != data_len)
                break;
        }
        fdatasync(tmp_fd);
        ::close(rd_fd);
        ::close(tmp_fd);
        if (rename(tmp.c_str(), path_.c_str()) != 0)
            return Result<void>::err(Errc::IoError);
        ::close(fd_);
        fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        lseek(fd_, 0, SEEK_END);
        return Result<void>::ok();
    }

    // ── Snapshot support ───────────────────────────────────────────────────────
    //
    //  Creates a point-in-time snapshot of all entries up to the given index.
    //  Used for log compaction and state transfer to new/falling-behind peers.
    Result<void> create_snapshot(const std::string& snapshot_path, uint64_t through_index) noexcept
    {
        std::string snap_tmp = snapshot_path + ".tmp";
        int snap_fd = ::open(snap_tmp.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (snap_fd < 0)
            return Result<void>::err(Errc::IoError);

        // Write snapshot header: [magic:4][version:4][through_index:8][entry_count:8]
        uint8_t hdr[24];
        uint32_t magic = htonl(0xAEC05NAPu);
        uint32_t version = htonl(1);
        uint64_t idx_be = htobe64(through_index);
        uint64_t count_be = 0; // Will be updated
        memcpy(hdr + 0, &magic, 4);
        memcpy(hdr + 4, &version, 4);
        memcpy(hdr + 8, &idx_be, 8);
        memcpy(hdr + 16, &count_be, 8);
        if (write(snap_fd, hdr, 24) != 24)
        {
            ::close(snap_fd);
            unlink(snap_tmp.c_str());
            return Result<void>::err(Errc::IoError);
        }

        int rd_fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
        if (rd_fd < 0)
        {
            ::close(snap_fd);
            unlink(snap_tmp.c_str());
            return Result<void>::err(Errc::IoError);
        }

        uint64_t entry_count = 0;
        std::lock_guard lk(mtx_);
        for (;;)
        {
            uint8_t rec_hdr[12];
            if (read(rd_fd, rec_hdr, 12) != 12)
                break;
            uint32_t len_be;
            memcpy(&len_be, rec_hdr + 4, 4);
            uint32_t data_len = ntohl(len_be);
            std::vector<uint8_t> data(data_len);
            if ((uint32_t)read(rd_fd, data.data(), data_len) != data_len)
                break;

            uint64_t entry_idx = 0;
            if (data_len >= 16)
            {
                memcpy(&entry_idx, data.data() + 8, 8);
                entry_idx = be64toh(entry_idx);
            }

            if (entry_idx > through_index)
                continue;

            // Write entry to snapshot
            if (write(snap_fd, rec_hdr, 12) != 12)
                break;
            if ((uint32_t)write(snap_fd, data.data(), data_len) != data_len)
                break;
            entry_count++;
        }

        ::close(rd_fd);

        // Update entry count in header
        uint64_t count_be = htobe64(entry_count);
        lseek(snap_fd, 16, SEEK_SET);
        if (write(snap_fd, &count_be, 8) != 8)
        {
            ::close(snap_fd);
            unlink(snap_tmp.c_str());
            return Result<void>::err(Errc::IoError);
        }

        fdatasync(snap_fd);
        ::close(snap_fd);

        if (rename(snap_tmp.c_str(), snapshot_path.c_str()) != 0)
        {
            unlink(snap_tmp.c_str());
            return Result<void>::err(Errc::IoError);
        }

        LOG_INFO("WAL snapshot created: %s through_index=%llu entries=%llu",
                 snapshot_path.c_str(), (unsigned long long)through_index, (unsigned long long)entry_count);
        return Result<void>::ok();
    }

    // Load entries from a snapshot
    Result<uint64_t> load_snapshot(const std::string& snapshot_path,
                                    std::function<void(const LogEntry&)> cb) noexcept
    {
        int snap_fd = ::open(snapshot_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (snap_fd < 0)
            return Result<uint64_t>::err(Errc::IoError);

        // Read and verify header
        uint8_t hdr[24];
        if (read(snap_fd, hdr, 24) != 24)
        {
            ::close(snap_fd);
            return Result<uint64_t>::err(Errc::Corrupt);
        }

        uint32_t magic_be, version_be;
        memcpy(&magic_be, hdr + 0, 4);
        memcpy(&version_be, hdr + 4, 4);

        if (ntohl(magic_be) != 0xAEC05NAPu)
        {
            LOG_ERROR("Snapshot: bad magic");
            ::close(snap_fd);
            return Result<uint64_t>::err(Errc::Corrupt);
        }

        uint64_t through_index, entry_count;
        memcpy(&through_index, hdr + 8, 8);
        memcpy(&entry_count, hdr + 16, 8);
        through_index = be64toh(through_index);
        entry_count = be64toh(entry_count);

        uint64_t loaded = 0;
        for (uint64_t i = 0; i < entry_count; i++)
        {
            uint8_t rec_hdr[12];
            if (read(snap_fd, rec_hdr, 12) != 12)
            {
                LOG_WARN("Snapshot: truncated at entry %llu", (unsigned long long)i);
                break;
            }

            uint32_t len_be;
            memcpy(&len_be, rec_hdr + 4, 4);
            uint32_t data_len = ntohl(len_be);
            std::vector<uint8_t> data(data_len);
            if ((uint32_t)read(snap_fd, data.data(), data_len) != data_len)
            {
                LOG_WARN("Snapshot: truncated data at entry %llu", (unsigned long long)i);
                break;
            }

            ByteReader r(data.data(), data_len);
            LogEntry le;
            le.term = r.u64();
            le.index = r.u64();
            le.op = static_cast<Cmd>(r.u8());
            le.key = r.str();
            le.val = r.str();
            cb(le);
            loaded++;
        }

        ::close(snap_fd);
        LOG_INFO("Snapshot loaded: %s entries=%llu/%llu",
                 snapshot_path.c_str(), (unsigned long long)loaded, (unsigned long long)entry_count);
        return Result<uint64_t>::ok(through_index);
    }

    // Compact WAL by removing entries before a given index (after snapshot)
    Result<void> compact_before(uint64_t before_index) noexcept
    {
        // First create a snapshot of entries we're keeping
        std::string snapshot_path = path_ + ".snapshot";
        auto snap_result = create_snapshot(snapshot_path, before_index - 1);
        if (snap_result.is_err())
            return snap_result;

        // Replace WAL with empty file (entries are now in snapshot)
        close();
        std::string backup = path_ + ".backup";
        if (rename(path_.c_str(), backup.c_str()) != 0)
            return Result<void>::err(Errc::IoError);

        // Create fresh WAL
        fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd_ < 0)
        {
            rename(backup.c_str(), path_.c_str());
            return Result<void>::err(Errc::IoError);
        }

        LOG_INFO("WAL compacted: removed entries before index %llu", (unsigned long long)before_index);
        return Result<void>::ok();
    }

    // Get current WAL size (for monitoring)
    uint64_t size_bytes() const noexcept
    {
        struct stat st;
        if (fd_ >= 0 && fstat(fd_, &st) == 0)
            return static_cast<uint64_t>(st.st_size);
        return 0;
    }

private:
    Config cfg_;
    std::string path_;
    int fd_ = -1;
    std::mutex mtx_;

    // ── Group-commit state ────────────────────────────────────────────────────
    struct PendingEntry
    {
        std::vector<uint8_t> serialized; // 12-byte header + data
        uint64_t index;
        std::promise<Result<void>> promise;
    };

    std::mutex pending_mtx_;
    std::condition_variable pending_cv_;
    std::vector<PendingEntry *> pending_;
    uint64_t flushed_index_{0};
    std::condition_variable flushed_cv_;
    std::thread flush_thread_;
    std::atomic<bool> flush_running_{false};

    void start_flush_thread()
    {
        flush_running_.store(true, std::memory_order_release);
        flush_thread_ = std::thread([this]
                                    { flush_loop(); });
    }

    void stop_flush_thread()
    {
        flush_running_.store(false, std::memory_order_release);
        pending_cv_.notify_all();
        if (flush_thread_.joinable())
            flush_thread_.join();
    }

    void flush_loop()
    {
        while (flush_running_.load(std::memory_order_relaxed))
        {
            std::vector<PendingEntry *> batch;
            {
                std::unique_lock lk(pending_mtx_);
                pending_cv_.wait_for(lk,
                                     std::chrono::milliseconds(cfg_.flush_interval_ms),
                                     [this]
                                     { return !pending_.empty() || !flush_running_.load(); });
                if (pending_.empty())
                    continue;
                int take = std::min((int)pending_.size(), cfg_.max_batch_size);
                batch.assign(pending_.begin(), pending_.begin() + take);
                pending_.erase(pending_.begin(), pending_.begin() + take);
            }
            flush_batch(batch);
        }
        // Drain remaining on shutdown
        std::vector<PendingEntry *> remainder;
        {
            std::lock_guard lk(pending_mtx_);
            remainder = std::move(pending_);
        }
        if (!remainder.empty())
            flush_batch(remainder);
    }

    void flush_batch(std::vector<PendingEntry *> &batch)
    {
        // Build iovecs off the lock — contention reduction
        std::vector<struct iovec> iovs;
        iovs.reserve(batch.size());
        for (auto *e : batch)
        {
            iovs.push_back({e->serialized.data(), e->serialized.size()});
        }

        bool ok = true;
        {
            std::lock_guard lk(mtx_);
            ssize_t total = 0;
            for (auto &v : iovs)
                total += (ssize_t)v.iov_len;

            // writev batches all records in one syscall
            if (writev(fd_, iovs.data(), (int)iovs.size()) != total)
            {
                LOG_ERROR("WAL group writev failed: %s", strerror(errno));
                ok = false;
            }
            else if (cfg_.durability != DurabilityMode::Unsafe)
            {
                // Single fdatasync for the whole batch — the big perf win
                if (fdatasync(fd_) != 0)
                {
                    LOG_ERROR("WAL fdatasync failed: %s", strerror(errno));
                    ok = false;
                }
            }
        }

        for (auto *e : batch)
        {
            e->promise.set_value(ok ? Result<void>::ok()
                                    : Result<void>::err(Errc::IoError));
            delete e;
        }
    }

    Result<void> append_group_commit(const LogEntry &e) noexcept
    {
        auto serialized = serialize(e);
        auto *pe = new PendingEntry{std::move(serialized), e.index, {}};
        auto future = pe->promise.get_future();
        {
            std::lock_guard lk(pending_mtx_);
            pending_.push_back(pe);
            pending_cv_.notify_one();
        }
        return future.get();
    }

    Result<void> append_sync(const LogEntry &e, bool do_fsync) noexcept
    {
        auto data = serialize(e);
        std::lock_guard lk(mtx_);
        struct iovec iov = {data.data(), data.size()};
        if (writev(fd_, &iov, 1) != (ssize_t)data.size())
        {
            LOG_ERROR("WAL writev failed: %s", strerror(errno));
            return Result<void>::err(Errc::IoError);
        }
        if (do_fsync && fdatasync(fd_) != 0)
        {
            LOG_ERROR("WAL fdatasync failed: %s", strerror(errno));
            return Result<void>::err(Errc::IoError);
        }
        return Result<void>::ok();
    }

    static std::vector<uint8_t> serialize(const LogEntry &e)
    {
        ByteWriter w;
        w.u64(e.term);
        w.u64(e.index);
        w.u8(static_cast<uint8_t>(e.op));
        w.str(e.key);
        w.str(e.val);
        uint32_t data_len = (uint32_t)w.buf.size();
        uint32_t crc = crc32(w.buf.data(), data_len);
        uint8_t hdr[12];
        uint32_t m = htonl(MAGIC), l = htonl(data_len), c = htonl(crc);
        memcpy(hdr + 0, &m, 4);
        memcpy(hdr + 4, &l, 4);
        memcpy(hdr + 8, &c, 4);
        std::vector<uint8_t> out;
        out.insert(out.end(), hdr, hdr + 12);
        out.insert(out.end(), w.buf.begin(), w.buf.end());
        return out;
    }
};
