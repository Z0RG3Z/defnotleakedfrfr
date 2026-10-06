#pragma once
//
// Resolves a Rec Room AccountId to its room instance id via recflare's matchmaking endpoint
// (GET <base_url>?id=<accountId> -> a bare numeric instance id). The lookup runs once per handshake.
// It is deliberately NOT cached: a player's room changes when they switch rooms, and a reconnect
// after a switch must see the new room.
//
// resolve() blocks for up to the timeout, so the server never calls it on the poll_events thread:
// room_lookup_pool runs it on worker threads and hands results back through a completion queue.
//
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

class room_lookup {
public:
    // base_url e.g. "https://match.recflare.net/tachyon"; timeout in milliseconds.
    room_lookup(std::string base_url, long timeout_ms);

    // Returns the numeric instance id for an account, or nullopt on failure / non-numeric input.
    // A returned 0 is passed through verbatim; the server decides what 0 means (isolate).
    // Blocking; thread-safe (each call uses its own curl handle).
    std::optional<uint64_t> resolve(const std::string& account_id) const;

private:
    std::string m_base_url;
    long m_timeout_ms;
};

// Runs room_lookup::resolve on a few worker threads so a slow recflare never stalls the relay.
// The server thread submit()s a lookup under a ticket of its choosing and later poll()s finished
// ones; all server state stays on that one thread - only the two queues here are shared.
class room_lookup_pool {
public:
    // Pending lookups beyond this are refused (the caller isolates the client), so a connect flood
    // cannot grow the queue without bound.
    static constexpr size_t MAX_QUEUED = 1024;

    struct result {
        uint64_t ticket = 0;
        std::optional<uint64_t> room;   // as room_lookup::resolve
    };

    room_lookup_pool(const room_lookup& lookup, unsigned workers);
    ~room_lookup_pool();   // stop()
    room_lookup_pool(const room_lookup_pool&) = delete;
    room_lookup_pool& operator=(const room_lookup_pool&) = delete;

    // Queue a lookup. False if the queue is full or the pool is stopped.
    bool submit(uint64_t ticket, std::string account_id);
    // Pop one finished lookup, if any. Never blocks on the network.
    bool poll(result& out);
    // Drop queued work and join the workers (an in-flight request finishes or times out first).
    // Must run before curl_global_cleanup().
    void stop();

private:
    struct job {
        uint64_t ticket;
        std::string account_id;
    };

    void work();

    const room_lookup& m_lookup;
    std::mutex m_mutex;
    std::condition_variable m_wake;
    std::deque<job> m_jobs;
    std::deque<result> m_done;
    bool m_stop = false;
    std::vector<std::thread> m_workers;
};
