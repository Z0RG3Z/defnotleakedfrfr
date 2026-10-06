#include "room_lookup.h"
#include "log.h"

#include <curl/curl.h>

#include <cctype>
#include <cstdlib>

namespace {
    size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* out = static_cast<std::string*>(userdata);
        out->append(ptr, size * nmemb);
        return size * nmemb;
    }

    bool all_digits(const std::string& s) {
        if (s.empty()) return false;
        for (char c : s) if (!std::isdigit((unsigned char) c)) return false;
        return true;
    }
}

room_lookup::room_lookup(std::string base_url, long timeout_ms)
    : m_base_url(std::move(base_url)), m_timeout_ms(timeout_ms) {}

std::optional<uint64_t> room_lookup::resolve(const std::string& account_id) const {
    // AccountId comes from an untrusted client. It must be a plain integer - anything else is
    // rejected outright (also keeps it safe to splice into a URL).
    if (!all_digits(account_id)) {
        LOGW("[room] rejecting non-numeric AccountId '%s'\n", account_id.c_str());
        return std::nullopt;
    }

    std::string url = m_base_url + "?id=" + account_id;
    std::string body;

    CURL* curl = curl_easy_init();
    if (!curl) {
        LOGW("[room] curl_easy_init failed\n");
        return std::nullopt;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, m_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);   // thread-safe timeout handling

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        LOGW("[room] lookup for %s failed: %s\n", account_id.c_str(), curl_easy_strerror(rc));
        return std::nullopt;
    }
    if (http_code != 200) {
        LOGW("[room] lookup for %s returned HTTP %ld\n", account_id.c_str(), http_code);
        return std::nullopt;
    }

    // Body is a bare numeric instance id (possibly with trailing whitespace).
    char* end = nullptr;
    unsigned long long value = std::strtoull(body.c_str(), &end, 10);
    if (end == body.c_str()) {
        LOGW("[room] lookup for %s returned non-numeric body '%.32s'\n", account_id.c_str(), body.c_str());
        return std::nullopt;
    }

    uint64_t room = (uint64_t) value;
    LOGD("[room] AccountId %s -> room %llu\n", account_id.c_str(), (unsigned long long) room);
    return room;
}

room_lookup_pool::room_lookup_pool(const room_lookup& lookup, unsigned workers) : m_lookup(lookup) {
    if (workers == 0) workers = 1;
    for (unsigned i = 0; i < workers; i++) m_workers.emplace_back(&room_lookup_pool::work, this);
}

room_lookup_pool::~room_lookup_pool() { stop(); }

bool room_lookup_pool::submit(uint64_t ticket, std::string account_id) {
    {
        std::lock_guard lock(m_mutex);
        if (m_stop || m_jobs.size() >= MAX_QUEUED) return false;
        m_jobs.push_back({ticket, std::move(account_id)});
    }
    m_wake.notify_one();
    return true;
}

bool room_lookup_pool::poll(result& out) {
    std::lock_guard lock(m_mutex);
    if (m_done.empty()) return false;
    out = m_done.front();
    m_done.pop_front();
    return true;
}

void room_lookup_pool::stop() {
    {
        std::lock_guard lock(m_mutex);
        m_stop = true;
        m_jobs.clear();
    }
    m_wake.notify_all();
    for (auto& t : m_workers) if (t.joinable()) t.join();
    m_workers.clear();
}

void room_lookup_pool::work() {
    for (;;) {
        job j;
        {
            std::unique_lock lock(m_mutex);
            m_wake.wait(lock, [&] { return m_stop || !m_jobs.empty(); });
            if (m_stop) return;
            j = std::move(m_jobs.front());
            m_jobs.pop_front();
        }
        auto room = m_lookup.resolve(j.account_id);   // the only blocking call, outside the lock
        std::lock_guard lock(m_mutex);
        m_done.push_back({j.ticket, room});
    }
}
