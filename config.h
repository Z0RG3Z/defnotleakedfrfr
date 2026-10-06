#pragma once
//
// Runtime configuration, loaded from a simple `key = value` file (no dependency). CLI flags still
// win over the file. Unknown keys are an error so typos surface. See tachyon.conf.example.
//
#include "log.h"

#include <cstdint>
#include <string>

struct config {
    uint16_t port = 7777;
    bool encrypt = true;
    bool fork = true;
    bool dissonance = true;
    bool rooms = true;
    int ds_count_width = 2;
    LogLevel log_level = LogLevel::Info;

    std::string room_url = "https://match.recflare.net/tachyon";
    long room_timeout_ms = 2000;
    int room_workers = 4;   // threads running room lookups concurrently (off the relay thread)

    // The client (LiteNetLibTransport: DisconnectTimeout 5s, PingInterval 1s) leaves the room for
    // its dorm after 5s with nothing from us, and has no reconnect path - a dropped link always
    // costs the player their room. Both directions of that need defending:
    //  - disconnect_timeout: the server must outlast the client, so a brief stall in the client's
    //    uplink does not make US let go (which is what ends the session - the client then times out
    //    5s later, having heard nothing since).
    //  - ping_interval: in a quiet room our pings are the only thing holding the client's own timer
    //    open, so send them at twice its rate - 10 consecutive losses to kill a session, not 5.
    int32_t disconnect_timeout_ms = 20000;
    int32_t ping_interval_ms = 500;

    // Path to a file holding the RSA private key as .NET RSAKeyValue XML. Its public half is the
    // key the client encrypts AT/VB/CKA/CIA/CPK to; the server decrypts those with this key.
    std::string private_key_path;

    // Shared HS256 secret used to verify the JWT inside the AT blob. When BOTH this and the private
    // key are set, the server authenticates every connection (rejecting invalid/expired/mismatched
    // tokens). When either is empty, no auth is done and the server stays public.
    std::string jwt_secret;
};

// Load `path` over the defaults already in `cfg`. Returns false and sets `err` on any problem
// (missing file, bad line, unknown key, bad value).
bool load_config(const std::string& path, config& cfg, std::string& err);
