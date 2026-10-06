#pragma once
//
// Tachyon voice-relay server: the NGO 1.x + Dissonance session logic, sitting on top of
// LiteNetLibPP (the LiteNetLib transport) plus the
// RecRoom 0x11 marker layer installed on the net_manager.
//
#include "crypto.h"
#include "room_lookup.h"

#include <lnl/net_event_listener.h>
#include <lnl/net_manager.h>

#include <array>
#include <cstdint>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class tachyon_server : public lnl::net_event_listener {
public:
    // Ordinal sort by FullName with Connection{Approved,Request} pulled to the front, matching
    // NGO's NetworkMessageManager.PrioritizeMessageOrder. Sending this order in ConnectionApproved
    // defines the message-id space for the rest of the session.
    static constexpr std::array<const char*, 7> MESSAGE_ORDER = {
        "Unity.Netcode.ConnectionApprovedMessage",
        "Unity.Netcode.ConnectionRequestMessage",
        "Unity.Netcode.DisconnectReasonMessage",
        "Unity.Netcode.NamedMessage",
        "Unity.Netcode.ServerLogMessage",
        "Unity.Netcode.TimeSyncMessage",
        "Unity.Netcode.UnnamedMessage",
    };
    static constexpr int TICK_RATE = 30;
    // Minimum gap between cross-room-drop warnings for a given sender.
    static constexpr std::chrono::seconds CROSS_ROOM_LOG_INTERVAL{5};

    bool fork = true;          // Rec Room's 24-byte forked batch header
    bool dissonance = true;    // act as the Dissonance session server (answer handshake, relay)
    int ds_count_width = 2;    // list-count width in HandshakeResponse (2=u16, 1=byte) - unverified

    tachyon_server();

    int current_tick() const;
    // Called once per loop iteration to emit TimeSync to approved clients on tick boundaries.
    void pump_time_sync();
    // Called once per loop iteration: finish the handshake of clients whose room lookup completed.
    void pump_room_lookups();
    // Offline self-test: exercises the wire logic (packing, batch build<->parse, hashes) with no
    // network. If hexfile is non-null it is also fed through the batch parser. Returns 0 on success.
    int run_selftest(const char* hexfile);
    // True while any client is connected. The main loop polls fast when busy and backs off when
    // idle, so an empty server costs almost no CPU.
    bool has_clients() const { return !m_clients.empty(); }

    // Optional room resolver: AccountId -> room instance id, run off-thread. When set, the server
    // scopes the Dissonance session/roster/relay per room (recflare enforcement) and a client's
    // ConnectionApproved waits for its lookup. When unset, every client shares one session (the
    // original single-room behaviour). Not owned.
    room_lookup_pool* room_pool = nullptr;

    // RSA private key matching the public key the client encrypts its wire blobs to. When set, the
    // server decrypts AT/VB/CKA/CIA/CPK at handshake (logged at debug). Not owned.
    const rsa_key* priv_key = nullptr;

    // Shared HS256 secret for verifying the JWT carried in AT. Authentication is enabled only when
    // this is non-empty AND priv_key is valid (we must decrypt AT to read the token). Otherwise the
    // server does no auth and accepts everyone - see handle_connection_request.
    std::string jwt_secret;

    // The transport manager, needed to disconnect a peer that fails authentication. Not owned.
    lnl::net_manager* manager = nullptr;

    bool auth_enabled() const { return manager && !jwt_secret.empty() && priv_key && priv_key->valid(); }

protected:
    void on_connection_request(std::shared_ptr<lnl::net_connection_request>& request) override;
    void on_peer_connected(std::shared_ptr<lnl::net_peer>& peer) override;
    void on_peer_disconnected(std::shared_ptr<lnl::net_peer>& peer, lnl::disconnect_info& info) override;
    void on_network_receive(std::shared_ptr<lnl::net_peer>& peer, lnl::net_data_reader& reader,
                            uint8_t channel, lnl::DELIVERY_METHOD delivery) override;

private:
    struct client_state {
        std::shared_ptr<lnl::net_peer> peer;
        uint64_t client_id = 0;
        bool approved = false;
        std::unordered_map<uint32_t, int> remote_versions;
        std::vector<std::pair<uint32_t, int>> client_version_list;  // wire order, echoed verbatim
        uint16_t ds_client_id = 0;
        std::vector<uint8_t> last_client_state;     // replayed to newcomers for roster
        std::string account_id;                     // Tachyon "AI" - stable across reconnects
        uint64_t room = 0;                          // room instance id (recflare); 0 = unresolved
        uint64_t room_ticket = 0;                   // in-flight room lookup; 0 = none
        uint32_t session = 0;                       // Dissonance session id for this client's room
        // Cross-room drops are counted per sender and logged at most once per
        // CROSS_ROOM_LOG_INTERVAL, so one stale roster entry cannot flood the log at voice rate.
        uint32_t cross_room_drops = 0;
        std::chrono::steady_clock::time_point last_cross_room_log{};
    };

    std::unordered_map<lnl::net_peer*, client_state> m_clients;
    std::unordered_map<std::string, uint16_t> m_ds_id_by_account;
    // The peer currently OWNING each Dissonance id. A reconnect-before-timeout reuses an id while
    // the old peer is still live; the newest handshake becomes owner, so the old peer's later
    // disconnect must not broadcast RemoveClient for an id now held by someone else.
    std::unordered_map<uint16_t, lnl::net_peer*> m_ds_owner;
    std::array<uint32_t, 7> m_hashes{};
    std::chrono::steady_clock::time_point m_start;
    int m_last_tick = -1;
    uint64_t m_next_client_id = 1;
    uint16_t m_next_ds_client_id = 1;
    // One Dissonance session id per room, so a cross-room packet is dropped by the client's own
    // Dissonance layer (wrong session) as well as by our scoped relay.
    std::unordered_map<uint64_t, uint32_t> m_session_by_room;
    uint64_t m_next_isolated_room = 0xFFFFFFFF00000000ULL;  // unique rooms for unresolved clients
    // In-flight room lookups, ticket -> peer. Tickets are never reused, so a result for a peer that
    // disconnected meanwhile (entry erased) can never be applied to a newer peer at the same address.
    std::unordered_map<uint64_t, lnl::net_peer*> m_room_pending;
    uint64_t m_next_room_ticket = 1;

    client_state* find(lnl::net_peer* p);
    // Start resolving this client's room. Returns true if the room is already set (no resolver, or
    // the lookup could not be queued -> isolated); false if a lookup is now in flight and
    // pump_room_lookups will finish the handshake.
    bool begin_room_lookup(client_state& st);
    void set_room(client_state& st, uint64_t room);
    void isolate(client_state& st, const char* why);
    void approve(client_state& st);
    uint32_t session_for_room(uint64_t room);

    // Reusable scratch buffers for the send path (all sends happen on the one poll_events thread),
    // so relaying a voice packet does not churn the heap.
    std::vector<uint8_t> m_wire_scratch;
    std::vector<uint8_t> m_named_scratch;
    void write_batch_header(uint8_t* d, size_t size, uint64_t hash) const;
    // Build the full on-wire batch for one message into `out` (header + packed type/size + body).
    void build_batch(const char* full_name, const std::vector<uint8_t>& body, std::vector<uint8_t>& out);

    // receive
    bool handle_batch(client_state& st, const uint8_t* data, size_t len);   // true = parsed, hash ok
    void handle_message(client_state& st, uint32_t type, const uint8_t* data, size_t off, size_t len);
    void handle_connection_request(client_state& st, const uint8_t* data, size_t off, size_t len);
    void handle_named_message(client_state& st, const uint8_t* data, size_t off, size_t len);
    void handle_dissonance_to_server(client_state& st, const std::vector<uint8_t>& diss);
    void handle_server_relay(client_state& st, const std::vector<uint8_t>& diss, lnl::DELIVERY_METHOD delivery);

    // send
    void send_connection_approved(client_state& st);
    void send_handshake_response(client_state& st);
    void send_remove_client(client_state& leaving);
    // Retire a Dissonance id in one room: `session` must be that room's session or its clients
    // ignore the packet. `except` (may be null) is skipped.
    void broadcast_remove_client(uint16_t ds_id, uint64_t room, uint32_t session, lnl::net_peer* except);
    void relay_dissonance(client_state& st, const std::vector<uint8_t>& diss, lnl::DELIVERY_METHOD delivery);
    void send_dissonance_to_client(client_state& st, const std::vector<uint8_t>& diss, lnl::DELIVERY_METHOD delivery);
    void send_time_sync(client_state& st, int tick);
    void send_message(client_state& st, const char* full_name, const std::vector<uint8_t>& body,
                      lnl::DELIVERY_METHOD delivery);

    int local_version(const char* full_name) const;
    int index_of(const char* full_name) const;
};
