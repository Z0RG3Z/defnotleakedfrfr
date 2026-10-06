#pragma once
//
// RSA private key loaded from .NET RSAKeyValue XML (RSA.ToXmlString), used to decrypt the client's
// wire blobs (AT/VB/CKA/CIA/CPK) which are RSA-encrypted to the matching public key. Wraps OpenSSL;
// no OpenSSL types leak into the header.
//
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Standard base64 decode (ignores whitespace). Empty result on malformed input.
std::vector<uint8_t> base64_decode(const std::string& in);

// AES-CBC decrypt. key_len picks the variant (16/24/32 -> AES-128/192/256); iv is 16 bytes; data
// length must be a non-zero multiple of 16. With strip_padding, PKCS#7 padding is removed (and a
// bad pad fails); without it, the raw blocks are returned. Returns nullopt on any failure.
std::optional<std::vector<uint8_t>> aes_cbc_decrypt(const uint8_t* key, size_t key_len,
                                                    const uint8_t* iv, const uint8_t* data,
                                                    size_t len, bool strip_padding = true);

// Verify a compact JWT (JWS) signed with HS256 against the shared HMAC secret. Requires the header
// to declare alg=HS256 (alg=none and asymmetric algs are refused) and the signature to match.
// Returns the decoded payload JSON on success; nullopt on any malformed/failed check. Claim checks
// (exp/nbf/sub) are the caller's responsibility, on the returned payload.
std::optional<std::string> jwt_verify_hs256(const std::string& token, const std::string& secret);

class rsa_key {
public:
    rsa_key() = default;
    ~rsa_key();
    rsa_key(const rsa_key&) = delete;
    rsa_key& operator=(const rsa_key&) = delete;

    // Build from .NET RSAKeyValue XML. Returns false and sets `err` on failure.
    bool load_xml(const std::string& xml, std::string& err);
    bool valid() const { return m_pkey != nullptr; }
    int bits() const;

    // RSA-decrypt one ciphertext block, trying PKCS#1 v1.5 then OAEP(SHA-1) (the two .NET defaults).
    // Returns nullopt if neither padding yields a valid plaintext.
    std::optional<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len) const;

private:
    void* m_pkey = nullptr;   // EVP_PKEY*
};
