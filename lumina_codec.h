#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>

namespace lumina {

// ---------- dd / dq encoders (match dazhbog/src/legacy.rs) ----------

// Encode u32 in "dd" variable-length format
inline void pack_dd_into(std::vector<uint8_t>& out, uint32_t v) {
    if (v <= 0x7Fu) {
        out.push_back(static_cast<uint8_t>(v));
        return;
    }
    if (v <= 0x3FFFu) {
        // 10xxxxxx yyyyyyyy  (little-endian mapping)
        uint8_t b0 = 0x80u | static_cast<uint8_t>((v >> 8) & 0x3Fu);
        uint8_t b1 = static_cast<uint8_t>(v & 0xFFu);
        out.push_back(b0); out.push_back(b1);
        return;
    }
    if (v <= 0x1FFFFFu) {
        // 11000000 yyyyyyyy zzzzzzzz wwwwwwww
        uint8_t b0 = 0xC0u;
        uint8_t b1 = static_cast<uint8_t>((v >> 16) & 0xFFu);
        uint8_t b2 = static_cast<uint8_t>((v >> 8)  & 0xFFu);
        uint8_t b3 = static_cast<uint8_t>(v & 0xFFu);
        out.push_back(b0); out.push_back(b1); out.push_back(b2); out.push_back(b3);
        return;
    }
    // Five-byte: 0xFF + 32-bit big-endian
    out.push_back(0xFFu);
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

inline std::vector<uint8_t> pack_dd(uint32_t v) { std::vector<uint8_t> o; o.reserve(5); pack_dd_into(o, v); return o; }

// Encode u64 as two dd-encoded u32 (high, low)
inline void pack_dq_into(std::vector<uint8_t>& out, uint64_t v) {
    pack_dd_into(out, static_cast<uint32_t>(v >> 32));
    pack_dd_into(out, static_cast<uint32_t>(v & 0xFFFFFFFFu));
}

// dd-length-prefixed bytes
inline void pack_var_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    pack_dd_into(out, static_cast<uint32_t>(len));
    if (len != 0)  // avoid UB on null pointer
        out.insert(out.end(), data, data + len);
}

// Null-terminated C string
inline void pack_cstr(std::vector<uint8_t>& out, const std::string& s) {
    out.insert(out.end(), s.begin(), s.end());
    out.push_back(0);
}

// ---------- function container for PushMetadata ----------

struct EncodedFunction {
    std::string name;               // function display name
    uint32_t    func_len = 0;       // length-in-bytes metric (e.g., sum of BB bytes)
    std::vector<uint8_t> func_data; // TLV-like payload (arbitrary; server stores/returns)
    std::array<uint8_t, 16> hash{}; // 16-byte fingerprint (key)
    uint32_t    unk2 = 0;           // reserved, keep 0
};

// Legacy Hello (0x0d) payload: dd(protocol)=5, dd(len=0), 6x00, dd(0) ; no username/password (=> "guest")
inline std::vector<uint8_t> encode_hello_payload(uint32_t protocol_version = 5) {
    std::vector<uint8_t> p;
    pack_dd_into(p, protocol_version);
    pack_var_bytes(p, nullptr, 0);                 // empty license_data
    p.insert(p.end(), 6, 0);                       // lic_number (6 bytes)
    pack_dd_into(p, 0);                            // unk2
    // omit user/pass to default to "guest" (per server)
    return p;
}

// Legacy PushMetadata (0x10) payload
inline std::vector<uint8_t> encode_push_payload(
    uint32_t unk0,
    const std::string& idb_path,
    const std::string& file_path,
    const std::array<uint8_t, 16>& md5_of_binary,
    const std::string& hostname,
    const std::vector<EncodedFunction>& funcs,
    const std::vector<uint64_t>& tail_unk1 // usually empty
) {
    std::vector<uint8_t> p;
    // header
    pack_dd_into(p, unk0);
    pack_cstr(p, idb_path);
    pack_cstr(p, file_path);
    p.insert(p.end(), md5_of_binary.begin(), md5_of_binary.end());
    pack_cstr(p, hostname);
    // functions
    pack_dd_into(p, static_cast<uint32_t>(funcs.size()));
    for (const auto& f : funcs) {
        pack_cstr(p, f.name);
        pack_dd_into(p, f.func_len);
        pack_var_bytes(p, f.func_data.data(), f.func_data.size());
        pack_dd_into(p, f.unk2);
        // hash as dd-len + bytes (server expects 16)
        pack_dd_into(p, 16);
        p.insert(p.end(), f.hash.begin(), f.hash.end());
    }
    // tail (vector<u64> as two dd-encoded u32s)
    pack_dd_into(p, static_cast<uint32_t>(tail_unk1.size()));
    for (auto v : tail_unk1) pack_dq_into(p, v);
    return p;
}

// Encode legacy PullMetadata (0x0e)
// unk0=0; unk1 (u32 vec) empty; funcs = array of {func_unk0=0, mb_hash: dd-len(16)+bytes}
inline std::vector<uint8_t> encode_pull_payload(
    uint32_t unk0,
    const std::vector<std::array<uint8_t,16>>& hashes
){
    std::vector<uint8_t> p;
    pack_dd_into(p, unk0);
    pack_dd_into(p, 0); // unk1 count = 0
    pack_dd_into(p, static_cast<uint32_t>(hashes.size())); // funcs count
    for (const auto& h : hashes) {
        pack_dd_into(p, 0); // per-func unk0
        pack_dd_into(p, 16);
        p.insert(p.end(), h.begin(), h.end());
    }
    return p;
}

} // namespace lumina

