#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "lumina_codec.h"

namespace lumina {

// Simple TLV (Tag=u32 dd-encoded, Len=u32 dd-encoded, Val=bytes).
inline void tlv_emit(std::vector<uint8_t>& out, uint32_t tag, const std::vector<uint8_t>& val) {
    pack_dd_into(out, tag);
    pack_dd_into(out, static_cast<uint32_t>(val.size()));
    out.insert(out.end(), val.begin(), val.end());
}

// Build a compact function-metadata TLV set. Tags chosen for compatibility flavor.
inline std::vector<uint8_t> build_function_tlv(bool noReturn, const std::string& comment,
                                               const std::vector<std::string>& varNames) {
    std::vector<uint8_t> out;

    // Tag 1: type flags (bit0 = no-return)
    {
        std::vector<uint8_t> v(1, noReturn ? 1u : 0u);
        tlv_emit(out, 1, v);
    }

    // Tag 3: comment (utf-8)
    if (!comment.empty()) {
        std::vector<uint8_t> v(comment.begin(), comment.end());
        tlv_emit(out, 3, v);
    }

    // Tag 9: variable names (dd count + cstrs)
    {
        std::vector<uint8_t> v;
        pack_dd_into(v, static_cast<uint32_t>(varNames.size()));
        for (const auto& n : varNames) pack_cstr(v, n);
        tlv_emit(out, 9, v);
    }

    return out;
}

// ---------- TLV Parser ----------

struct ParsedTLV {
    bool hasNoReturn = false;
    bool noReturn = false;
    std::string comment;
    std::vector<std::string> varNames;
};

// dd decoder (minimal)
inline bool unpack_dd(const uint8_t* p, size_t n, uint32_t& val, size_t& used) {
    if (n == 0) { used = 0; return false; }
    uint8_t b0 = p[0];
    if ((b0 & 0x80u) == 0) { val = b0; used = 1; return true; }
    if ((b0 & 0xC0u) == 0x80u) {
        if (n < 2) { used = 0; return false; }
        val = ((uint32_t)(b0 & 0x3Fu) << 8) | p[1]; used = 2; return true;
    }
    if ((b0 & 0xE0u) == 0xC0u) {
        if (n < 4) { used = 0; return false; }
        val = (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) | ((uint32_t)(b0 & 0x1Fu) << 24);
        used = 4; return true;
    }
    if (b0 == 0xFFu) {
        if (n < 5) { used = 0; return false; }
        val = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | (uint32_t)p[4];
        used = 5; return true;
    }
    if (n < 4) { used = 0; return false; }
    val = ((uint32_t)(b0 & 0x1Fu) << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    used = 4; return true;
}

inline bool parse_function_tlv(const std::vector<uint8_t>& data, ParsedTLV* out) {
    const uint8_t* p = data.data();
    size_t n = data.size();
    while (n > 0) {
        uint32_t tag=0, len=0; size_t u=0;
        if (!unpack_dd(p, n, tag, u) || u==0) return false; p+=u; n-=u;
        if (!unpack_dd(p, n, len, u) || u==0) return false; p+=u; n-=u;
        if (n < len) return false;
        const uint8_t* v = p; p += len; n -= len;

        switch (tag) {
            case 1: // flags
                if (len >= 1) { out->hasNoReturn = true; out->noReturn = (v[0] != 0); }
                break;
            case 3: // comment utf-8
                out->comment.assign(reinterpret_cast<const char*>(v), reinterpret_cast<const char*>(v)+len);
                break;
            case 9: { // variables: dd(count) + cstrs
                const uint8_t* q=v; size_t m=len, uu=0; uint32_t count=0;
                if (!unpack_dd(q, m, count, uu) || uu==0) break;
                q+=uu; m-=uu;
                out->varNames.clear(); out->varNames.reserve(count);
                for (uint32_t i=0;i<count;i++) {
                    const uint8_t* s=q; size_t k=0; while (k<m && s[k]!=0) k++;
                    if (k>=m) break;
                    out->varNames.emplace_back(reinterpret_cast<const char*>(s), reinterpret_cast<const char*>(s)+k);
                    q += (k+1); m -= (k+1);
                }
                break;
            }
            default: break; // unknown tag => skip
        }
    }
    return true;
}

} // namespace lumina

