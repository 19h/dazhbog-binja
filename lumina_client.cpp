#include "lumina_client.h"
#include <QDeadlineTimer>

namespace lumina {

bool Client::readPacket(QTcpSocket& s, uint8_t* outType, QByteArray* outPayload, int timeoutMs) {
    if (!s.waitForReadyRead(timeoutMs)) return false;
    QByteArray hdr = s.peek(5);
    while (hdr.size() < 5) {
        if (!s.waitForReadyRead(timeoutMs)) return false;
        hdr = s.peek(5);
    }
    s.read(5);
    const uint8_t* h = reinterpret_cast<const uint8_t*>(hdr.constData());
    uint32_t len = (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) | (uint32_t(h[2]) << 8) | uint32_t(h[3]);
    *outType = h[4];
    outPayload->clear();
    outPayload->reserve(len);
    while (static_cast<uint32_t>(outPayload->size()) < len) {
        if (!s.waitForReadyRead(timeoutMs)) return false;
        const qint64 need = qint64(len) - qint64(outPayload->size());
        outPayload->append(s.read(need));
    }
    return true;
}

bool Client::unpack_dd(const uint8_t* p, size_t n, uint32_t& val, size_t& consumed) {
    if (n == 0) { consumed = 0; return false; }
    uint8_t b0 = p[0];
    if ((b0 & 0x80u) == 0) { val = b0; consumed = 1; return true; }
    if ((b0 & 0xC0u) == 0x80u) {
        if (n < 2) { consumed = 0; return false; }
        val = ((uint32_t)(b0 & 0x3Fu) << 8) | p[1];
        consumed = 2; return true;
    }
    if ((b0 & 0xE0u) == 0xC0u) {
        if (n < 4) { consumed = 0; return false; }
        // little-endian reconstruction: [data3 data2 data1 (b0&0x1F)]
        val = (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) | ((uint32_t)(b0 & 0x1Fu) << 24);
        consumed = 4; return true;
    }
    if (b0 == 0xFFu) {
        if (n < 5) { consumed = 0; return false; }
        val = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | (uint32_t)p[4];
        consumed = 5; return true;
    }
    if (n < 4) { consumed = 0; return false; }
    val = ((uint32_t)(b0 & 0x1Fu) << 24) | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
    consumed = 4; return true;
}

bool Client::helloAndPush(const std::vector<uint8_t>& helloPayload,
                          const std::vector<uint8_t>& pushPayload,
                          QString* err,
                          std::vector<uint32_t>* outStatuses,
                          int timeoutMs) {
    QTcpSocket sock;
    sock.connectToHost(m_host, m_port);
    if (!sock.waitForConnected(timeoutMs)) {
        if (err) *err = "connect failed";
        return false;
    }

    // Hello (0x0d)
    QByteArray helloPkt = makePacket(0x0d, helloPayload);
    if (sock.write(helloPkt) != helloPkt.size() || !sock.waitForBytesWritten(timeoutMs)) {
        if (err) *err = "hello write failed";
        return false;
    }

    // Read Hello result (0x0a or 0x31)
    uint8_t t = 0; QByteArray payload;
    if (!readPacket(sock, &t, &payload, timeoutMs)) { if (err) *err = "hello read failed"; return false; }
    if (t != 0x0a && t != 0x31) { if (err) *err = "unexpected hello response"; return false; }

    // Push (0x10)
    QByteArray pushPkt = makePacket(0x10, pushPayload);
    if (sock.write(pushPkt) != pushPkt.size() || !sock.waitForBytesWritten(timeoutMs)) {
        if (err) *err = "push write failed";
        return false;
    }

    if (!readPacket(sock, &t, &payload, timeoutMs)) { if (err) *err = "push read failed"; return false; }
    if (t != 0x11) { if (err) *err = "unexpected push result type"; return false; }

    // Parse PushMetadataResult: dd(count) then count * dd(status)
    const uint8_t* p = reinterpret_cast<const uint8_t*>(payload.constData());
    size_t n = (size_t)payload.size(), off = 0, ccons = 0;
    uint32_t count = 0;
    if (!unpack_dd(p, n, count, ccons) || ccons == 0) { if (err) *err = "malformed result"; return false; }
    off += ccons; p += ccons; n -= ccons;

    outStatuses->clear();
    outStatuses->reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t s = 0; size_t cc = 0;
        if (!unpack_dd(p, n, s, cc) || cc == 0) { if (err) *err = "malformed status"; return false; }
        outStatuses->push_back(s);
        p += cc; n -= cc;
    }

    return true;
}

bool Client::unpack_cstr(const uint8_t* p, size_t n, std::string& s, size_t& used) {
    size_t i=0; for (; i<n; ++i) if (p[i]==0) break;
    if (i>=n) { used=0; return false; }
    s.assign(reinterpret_cast<const char*>(p), i);
    used = i+1; return true;
}

bool Client::unpack_var_bytes(const uint8_t* p, size_t n, const uint8_t** bytes, size_t& blen, size_t& used) {
    uint32_t L=0; size_t c=0;
    if (!unpack_dd(p, n, L, c) || c==0) { used=0; return false; }
    p+=c; n-=c;
    if (n < L) { used=0; return false; }
    *bytes = p; blen = L; used = c + L; return true;
}

bool Client::helloAndPull(const std::vector<uint8_t>& helloPayload,
                          const std::vector<uint8_t>& pullPayload,
                          QString* err,
                          std::vector<uint32_t>* outStatuses,
                          std::vector<PulledFunction>* outFuncs,
                          int timeoutMs) {
    QTcpSocket sock;
    sock.connectToHost(m_host, m_port);
    if (!sock.waitForConnected(timeoutMs)) { if (err) *err = "connect failed"; return false; }

    // Hello
    QByteArray helloPkt = makePacket(0x0d, helloPayload);
    if (sock.write(helloPkt) != helloPkt.size() || !sock.waitForBytesWritten(timeoutMs)) {
        if (err) *err = "hello write failed"; return false;
    }
    uint8_t t = 0; QByteArray payload;
    if (!readPacket(sock, &t, &payload, timeoutMs)) { if (err) *err = "hello read failed"; return false; }
    if (t != 0x0a && t != 0x31) { if (err) *err = "unexpected hello response"; return false; }

    // Pull
    QByteArray pullPkt = makePacket(0x0e, pullPayload);
    if (sock.write(pullPkt) != pullPkt.size() || !sock.waitForBytesWritten(timeoutMs)) {
        if (err) *err = "pull write failed"; return false;
    }
    if (!readPacket(sock, &t, &payload, timeoutMs)) { if (err) *err = "pull read failed"; return false; }
    if (t != 0x0f) { if (err) *err = "unexpected pull result type"; return false; }

    // Decode 0x0f: statuses, funcs
    const uint8_t* p = reinterpret_cast<const uint8_t*>(payload.constData());
    size_t n = (size_t)payload.size(), u=0;

    uint32_t sc=0; if (!unpack_dd(p, n, sc, u) || u==0) { if (err) *err="malformed statuses count"; return false; }
    p+=u; n-=u;
    outStatuses->clear(); outStatuses->reserve(sc);
    for (uint32_t i=0;i<sc;i++) {
        uint32_t s=0; if (!unpack_dd(p, n, s, u) || u==0) { if (err) *err="malformed status"; return false; }
        outStatuses->push_back(s); p+=u; n-=u;
    }

    uint32_t fc=0; if (!unpack_dd(p, n, fc, u) || u==0) { if (err) *err="malformed funcs count"; return false; }
    p+=u; n-=u;
    outFuncs->clear(); outFuncs->reserve(fc);
    for (uint32_t i=0;i<fc;i++) {
        PulledFunction f;
        std::string nm; if (!unpack_cstr(p, n, nm, u) || u==0) { if (err) *err="malformed name"; return false; }
        p+=u; n-=u; f.name = std::move(nm);

        uint32_t flen=0; if (!unpack_dd(p, n, flen, u) || u==0) { if (err) *err="malformed len"; return false; }
        p+=u; n-=u; f.len = flen;

        const uint8_t* db=nullptr; size_t dlen=0, uu=0;
        if (!unpack_var_bytes(p, n, &db, dlen, uu) || uu==0) { if (err) *err="malformed data"; return false; }
        p+=uu; n-=uu; f.data.assign(db, db+dlen);

        uint32_t pop=0; if (!unpack_dd(p, n, pop, u) || u==0) { if (err) *err="malformed popularity"; return false; }
        p+=u; n-=u; f.popularity = pop;

        outFuncs->push_back(std::move(f));
    }

    return true;
}

} // namespace lumina

