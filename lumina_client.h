#pragma once
#include <QObject>
#include <QTcpSocket>
#include <QHostAddress>
#include <QCryptographicHash>
#include <vector>
#include <cstdint>
#include <string>

// Check for SSL support at compile time
#ifndef QT_NO_SSL
#include <QSslSocket>
#include <QSslConfiguration>
#define LUMINA_HAS_SSL 1
#else
#define LUMINA_HAS_SSL 0
#endif

namespace lumina {

struct PulledFunction {
    uint32_t popularity = 0;
    uint32_t len = 0;
    std::string name;
    std::vector<uint8_t> data; // TLV bytes
};

// Client for Lumina protocol with TLS support
class Client : public QObject {
    Q_OBJECT

public:
    explicit Client(const QString& host, quint16 port, QObject* parent = nullptr,
                    bool useTls = false, bool verifyTls = true)
        : QObject(parent), m_host(host), m_port(port), m_useTls(useTls), m_verifyTls(verifyTls) {}

    // Static factory method using settings
    static Client* fromSettings(QObject* parent = nullptr);

    // Sends Hello + Push; returns true on success, fills statuses (0=new? per server doc: PushResult is array of u32)
    bool helloAndPush(const std::vector<uint8_t>& helloPayload,
                      const std::vector<uint8_t>& pushPayload,
                      QString* err,
                      std::vector<uint32_t>* outStatuses,
                      int timeoutMs = 5000);

    // NEW: Pull
    bool helloAndPull(const std::vector<uint8_t>& helloPayload,
                      const std::vector<uint8_t>& pullPayload,
                      QString* err,
                      std::vector<uint32_t>* outStatuses,
                      std::vector<PulledFunction>* outFuncs,
                      int timeoutMs = 5000);

private:
    QString m_host;
    quint16 m_port;
    bool m_useTls;
    bool m_verifyTls;

    // Create and connect socket (returns QTcpSocket* or QSslSocket* depending on m_useTls)
    QTcpSocket* createSocket(QString* err, int timeoutMs);

    static QByteArray makePacket(uint8_t type, const std::vector<uint8_t>& payload) {
        QByteArray a;
        uint32_t len = static_cast<uint32_t>(payload.size());
        char be[4] = { static_cast<char>((len >> 24) & 0xFF),
                       static_cast<char>((len >> 16) & 0xFF),
                       static_cast<char>((len >> 8) & 0xFF),
                       static_cast<char>(len & 0xFF) };
        a.append(be, 4);
        a.append(static_cast<char>(type));
        if (!payload.empty()) a.append(reinterpret_cast<const char*>(payload.data()), payload.size());
        return a;
    }

    static bool readPacket(QTcpSocket& s, uint8_t* outType, QByteArray* outPayload, int timeoutMs);
    static bool unpack_dd(const uint8_t* p, size_t n, uint32_t& val, size_t& consumed);

    // NEW helpers
    static bool unpack_cstr(const uint8_t* p, size_t n, std::string& s, size_t& used);
    static bool unpack_var_bytes(const uint8_t* p, size_t n, const uint8_t** bytes, size_t& blen, size_t& used);
};

} // namespace lumina

