#ifndef X3DH_PROTOCOL_H
#define X3DH_PROTOCOL_H

#include <QMainWindow>
#include <QByteArray>
#include <common_types.h>

class X3DHProtocol {
public:
    static KeyPair generateDHKeyPair();
    static KeyPair generateSignKeyPair();

    static KeyPair generateIK();
    static KeyPair generateEK();
    static KeyPair generateSPK();

    QByteArray signData(const QByteArray& data, const QByteArray& privateKey);
    bool verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& publicKey);

    static QByteArray computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey);

    QByteArray X3DH(const KeyPair& localIK, const KeyPair& localEK,
                    const KeyPair& remoteIK, const KeyPair& remoteSPK,
                    const KeyPair& signKey, const QByteArray& signDataKey);
private:
    static void handleOpenSSLError(const std::string& message);

};

#endif // X3DH_PROTOCOL_H
