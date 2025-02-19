#ifndef DOUBLERATCHET_H
#define DOUBLERATCHET_H

#include "common_types.h"
#include <utility>

class DoubleRatchet {
private:
    RatchetState state;

    QByteArray kdfExtract(const QByteArray& inputKeyMaterial, const QByteArray& salt);

    QByteArray kdfExpand(const QByteArray& prk, const QByteArray& info, int outputSize);

public:
    const RatchetState& getState() const { return state; }

    void initialize(const QByteArray& sharedSecret,
                    const KeyPair& myDH, bool isAlice);
    std::pair<QByteArray, int> deriveMessageKey(bool isSender);
    void dhRatchet(const QByteArray& remotePublicKey);

    QByteArray padData(const QByteArray &input);
    QByteArray unpadData(const QByteArray &input);

    QByteArray encryptMessage(const QByteArray& message, QByteArray& iv,
                              QByteArray& tag, int& messageIndex);
    QByteArray decryptMessage(const QByteArray& ciphertext, const QByteArray& iv,
                              const QByteArray& tag, int messageIndex);
};

#endif // DOUBLERATCHET_H
