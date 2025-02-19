#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <QByteArray>

struct KeyPair {
    QByteArray privateKey;
    QByteArray publicKey;
};

struct KeyStorage {
    KeyPair IK;
    KeyPair EK;
    KeyPair SPK;
    KeyPair OPK;
};

struct RatchetState {
    QByteArray rootKey;
    QByteArray chainKeySend;
    QByteArray chainKeyRecv;
    KeyPair dhKey;

    int messageIndexSend = 0;
    int messageIndexRecv = 0;
};

struct EncryptedMessage {
    QByteArray cipher;
    QByteArray iv;
    QByteArray tag;
    int index;
};

#endif // COMMON_TYPES_H
