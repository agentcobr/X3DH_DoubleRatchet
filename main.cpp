#include "x3dh_protocol.h"
#include "doubleratchet.h"
#include <QDebug>
#include <iostream>
#include <QCoreApplication>
#include <QStringList>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    try {
        X3DHProtocol protocol;

        KeyPair ikAlice = protocol.generateIK();
        KeyPair ekAlice = protocol.generateEK();

        KeyPair keySignBob = protocol.generateSignKeyPair();
        KeyPair spkBob = protocol.generateSPK();
        KeyPair ikBob = protocol.generateIK();

        QByteArray dataSignedBob = protocol.signData(spkBob.publicKey, keySignBob.privateKey);

        QByteArray sharedSecretAlice = protocol.X3DH(ikAlice, ekAlice, ikBob,
                                                     spkBob, keySignBob,
                                                     dataSignedBob);

        QByteArray sharedSecretBob = protocol.X3DH(ikBob, spkBob, ikAlice,
                                                   ekAlice, {}, {});

        DoubleRatchet Alice, Bob;

        Alice.initialize(sharedSecretAlice, protocol.generateDHKeyPair(), true);
        Bob.initialize(sharedSecretBob, protocol.generateDHKeyPair(), false);

        QByteArray iv, tag;
        int msgIndex;
        QByteArray cipher = Alice.encryptMessage("Hello, Bob", iv, tag, msgIndex);
        qDebug() << "\nAlice encrypted message 1. Index:" << msgIndex;

        QByteArray decrypted = Bob.decryptMessage(cipher, iv, tag, msgIndex);
        qDebug() << "Bob decrypted 1:" << decrypted;
        if(decrypted != "Hello, Bob") throw std::runtime_error("Message 1 corrupted");

        QByteArray bobIv, bobTag;
        int bobIndex;
        QByteArray bobCipher = Bob.encryptMessage("Hi Alice!", bobIv, bobTag, bobIndex);
        qDebug() << "\nBob encrypted reply 1. Index:" << bobIndex;

        QByteArray aliceDecrypted = Alice.decryptMessage(bobCipher, bobIv, bobTag, bobIndex);
        qDebug() << "Alice decrypted reply 1:" << aliceDecrypted;
        if(aliceDecrypted != "Hi Alice!") throw std::runtime_error("Reply 1 corrupted");

        QStringList conversation = {
            "How is the weather?",
            "Want to meet tomorrow?",
            "I'd like to visit a museum!"
        };

        for(int i = 0; i < conversation.size(); i++) {
            QByteArray aIv, aTag;
            int aIndex;
            QByteArray aCipher = Alice.encryptMessage(conversation[i].toUtf8(), aIv, aTag, aIndex);
            qDebug() << "\nAlice encrypted message" << i+2 << ". Index:" << aIndex;

            QByteArray bDecrypted;
            try {
                bDecrypted = Bob.decryptMessage(aCipher, aIv, aTag, aIndex);
            } catch(const std::exception& e) {
                qCritical() << "Bob failed to decrypt message" << i+2 << ":" << e.what();
                throw;
            }
            qDebug() << "Bob decrypted" << i+2 << ":" << bDecrypted;

            QByteArray bIv, bTag;
            int bIndex;
            QString receipt = "Received: " + QString(bDecrypted);
            QByteArray bCipher = Bob.encryptMessage(receipt.toUtf8(), bIv, bTag, bIndex);
            qDebug() << "Bob encrypted receipt" << i+2 << ". Index:" << bIndex;

            QByteArray aDecrypted;
            try {
                aDecrypted = Alice.decryptMessage(bCipher, bIv, bTag, bIndex);
            } catch(const std::exception& e) {
                qCritical() << "Alice failed to decrypt receipt" << i+2 << ":" << e.what();
                throw;
            }
            qDebug() << "Alice decrypted receipt" << i+2 << ":" << aDecrypted;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
