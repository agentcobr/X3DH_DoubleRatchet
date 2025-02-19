#include "doubleratchet.h"
#include "x3dh_protocol.h"
#include "common_types.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <QByteArray>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

std::pair<QByteArray, int> DoubleRatchet::deriveMessageKey(bool isSender) {
    QByteArray& chainKey = isSender ? state.chainKeySend : state.chainKeyRecv;
    qDebug() << "Using chain key:" << chainKey.toHex().left(32)
             << "for" << (isSender ? "sending" : "receiving");

    int& messageIndex = isSender ? state.messageIndexSend : state.messageIndexRecv;

    QByteArray prk = kdfExtract(chainKey, "Message Key");
    QByteArray messageKey = kdfExpand(prk, "AES-GSM", 32);

    chainKey = kdfExpand(prk, "Chain Key", 32);

    int currentIndex = messageIndex;
    messageIndex++;

    return {messageKey, currentIndex};
}

void DoubleRatchet::initialize(const QByteArray& sharedSecret, const KeyPair& myDH, bool isAlice) {
    state.rootKey = kdfExtract(sharedSecret, "DR-Root-Key");

    state.dhKey = myDH;

    QByteArray chainKeys = kdfExpand(state.rootKey, "Chain-Keys", 64);

    state.chainKeySend = isAlice ? chainKeys.left(32) : chainKeys.mid(32);
    state.chainKeyRecv = isAlice ? chainKeys.mid(32) : chainKeys.left(32);

    state.messageIndexSend = 0;
    state.messageIndexRecv = 0;
}

void DoubleRatchet::dhRatchet(const QByteArray& remotePublicKey) {
    X3DHProtocol protocol;
    KeyPair newDH = protocol.generateDHKeyPair();

    QByteArray dhOutput = protocol.computeSharedSecret(newDH, remotePublicKey);

    QByteArray prk = kdfExtract(state.rootKey + dhOutput, "Ratchet-Step");
    state.rootKey = kdfExpand(prk, "New-Root-Key", 32);

    state.chainKeySend = kdfExpand(prk, "Send-Chain-Key", 32);

    state.dhKey = newDH;

    state.messageIndexSend = 0;
    state.messageIndexRecv = 0;
}

QByteArray DoubleRatchet::kdfExtract(const QByteArray& inputKeyMaterial, const QByteArray& salt) {

    Q_ASSERT(!inputKeyMaterial.isEmpty());
    Q_ASSERT(inputKeyMaterial.size() >= 32);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    QByteArray prk(32, 0);

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_KDF_HKDF_MODE_EXTRACT_ONLY);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>(salt.data()), salt.size());
    EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const unsigned char*>(inputKeyMaterial.data()), inputKeyMaterial.size());

    size_t prkLen = 32;
    EVP_PKEY_derive(pctx, reinterpret_cast<unsigned char*>(prk.data()), &prkLen);
    EVP_PKEY_CTX_free(pctx);
    return prk;
}

QByteArray DoubleRatchet::kdfExpand(const QByteArray& prk, const QByteArray& info, int outputSize) {

    Q_ASSERT(outputSize > 0 && outputSize <= 64);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    QByteArray dkm(outputSize, 0);

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const unsigned char*>(prk.data()), prk.size());
    EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()), info.size());

    size_t dkmLen = outputSize;
    EVP_PKEY_derive(pctx, reinterpret_cast<unsigned char*>(dkm.data()), &dkmLen);
    EVP_PKEY_CTX_free(pctx);
    return dkm;
}

QByteArray DoubleRatchet::padData(const QByteArray &input) {
    int padLength = 16 - (input.size() % 16);
    QByteArray padded = input;
    padded.append(QByteArray(padLength, char(padLength)));
    return padded;
}

QByteArray DoubleRatchet::unpadData(const QByteArray &input) {
    if (input.isEmpty()) return QByteArray();
    char padLength = input[input.size() - 1];
    return input.left(input.size() - padLength);
}

QByteArray DoubleRatchet::encryptMessage(const QByteArray& message, QByteArray& iv, QByteArray& tag, int& messageIndex) {
    auto [key, index] = deriveMessageKey(true);
    qDebug() << "Encrypt Key:" << key.toHex().left(8) << "Index:" << index;

    messageIndex = index;

    if (key.size() != 32) {
        throw std::runtime_error("Invalid encryption key size");
    }

    const int ivSize = 12;
    iv.resize(ivSize);
    if (!RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), ivSize)) {
        throw std::runtime_error("IV generation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    QByteArray ciphertext(message.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0, ciphertextLen = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.constData()),
                                reinterpret_cast<const unsigned char*>(iv.constData()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption initialization failed");
    }

    if (1 != EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                               reinterpret_cast<const unsigned char*>(message.constData()),
                               message.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    ciphertextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                                 &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertextLen += len;

    tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Tag extraction failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertextLen);
    return ciphertext;
}

QByteArray DoubleRatchet::decryptMessage(const QByteArray& ciphertext, const QByteArray& iv, const QByteArray& tag, int messageIndex) {
    auto [key, expectedIndex] = deriveMessageKey(false);  // Генерируем ключ для приёма
    qDebug() << "Decrypt Key:" << key.toHex().left(8) << "Expected Index:" << expectedIndex;


    if (messageIndex != expectedIndex) {
        qDebug() << "Index mismatch! Expected:" << expectedIndex << "Got:" << messageIndex;
        throw std::runtime_error("Index error");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    QByteArray decryptedMessage(ciphertext.size(), 0);
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedMessage.data()), &len,
                      reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.data()));

    if (EVP_DecryptFinal_ex(ctx, nullptr, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return decryptedMessage;
}
