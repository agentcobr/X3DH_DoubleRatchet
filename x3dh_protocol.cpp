#include <x3dh_protocol.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <QCryptographicHash>

void X3DHProtocol::handleOpenSSLError(const std::string& message) {
    char errBuf[120];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    throw std::runtime_error(message + ": " + errBuf);
}

KeyPair X3DHProtocol::generateDHKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx)
        handleOpenSSLError("Failed to create context");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Keygen init failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Key generation failed");
    }

    BIO* bio_priv = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio_priv);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Failed to write private key");
    }

    BIO* bio_pub = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) {
        BIO_free(bio_pub);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Failed to write public key");
    }

    BUF_MEM *bptr_priv = nullptr, *bptr_pub = nullptr;
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    BIO_get_mem_ptr(bio_pub, &bptr_pub);

    KeyPair result {
        QByteArray(bptr_priv->data, bptr_priv->length),
        QByteArray(bptr_pub->data, bptr_pub->length)
    };

    BIO_free(bio_priv);
    BIO_free(bio_pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

KeyPair X3DHProtocol::generateSignKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx)
        handleOpenSSLError("Failed to create context");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Keygen init failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Key generation failed");
    }

    BIO* bio_priv = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio_priv);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Failed to write private key");
    }

    BIO* bio_pub = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) {
        BIO_free(bio_pub);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("Failed to write public key");
    }

    BUF_MEM *bptr_priv = nullptr, *bptr_pub = nullptr;
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    BIO_get_mem_ptr(bio_pub, &bptr_pub);

    KeyPair result {
        QByteArray(bptr_priv->data, bptr_priv->length),
        QByteArray(bptr_pub->data, bptr_pub->length)
    };

    BIO_free(bio_priv);
    BIO_free(bio_pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

KeyPair X3DHProtocol::generateIK(){
    return generateDHKeyPair();
}

KeyPair X3DHProtocol::generateEK(){
    return generateDHKeyPair();
}

KeyPair X3DHProtocol::generateSPK() {
    return generateDHKeyPair();
}

QByteArray X3DHProtocol::signData(const QByteArray& data, const QByteArray& privateKey) {
    BIO* bioPrivate = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bioPrivate) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bioPrivate, nullptr, nullptr, nullptr);
    BIO_free(bioPrivate);
    /*
    if (!pkey) {
        throw std::runtime_error("Failed to read private key");
    }
    */
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Private key is not an ED25519 key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    size_t siglen = 0;
    if (EVP_DigestSign(ctx, nullptr, &siglen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to determine signature length");
    }

    QByteArray signature(siglen, 0);
    if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(signature.data()), &siglen,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign data");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool X3DHProtocol::verifySignature(const QByteArray& data, const QByteArray& signature, const QByteArray& publicKey) {
    BIO* bioPublic = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    if (!bioPublic)
        throw std::runtime_error("Failed to create BIO for public key");

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bioPublic, nullptr, nullptr, nullptr);
    BIO_free(bioPublic);
    if (!pkey)
        throw std::runtime_error("Failed to read public key");

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Public key is not an ED25519 key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize verification");
    }

    int result = EVP_DigestVerify(ctx,
                                  reinterpret_cast<const unsigned char*>(signature.data()),
                                  signature.size(),
                                  reinterpret_cast<const unsigned char*>(data.data()),
                                  data.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result == 1;
}

QByteArray X3DHProtocol::computeSharedSecret(const KeyPair& localKey, const QByteArray& remotePublicKey) {
    BIO* privBio = BIO_new_mem_buf(localKey.privateKey.data(), localKey.privateKey.size());
    if (!privBio)
        throw std::runtime_error("Failed to create BIO for private key.");

    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(privBio, nullptr, nullptr, nullptr);
    BIO_free(privBio);
    if (!privKey) {
        char errBuff[120];
        ERR_error_string_n(ERR_get_error(), errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to read private key: ") + errBuff);
    }

    BIO* pubBio = BIO_new_mem_buf(remotePublicKey.data(), remotePublicKey.size());
    if (!pubBio)
        throw std::runtime_error("Failed to create BIO for public key.");

    EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(pubBio, nullptr, nullptr, nullptr);
    BIO_free(pubBio);
    if (!pubKey) {
        char errBuff[120];
        ERR_error_string_n(ERR_get_error(), errBuff, sizeof(errBuff));
        throw std::runtime_error(std::string("Failed to read public key: ") + errBuff);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        throw std::runtime_error("Failed to create context for shared secret computation.");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        throw std::runtime_error("Failed to initialize context for shared secret computation.");
    }

    if (EVP_PKEY_derive_set_peer(ctx, pubKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        throw std::runtime_error("Failed to set peer key for shared secret computation.");
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        throw std::runtime_error("Failed to determine shared secret length.");
    }

    QByteArray sharedSecret(secretLen, 0);
    if (EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(sharedSecret.data()), &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        throw std::runtime_error("Failed to derive shared secret.");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privKey);
    EVP_PKEY_free(pubKey);
    return sharedSecret;
}

QByteArray X3DHProtocol::X3DH(const KeyPair &localIK, const KeyPair &localEK,
                              const KeyPair &remoteIK, const KeyPair &remoteSPK,
                              const KeyPair &signKey, const QByteArray &signDataKey) {
    if(!signDataKey.isEmpty()) {
        if (!verifySignature(remoteSPK.publicKey, signDataKey, signKey.publicKey)) {
            qDebug() << "Signature verification failed!";
            throw std::runtime_error("Signature verification failed");
        } else {
            qDebug() << "Signature verified successfully.";
        }

        QByteArray DH1 = computeSharedSecret(localIK, remoteSPK.publicKey);
        qDebug() << "DH1:" << DH1.toHex();

        QByteArray DH2 = computeSharedSecret(localEK, remoteIK.publicKey);
        qDebug() << "DH2:" << DH2.toHex();

        QByteArray DH3 = computeSharedSecret(localEK, remoteSPK.publicKey);
        qDebug() << "DH3:" << DH3.toHex();

        QByteArray combined = DH1 + DH2 + DH3;

        QByteArray finalKey = QCryptographicHash::hash(combined, QCryptographicHash::Sha256);
        qDebug() << "Final shared secret (raw):" << finalKey.toHex();

        return finalKey;
    } else {
        QByteArray DH1 = computeSharedSecret(localIK, remoteSPK.publicKey);
        qDebug() << "DH1:" << DH1.toHex();

        QByteArray DH2 = computeSharedSecret(localEK, remoteIK.publicKey);
        qDebug() << "DH2:" << DH2.toHex();

        QByteArray DH3 = computeSharedSecret(localEK, remoteSPK.publicKey);
        qDebug() << "DH3:" << DH3.toHex();

        QByteArray combined = DH2 + DH1 + DH3;

        QByteArray finalKey = QCryptographicHash::hash(combined, QCryptographicHash::Sha256);
        qDebug() << "Final shared secret (raw):" << finalKey.toHex();

        return finalKey;
    }
}

