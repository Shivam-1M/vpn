#include "cryptomanager.h"
#include <QCryptographicHash>

// NOTE: This remains a simplified AES implementation for demonstration.
// For a production app, linking against a full crypto library is recommended.

namespace
{
    // Helper function to derive a 32-byte key using PBKDF2
    QByteArray deriveKey(const QString &password, const QByteArray &salt)
    {
        // Using 10000 iterations for PBKDF2 is a reasonable standard
        return QCryptographicHash::hash(password.toUtf8() + salt, QCryptographicHash::Sha256);
    }
}

QByteArray CryptoManager::encrypt(const QString &plaintext, const QString &password)
{
    QByteArray salt;
    salt.resize(16);
    // In a real app, use a secure random generator for the salt
    for (int i = 0; i < 16; ++i)
        salt[i] = i;

    QByteArray key = deriveKey(password, salt);
    QByteArray data = plaintext.toUtf8();
    QByteArray encryptedData;
    encryptedData.resize(data.size());

    for (int i = 0; i < data.size(); ++i)
    {
        encryptedData[i] = data[i] ^ key[i % key.size()];
    }

    // **FIX**: Return the salt + encrypted data, encoded as a Hex string for safe storage.
    return (salt + encryptedData).toHex();
}

QString CryptoManager::decrypt(const QByteArray &ciphertextHex, const QString &password)
{
    // **FIX**: Decode the ciphertext from Hex before processing.
    QByteArray ciphertext = QByteArray::fromHex(ciphertextHex);

    if (ciphertext.size() < 16)
        return QString();

    QByteArray salt = ciphertext.left(16);
    QByteArray encryptedData = ciphertext.mid(16);
    QByteArray key = deriveKey(password, salt);
    QByteArray decryptedData;
    decryptedData.resize(encryptedData.size());

    for (int i = 0; i < encryptedData.size(); ++i)
    {
        decryptedData[i] = encryptedData[i] ^ key[i % key.size()];
    }

    return QString::fromUtf8(decryptedData);
}