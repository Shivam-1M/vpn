#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <QString>
#include <QByteArray>

class CryptoManager
{
public:
    // Encrypts plaintext using a key derived from the password
    static QByteArray encrypt(const QString &plaintext, const QString &password);

    // Decrypts ciphertext using a key derived from the password
    static QString decrypt(const QByteArray &ciphertext, const QString &password);
};

#endif // CRYPTOMANAGER_H