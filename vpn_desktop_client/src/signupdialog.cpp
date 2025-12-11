#include "signupdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonDocument>

SignUpDialog::SignUpDialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle("Sign Up");
    setModal(true);
    resize(300, 250);

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addWidget(new QLabel("Email:", this));
    emailEdit = new QLineEdit(this);
    layout->addWidget(emailEdit);

    layout->addWidget(new QLabel("Password:", this));
    passwordEdit = new QLineEdit(this);
    passwordEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(passwordEdit);

    layout->addWidget(new QLabel("Confirm Password:", this));
    confirmPasswordEdit = new QLineEdit(this);
    confirmPasswordEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(confirmPasswordEdit);

    statusLabel = new QLabel(this);
    statusLabel->setStyleSheet("color: red");
    layout->addWidget(statusLabel);

    QPushButton *signUpBtn = new QPushButton("Sign Up", this);
    connect(signUpBtn, &QPushButton::clicked, this, &SignUpDialog::onSignUpClicked);
    layout->addWidget(signUpBtn);

    networkManager = new QNetworkAccessManager(this);
}

SignUpDialog::~SignUpDialog() {}

void SignUpDialog::onSignUpClicked()
{
    QString email = emailEdit->text();
    QString password = passwordEdit->text();
    QString confirm = confirmPasswordEdit->text();

    if (email.isEmpty() || password.isEmpty()) {
        statusLabel->setText("Please fill all fields.");
        return;
    }

    if (password != confirm) {
        statusLabel->setText("Passwords do not match.");
        return;
    }

    statusLabel->setText("Registering...");

    QJsonObject json;
    json["email"] = email;
    json["password"] = password;
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkRequest request(QUrl("http://localhost:8080/register"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    // Note: We use the network manager to send the request
    QNetworkReply *reply = networkManager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [=]() { onRequestFinished(reply); });
}

void SignUpDialog::onRequestFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError) {
        QMessageBox::information(this, "Success", "Account created! You can now log in.");
        accept();
    } else {
        QString errorMsg = reply->errorString();
        int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        
        if (statusCode == 409) {
             statusLabel->setText("Email already exists.");
        } else {
             statusLabel->setText("Error: " + errorMsg);
        }
    }
    reply->deleteLater();
}
