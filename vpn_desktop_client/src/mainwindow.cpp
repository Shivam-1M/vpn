#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QUrl>
#include <QThread>
#include <QCoreApplication>
#include <QHostAddress>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), vpnClient(nullptr), isConnected(false)
{
    ui->setupUi(this);

    vpnClient = vpn_client_create();
    if (!vpnClient)
    {
        QMessageBox::critical(this, "Error", "Failed to initialize VPN client core.");
        ui->connectButton->setEnabled(false);
        ui->loginGroup->setEnabled(false);
    }

    networkManager = new QNetworkAccessManager(this);

    connect(ui->connectButton, &QPushButton::clicked, this, &MainWindow::onConnectButtonClicked);
    connect(ui->loginButton, &QPushButton::clicked, this, &MainWindow::onLoginButtonClicked);
    connect(ui->registerDeviceButton, &QPushButton::clicked, this, &MainWindow::onRegisterDeviceButtonClicked);
    connect(ui->logoutButton, &QPushButton::clicked, this, &MainWindow::onLogoutButtonClicked);
}

MainWindow::~MainWindow()
{
    // Ensure kill switch is disabled if the app closes while connected.
    if (isConnected)
    {
        manageKillSwitch(false);
    }

    if (vpnClient)
    {
        if (isConnected)
        {
            vpn_client_disconnect(vpnClient);
        }
        vpn_client_destroy(vpnClient);
    }
    delete ui;
}

bool MainWindow::manageKillSwitch(bool enable)
{
    QString program = "iptables";
    if (enable)
    {
        // --- Input Validation ---
        QUrl endpointUrl("udp://" + vpnConfig.serverEndpoint);
        QString serverIpStr = endpointUrl.host();
        QHostAddress serverIp(serverIpStr);
        QHostAddress dnsIp(vpnConfig.dnsServer);

        if (serverIp.isNull() || (serverIp.protocol() != QAbstractSocket::IPv4Protocol && serverIp.protocol() != QAbstractSocket::IPv6Protocol))
        {
            QMessageBox::critical(this, "Kill Switch Error", "Invalid or malicious server IP received: " + serverIpStr);
            return false;
        }
        
        if (dnsIp.isNull() || (dnsIp.protocol() != QAbstractSocket::IPv4Protocol && dnsIp.protocol() != QAbstractSocket::IPv6Protocol))
        {
            QMessageBox::critical(this, "Kill Switch Error", "Invalid or malicious DNS server IP received: " + vpnConfig.dnsServer);
            return false;
        }
        // --- End of Input Validation ---

        qInfo() << "Enabling Kill Switch for server IP:" << serverIp.toString();

        // --- Enable Kill Switch ---
        QProcess::execute(program, {"-F"});
        QProcess::execute(program, {"-P", "INPUT", "ACCEPT"});
        QProcess::execute(program, {"-P", "FORWARD", "DROP"});
        QProcess::execute(program, {"-P", "OUTPUT", "DROP"});

        // Allow essential traffic
        QProcess::execute(program, {"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
        QProcess::execute(program, {"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"});

        // Allow traffic to the VPN server (using the validated IP)
        QProcess::execute(program, {"-A", "OUTPUT", "-d", serverIp.toString(), "-p", "udp", "--dport", "51820", "-j", "ACCEPT"});

        // Explicitly allow DNS traffic to our chosen DNS server (using the validated IP)
        if (!vpnConfig.dnsServer.isEmpty())
        {
            qInfo() << "Allowing DNS traffic to" << dnsIp.toString();
            QProcess::execute(program, {"-A", "OUTPUT", "-d", dnsIp.toString(), "-p", "udp", "--dport", "53", "-j", "ACCEPT"});
            QProcess::execute(program, {"-A", "OUTPUT", "-d", dnsIp.toString(), "-p", "tcp", "--dport", "53", "-j", "ACCEPT"});
        }

        // Allow all traffic going through the VPN tunnel itself
        QProcess::execute(program, {"-A", "OUTPUT", "-o", "wg_client", "-j", "ACCEPT"});

        QMessageBox::information(this, "Kill Switch", "Kill Switch Enabled.");
    }
    else
    {
        // --- Disable Kill Switch ---
        qInfo() << "Disabling Kill Switch.";
        QProcess::execute(program, {"-F"});
        QProcess::execute(program, {"-P", "INPUT", "ACCEPT"});
        QProcess::execute(program, {"-P", "FORWARD", "ACCEPT"});
        QProcess::execute(program, {"-P", "OUTPUT", "ACCEPT"});
        QMessageBox::information(this, "Kill Switch", "Kill Switch Disabled.");
    }
    return true;
}

void MainWindow::loadOrGenerateKeys()
{
    QSettings settings("MyVpn", "VpnClient");
    QString settingsKey = currentUserEmail + "_clientPrivateKey";
    QString savedPrivateKey = settings.value(settingsKey).toString();

    if (savedPrivateKey.isEmpty())
    {
        QMessageBox::information(this, "New Device", "No keys found. Please register this device.");
        ui->deviceGroup->setEnabled(true);
    }
    else
    {
        QMessageBox::information(this, "Device Found", "Loading existing keys for this device.");
        vpnConfig.clientPrivateKey = savedPrivateKey;

        char *pubKeyCStr = vpn_get_public_key(savedPrivateKey.toStdString().c_str());
        if (pubKeyCStr)
        {
            clientPublicKey = QString::fromUtf8(pubKeyCStr);
            vpn_free_string(pubKeyCStr); // Free the memory allocated by Rust
        }

        ui->deviceGroup->setEnabled(false);

        QNetworkRequest request(QUrl("http://localhost:8080/config"));
        QString authHeader = "Bearer " + accessToken;
        request.setRawHeader("Authorization", authHeader.toUtf8());

        QNetworkReply *configReply = networkManager->get(request);
        connect(configReply, &QNetworkReply::finished, this, [=]()
                { onConfigReplyFinished(configReply); });
    }
}

void MainWindow::onLoginButtonClicked()
{
    QString email = ui->emailLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    if (email.isEmpty() || password.isEmpty())
    {
        QMessageBox::warning(this, "Login Failed", "Please enter both email and password.");
        return;
    }

    QJsonObject json;
    json["email"] = email;
    json["password"] = password;
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkRequest request(QUrl("http://localhost:8080/login"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = networkManager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [=]()
            { onLoginReplyFinished(reply); });
}

void MainWindow::onLoginReplyFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError)
    {
        QByteArray response_data = reply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response_data);
        QJsonObject jsonObj = jsonDoc.object();
        if (jsonObj.contains("access_token") && jsonObj.contains("refresh_token"))
        {
            currentUserEmail = ui->emailLineEdit->text();

            accessToken = jsonObj["access_token"].toString();
            refreshToken = jsonObj["refresh_token"].toString(); // Store the refresh token

            // Save the refresh token to settings for persistence
            QSettings settings("MyVpn", "VpnClient");
            settings.setValue("refreshToken", refreshToken);

            QMessageBox::information(this, "Login Success", "Successfully logged in!");
            ui->loginGroup->setEnabled(false);
            loadOrGenerateKeys();
        }
        else
        {
            QMessageBox::critical(this, "Login Failed", "Invalid credentials or server error.");
        }
    }
    else
    {
        QMessageBox::critical(this, "Login Failed", "Error: " + reply->errorString());
    }
    reply->deleteLater();
}

void MainWindow::onRegisterDeviceButtonClicked()
{
    // 1. Generate a new key pair
    VpnKeyPair keypair = vpn_generate_keypair();
    clientPublicKey = QString::fromUtf8(keypair.public_key);
    vpnConfig.clientPrivateKey = QString::fromUtf8(keypair.private_key);

    vpn_free_string(keypair.public_key);
    vpn_free_string(keypair.private_key);

    // 2. Send the public key to the server
    QJsonObject json;
    json["public_key"] = clientPublicKey; // Use the member variable
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkRequest request(QUrl("http://localhost:8080/devices"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QString authHeader = "Bearer " + accessToken;
    request.setRawHeader("Authorization", authHeader.toUtf8());

    QNetworkReply *reply = networkManager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [=]()
            { onDeviceReplyFinished(reply); });
}

void MainWindow::onDeviceReplyFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError)
    {
        QMessageBox::information(this, "Device Registered", "Device successfully registered!");

        QSettings settings("MyVpn", "VpnClient");
        QString settingsKey = currentUserEmail + "_clientPrivateKey";
        settings.setValue(settingsKey, vpnConfig.clientPrivateKey);

        // **FIX**: Show a status message and use a more reliable delay
        ui->statusLabel->setText("Status: Finalizing setup...");
        // Process UI events to make sure the label updates
        QCoreApplication::processEvents();

        // Wait 2 seconds (2000 milliseconds). This is a more robust delay
        // to ensure the server's network interface is fully ready.
        QThread::msleep(2000);

        // Now that we've waited, fetch the config
        QNetworkRequest request(QUrl("http://localhost:8080/config"));
        QString authHeader = "Bearer " + accessToken;
        request.setRawHeader("Authorization", authHeader.toUtf8());

        QNetworkReply *configReply = networkManager->get(request);
        connect(configReply, &QNetworkReply::finished, this, [=]()
                { onConfigReplyFinished(configReply); });
    }
    else
    {
        QMessageBox::critical(this, "Device Registration Failed", "Error: " + reply->errorString() + ". The public key may already exist for another user.");
    }
    reply->deleteLater();
}

void MainWindow::onConfigReplyFinished(QNetworkReply *reply)
{
    // ... (This function remains mostly unchanged)
    if (reply->error() == QNetworkReply::NoError)
    {
        QByteArray response_data = reply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response_data);
        QJsonObject jsonObj = jsonDoc.object();

        vpnConfig.clientIp = jsonObj["client_ip"].toString();
        vpnConfig.dnsServer = jsonObj["dns_server"].toString();
        vpnConfig.serverPublicKey = jsonObj["server_public_key"].toString();
        vpnConfig.serverEndpoint = jsonObj["server_endpoint"].toString();

        if (vpnConfig.clientIp.isEmpty() || vpnConfig.serverEndpoint.isEmpty())
        {
            QMessageBox::critical(this, "Config Error", "Failed to parse VPN configuration from server.");
            return;
        }

        QMessageBox::information(this, "Config Received", "VPN configuration loaded successfully.");
        ui->connectButton->setEnabled(true);

        // Make sure both login and device groups are disabled now
        ui->loginGroup->setEnabled(false);
        ui->deviceGroup->setEnabled(false);
        ui->sessionGroup->setEnabled(true);
    }
    else
    {
        QMessageBox::critical(this, "Config Error", "Could not fetch VPN config: " + reply->errorString());
    }
    reply->deleteLater();
}

void MainWindow::onLogoutButtonClicked()
{
    // 1. If currently connected, disconnect first for a clean exit.
    if (isConnected)
    {
        onConnectButtonClicked();
    }

    // 2. Prepare the DELETE request to the server
    QJsonObject json;
    json["public_key"] = clientPublicKey;
    QJsonDocument doc(json);
    QByteArray data = doc.toJson();

    QNetworkRequest request(QUrl("http://localhost:8080/devices/remove"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QString authHeader = "Bearer " + accessToken;
    request.setRawHeader("Authorization", authHeader.toUtf8());

    // QNetworkAccessManager doesn't have a direct "delete" method,
    // but you can send a custom request.
    QNetworkReply *reply = networkManager->sendCustomRequest(request, "DELETE", data);
    connect(reply, &QNetworkReply::finished, this, [=]()
            { onLogoutReplyFinished(reply); });
}

void MainWindow::onLogoutReplyFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError)
    {
        QMessageBox::information(this, "Logged Out", "Device successfully removed from your account.");
    }
    else
    {
        // We still log out locally even if the server request fails.
        QMessageBox::warning(this, "Logout Warning", "Could not remove device from server (maybe it's offline?), but logging out locally.");
    }
    reply->deleteLater();

    // 3. Reset the application to its initial state
    resetToLoginState();
}

void MainWindow::resetToLoginState()
{
    // Clear local settings
    QSettings settings("MyVpn", "VpnClient");
    settings.clear();

    // Reset UI elements
    ui->loginGroup->setEnabled(true);
    ui->deviceGroup->setEnabled(false);
    ui->sessionGroup->setEnabled(false);
    ui->connectButton->setEnabled(false);
    ui->connectButton->setText("Connect");
    ui->statusLabel->setText("Status: Disconnected");
    ui->emailLineEdit->clear();
    ui->passwordLineEdit->clear();

    // Reset internal state
    isConnected = false;
    accessToken.clear();
    refreshToken.clear();
    clientPublicKey.clear();
    currentUserEmail.clear();
    vpnConfig = {};
}

void MainWindow::onConnectButtonClicked()
{
    if (!isConnected)
    {
        if (!manageKillSwitch(true))
        {
            return;
        }

        // **FIX**: Add a small delay to prevent the race condition
        QThread::msleep(200); // Wait 200 milliseconds

        if (vpn_client_connect(vpnClient,
                               vpnConfig.clientPrivateKey.toStdString().c_str(),
                               vpnConfig.clientIp.toStdString().c_str(),
                               vpnConfig.dnsServer.toStdString().c_str(),
                               vpnConfig.serverPublicKey.toStdString().c_str(),
                               vpnConfig.serverEndpoint.toStdString().c_str()) == 0)
        {
            ui->statusLabel->setText("Status: Connected");
            ui->connectButton->setText("Disconnect");
            isConnected = true;
        }
        else
        {
            QMessageBox::warning(this, "Connection Failed", "Could not connect to the VPN server.");
            manageKillSwitch(false);
        }
    }
    else
    {
        if (vpn_client_disconnect(vpnClient) == 0)
        {

            ui->statusLabel->setText("Status: Disconnecting...");
            QCoreApplication::processEvents(); // Update the UI to show the message

            // **FIX**: Add a short delay to allow the OS to clean up the interface
            QThread::msleep(500); // Wait half a second

            ui->statusLabel->setText("Status: Disconnected");
            ui->connectButton->setText("Connect");
            isConnected = false;
            manageKillSwitch(false);
        }
        else
        {
            QMessageBox::warning(this, "Disconnection Failed", "Could not disconnect from the VPN server.");
        }
    }
}