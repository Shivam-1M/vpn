#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QUrl>

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
}

MainWindow::~MainWindow()
{
    // Ensure kill switch is disabled if the app closes while connected.
    if (isConnected)
    {
        manageKillSwitch(false);
    }
    // ... (Rest of destructor remains the same)
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
        // --- Enable Kill Switch ---
        QUrl endpointUrl("udp://" + vpnConfig.serverEndpoint);
        QString serverIp = endpointUrl.host();
        if (serverIp.isEmpty())
        {
            QMessageBox::critical(this, "Kill Switch Error", "Could not parse server IP from endpoint.");
            return false;
        }
        qInfo() << "Enabling Kill Switch for server IP:" << serverIp;

        // FIX: Run each command separately
        QProcess::execute(program, {"-F"});                   // 1. Flush all existing rules
        QProcess::execute(program, {"-P", "OUTPUT", "DROP"}); // 2. Set default policy to DROP
        QProcess::execute(program, {"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
        QProcess::execute(program, {"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"});
        QProcess::execute(program, {"-A", "OUTPUT", "-o", "wg_client", "-j", "ACCEPT"});
        QProcess::execute(program, {"-A", "OUTPUT", "-d", serverIp, "-p", "udp", "--dport", "51820", "-j", "ACCEPT"});

        QMessageBox::information(this, "Kill Switch", "Kill Switch Enabled.");
    }
    else
    {
        // --- Disable Kill Switch ---
        qInfo() << "Disabling Kill Switch.";
        // FIX: Run each command separately
        QProcess::execute(program, {"-F"});                     // 1. Flush all rules
        QProcess::execute(program, {"-P", "OUTPUT", "ACCEPT"}); // 2. Set default policy back to ACCEPT

        QMessageBox::information(this, "Kill Switch", "Kill Switch Disabled.");
    }
    return true;
}

// ADD THIS ENTIRE FUNCTION
void MainWindow::loadOrGenerateKeys()
{
    QSettings settings("MyVpn", "VpnClient");
    QString savedPrivateKey = settings.value("clientPrivateKey").toString();

    if (savedPrivateKey.isEmpty())
    {
        // No key saved, so the user needs to register this device.
        QMessageBox::information(this, "New Device", "No keys found. Please register this device.");
        ui->deviceGroup->setEnabled(true);
    }
    else
    {
        // Key found, load it and prepare to fetch config.
        QMessageBox::information(this, "Device Found", "Loading existing keys for this device.");
        vpnConfig.clientPrivateKey = savedPrivateKey;
        ui->deviceGroup->setEnabled(false); // No need to register again

        // Directly fetch the VPN config since we have keys and are logged in.
        QNetworkRequest request(QUrl("http://localhost:8080/config"));
        QString authHeader = "Bearer " + jwtToken;
        request.setRawHeader("Authorization", authHeader.toUtf8());

        QNetworkReply *configReply = networkManager->get(request);
        connect(configReply, &QNetworkReply::finished, this, [=]()
                { onConfigReplyFinished(configReply); });
    }
}

void MainWindow::onLoginButtonClicked()
{
    // ... (This function remains unchanged)
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

        if (jsonObj.contains("token") && jsonObj["token"].isString())
        {
            jwtToken = jsonObj["token"].toString();
            QMessageBox::information(this, "Login Success", "Successfully logged in!");
            ui->loginGroup->setEnabled(false);

            // UPDATE: Instead of just enabling the device group,
            // call our new function to decide what to do next.
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
    QString authHeader = "Bearer " + jwtToken;
    request.setRawHeader("Authorization", authHeader.toUtf8());

    QNetworkReply *reply = networkManager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [=]()
            { onDeviceReplyFinished(reply); });
}

void MainWindow::onDeviceReplyFinished(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError)
    {
        QMessageBox::information(this, "Device Registered", "Device successfully registered! Now fetching config...");

        // UPDATE: Save the private key upon successful registration
        QSettings settings("MyVpn", "VpnClient");
        settings.setValue("clientPrivateKey", vpnConfig.clientPrivateKey);

        // 3. Now get the VPN config
        QNetworkRequest request(QUrl("http://localhost:8080/config"));
        QString authHeader = "Bearer " + jwtToken;
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
    }
    else
    {
        QMessageBox::critical(this, "Config Error", "Could not fetch VPN config: " + reply->errorString());
    }
    reply->deleteLater();
}

void MainWindow::onConnectButtonClicked()
{
    if (!isConnected)
    {
        // 1. Enable the kill switch BEFORE connecting
        if (!manageKillSwitch(true))
        {
            return; // Don't proceed if kill switch fails
        }

        // 2. Attempt to connect
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
            // 3. IMPORTANT: Disable kill switch if connection fails
            manageKillSwitch(false);
        }
    }
    else
    {
        // 1. Disconnect from the VPN
        if (vpn_client_disconnect(vpnClient) == 0)
        {
            ui->statusLabel->setText("Status: Disconnected");
            ui->connectButton->setText("Connect");
            isConnected = false;

            // 2. Disable the kill switch AFTER disconnecting
            manageKillSwitch(false);
        }
        else
        {
            QMessageBox::warning(this, "Disconnection Failed", "Could not disconnect from the VPN server.");
            // Don't disable kill switch here, as we might still be connected.
        }
    }
}