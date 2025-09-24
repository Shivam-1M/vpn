#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <QSettings>
#include <QProcess> // ADD THIS

#include "vpn_client_core.h" // Include our Rust library header

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onConnectButtonClicked();
    void onLoginButtonClicked();
    void onRegisterDeviceButtonClicked();
    void onDeviceReplyFinished(QNetworkReply *reply);
    void onLoginReplyFinished(QNetworkReply *reply);
    void onConfigReplyFinished(QNetworkReply *reply);
    void onLogoutButtonClicked();
    void onLogoutReplyFinished(QNetworkReply *reply);

private:
    void loadOrGenerateKeys();
    // ADD THIS FUNCTION
    bool manageKillSwitch(bool enable);
    void resetToLoginState();

    Ui::MainWindow *ui;
    VpnClient *vpnClient;
    bool isConnected;
    QNetworkAccessManager *networkManager;
    QString jwtToken;
    QString clientPublicKey;

    struct VpnConfig
    {
        QString clientPrivateKey;
        QString clientIp;
        QString dnsServer;
        QString serverPublicKey;
        QString serverEndpoint;
    } vpnConfig;
};
#endif // MAINWINDOW_H