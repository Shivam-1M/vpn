#ifndef SIGNUPDIALOG_H
#define SIGNUPDIALOG_H

#include <QDialog>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class QLineEdit;
class QLabel;

class SignUpDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SignUpDialog(QWidget *parent = nullptr);
    ~SignUpDialog();

private slots:
    void onSignUpClicked();
    void onRequestFinished(QNetworkReply *reply);

private:
    QLineEdit *emailEdit;
    QLineEdit *passwordEdit;
    QLineEdit *confirmPasswordEdit;
    QLabel *statusLabel;
    QNetworkAccessManager *networkManager;
};

#endif // SIGNUPDIALOG_H
