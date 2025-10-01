#include <QCoreApplication>
#include <QProcess>
#include <QDebug>

// A simple, standalone command-line utility to reset iptables rules.
// This is intended as a recovery tool in case the main VPN application
// crashes, leaving the kill switch enabled and blocking internet access.
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qInfo() << "Attempting to reset firewall rules to default...";

    QString program = "iptables";

    // Flush all existing rules from all chains.
    QProcess::execute(program, {"-F"});

    // Set the default policy for all built-in chains to ACCEPT.
    QProcess::execute(program, {"-P", "INPUT", "ACCEPT"});
    QProcess::execute(program, {"-P", "FORWARD", "ACCEPT"});
    QProcess::execute(program, {"-P", "OUTPUT", "ACCEPT"});

    qInfo() << "Firewall rules have been reset successfully.";
    qInfo() << "Your internet connection should now be restored.";

    return 0;
}