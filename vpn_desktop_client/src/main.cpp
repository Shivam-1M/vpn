#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    // Create the main application object.
    QApplication a(argc, argv);

    // Create and show the main window.
    MainWindow w;
    w.show();

    // Start the application's event loop.
    return a.exec();
}
