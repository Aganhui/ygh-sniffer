#include "mainwindow.h"

#include <QApplication>

#include "sniffer.h"

extern int run_sniffer();

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    Sniffer s;
    run_sniffer();
    w.show();

    return a.exec();
}
