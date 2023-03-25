#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QMessageBox>
#include "sniffer.h"

//class Sniffer;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void show_parsing(int idx);
    void show_bin(int idx);

    Sniffer s;
    QStandardItemModel *model;
    QStandardItemModel *tree_model;

    QList<Package *> pkg_list;

private slots:
//    void on_pushButton_clicked();

    void on_pushButton_2_clicked();
    void recieveData(Package *p);

//    void on_pushButton_clicked(bool checked);

private:
    Ui::MainWindow *ui;
    QStringList table_cols = {"Time", "Protocol", "IP_src",
                              "IP_dst", "Length", "Port_src", "Port_dst"};

public:
    void add_tabledata();
    void set_table_cols_width();
};
#endif // MAINWINDOW_H
