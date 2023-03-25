#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <thread>

#define BIN_DATA_LEN 256

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    string *ss;
    int num;
    s.get_devsname(&ss, &num);
    for(int i=0; i<num; i++){
        ui->comboBox->addItem(QString::asprintf(ss[i].c_str()));
    }


    this->model = new QStandardItemModel(this);
    this->model->setHorizontalHeaderLabels(this->table_cols);
    ui->tableView->setModel(this->model);
    this->set_table_cols_width();
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

    connect(ui->pushButton, &QPushButton::clicked, [=](){
//        int idx_selected = ui->comboBox->currentIndex();
        s.set_dev(ui->comboBox->currentIndex());
        s.start();
    });
    connect(&s, &Sniffer::sendTableData, this, &MainWindow::recieveData, Qt::QueuedConnection);

    /* 选中数据包显示详细信息 */
    connect(ui->tableView, &QTableView::clicked, [=](){
        auto index = ui->tableView->selectionModel()->currentIndex();
        this->show_parsing(index.row());
        this->show_bin(index.row());
//        ui->treeView->addPacketInfo(pktVector.at(index));
//        ui->packetText->addRawData(pktRaw.at(index)->len, pktRaw.at(index)->pkt_data, pktVector.at(index));
    });

//    QMessageBox::information(NULL, "Title", "show_parsing");
//    Package *p = this->pkg_list[idx];

    this->tree_model = new QStandardItemModel(ui->treeView);
//    this->tree_model->setHorizontalHeaderLabels(QStringList()<<QStringLiteral("名称")<<QStringLiteral("值"));
    this->tree_model->setHorizontalHeaderLabels(QStringList()<<QStringLiteral("数据包详细信息"));
//    QStandardItem* item_eh = new QStandardItem("eh");
//    this->tree_model->appendRow(item_eh);
//    QStandardItem* item_1 = new QStandardItem("eh1");
//    item_eh->appendRow(item_1);
    ui->treeView->setModel(this->tree_model);

//    ui->textBrowser->append("testing");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::set_table_cols_width(){
    ui->tableView->setColumnWidth(0, 70);
    ui->tableView->setColumnWidth(1, 60);
    ui->tableView->setColumnWidth(2, 90);
    ui->tableView->setColumnWidth(3, 90);
    ui->tableView->setColumnWidth(4, 60);
    ui->tableView->setColumnWidth(5, 60);
    ui->tableView->setColumnWidth(6, 60);
    ui->tableView->setColumnWidth(7, 120);
    ui->tableView->setColumnWidth(8, 120);
    ui->tableView->setColumnWidth(9, 120);
}

void MainWindow::recieveData(Package *p){
//    this->add_tabledata();
    this->pkg_list.append(p);
    QList<QStandardItem*> items;
//    items << new QStandardItem(QString::fromStdString(to_string(p->eh->type))) << new QStandardItem("item2") << new QStandardItem("item3");
//    this->model->appendRow(items);

    QString tmp;
    for(int i=0; i<this->table_cols.size(); i++){
        tmp = this->table_cols[i];
        if(tmp == "Time"){
            items << new QStandardItem(QString::fromStdString(p->get_time()));
        } else if(tmp == "Protocol"){
            items << new QStandardItem(QString::fromStdString(p->get_protocol()));
        } else if(tmp == "IP_src"){
            items << new QStandardItem(QString::fromStdString(p->get_src_ip()));
        } else if(tmp == "IP_dst"){
            items << new QStandardItem(QString::fromStdString(p->get_dst_ip()));
        } else if(tmp == "Length"){
            items << new QStandardItem(QString::fromStdString(to_string(p->get_len())));
        } else if(tmp == "Port_src"){
            items << new QStandardItem(QString::fromStdString(to_string(p->get_src_port())));
        } else if(tmp == "Port_dst"){
            items << new QStandardItem(QString::fromStdString(to_string(p->get_dst_port())));
        } else{

        }

    }
    this->model->appendRow(items);

}

int print_info(){
    printf("testing\n");
    return 0;
}

void MainWindow::show_parsing(int idx){
//    ui->treeView
    this->tree_model->removeRows(0, this->tree_model->rowCount());
    Package *p = this->pkg_list[idx];
    QStandardItem * item_d;
    if(p->eh){
        QStandardItem* item_eh = new QStandardItem("e-header");
        this->tree_model->appendRow(item_eh);
        QStandardItem* item_mac_src = new QStandardItem(
                    QString::fromStdString("src mac:"+p->get_src_mac()));
        item_eh->appendRow(item_mac_src);
        QStandardItem* item_mac_dst = new QStandardItem(
                    QString::fromStdString("dst mac:"+p->get_dst_mac()));
        item_eh->appendRow(item_mac_dst);
        QStandardItem* item_eh_type = new QStandardItem(
                    QString::fromStdString("type:"+to_string(p->get_ih_type())));
        item_eh->appendRow(item_eh_type);
    }
    if(p->ih){
        QStandardItem* item_ih = new QStandardItem("ip-header");
        this->tree_model->appendRow(item_ih);
        item_d = new QStandardItem(QString::fromStdString(
                        "version:"+to_string(p->get_version())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "ip header len:"+to_string(p->get_iphead_len())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "tos:"+to_string(p->get_tos())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "total len:"+to_string(p->get_total_len())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "identification:"+to_string(p->get_indenti())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "ip flags:"+to_string(p->get_flag())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "slice offset:"+to_string(p->get_offset())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "ttl:"+to_string(p->get_ttl())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "protocol:"+to_string(p->get_ih_type())));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "source ip:"+p->get_src_ip()));
        item_ih->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "destination ip:"+p->get_dst_ip()));
        item_ih->appendRow(item_d);
    }
    if(p->th){
        QStandardItem* item_th = new QStandardItem("tcp-header");
        this->tree_model->appendRow(item_th);
        item_d = new QStandardItem(QString::fromStdString(
                        "source port:"+to_string(p->get_src_port())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "destination port:"+to_string(p->get_dst_port())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "seq id:"+to_string(p->get_seq())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "ack id:"+to_string(p->get_ack())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "header len:"+to_string(p->get_tcphead_len())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "ack flag:"+to_string(p->get_ack_flag())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "syn flag:"+to_string(p->get_syn_flag())));
        item_th->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "fin flag:"+to_string(p->get_fin_flag())));
        item_th->appendRow(item_d);
    }
    if(p->uh){
        QStandardItem* item_uh = new QStandardItem("udp-header");
        this->tree_model->appendRow(item_uh);
        item_d = new QStandardItem(QString::fromStdString(
                        "source port:"+to_string(p->get_src_port())));
        item_uh->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "destination port:"+to_string(p->get_dst_port())));
        item_uh->appendRow(item_d);
        item_d = new QStandardItem(QString::fromStdString(
                        "udp length:"+to_string(p->get_udphead_len())));
        item_uh->appendRow(item_d);

    }
}

void MainWindow::show_bin(int idx){
    this->ui->textBrowser->clear();
    Package *p = this->pkg_list[idx];
    int show_len = BIN_DATA_LEN;
    if(p->len < BIN_DATA_LEN)
        show_len = p->len;
    for(int i=0; i<show_len; i++){
        this->ui->textBrowser->insertPlainText(QString("%1 ").arg(p->data[i], 2, 16, QLatin1Char('0')));
    }
    this->ui->textBrowser->append("...");
}

//void MainWindow::on_pushButton_clicked()
//{
//    int idx_selected = ui->comboBox->currentIndex();
//    s.set_dev(idx_selected);

//    QMessageBox::information(NULL, "Title", "Content1");
////    std::thread t(std::bind(&Sniffer::sniffing, &s, this));
////    std::thread t([&s, this]() {s.sniffing(this);});
////    std::thread t(&Sniffer::sniffing, &this->s, this);
////    std::thread t(&Sniffer::stop, &this->s);
//    std::thread t(print_info);

//    QMessageBox::information(NULL, "Title", "Content2");
////    t.join();
//    //开始sniffer，传入显示数据的func
////    s.sniffing(this);

//}

void MainWindow::add_tabledata(){
    QList<QStandardItem*> items;
    items << new QStandardItem("item1") << new QStandardItem("item2") << new QStandardItem("item3");
    this->model->appendRow(items);
}

void MainWindow::on_pushButton_2_clicked()
{
    s.stop();
}

