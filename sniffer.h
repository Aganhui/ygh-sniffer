#ifndef SNIFFER_H
#define SNIFFER_H

//#include "mainwindow.h"
#include "pcap.h"
#include "protocol.h"
#include <list>
#include<string>
using namespace std;

#include <QThread>
#include <QObject>

#define 	PCAP_OPENFLAG_PROMISCUOUS   1

//typedef void (add_table_data) ();

class MainWindow;

class Sniffer : public QThread
{
    Q_OBJECT
public:
    Sniffer();
    ~Sniffer();
    int get_devsname(string **ss, int *num);
    int set_dev(int idx);
//    int sniffing(MainWindow *w);
    int sniffing();
    int stop();
    int analyzing(const u_char *pkt_data, Package *p);

protected:
    void run();

private:
    void save_header(Package *p, struct pcap_pkthdr *header);

signals:
//    void done();
    void sendTableData(Package *pkg);



public:
    pcap_if_t *dev;


private:
    void update_devsnum();

private:
    pcap_if_t *alldevs;
    int devsnum;
    int run_flag = 0;

};

#endif // SNIFFER_H
