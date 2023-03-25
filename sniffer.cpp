#include "sniffer.h"
#include "mainwindow.h"
#include <QMessageBox>
#include<fstream>

Sniffer::Sniffer() : QThread()
{

    char errbuf[PCAP_ERRBUF_SIZE];
    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    update_devsnum();
    if(this->devsnum==0){
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        exit(1);
    }

}

Sniffer::~Sniffer(){
    /* At this point, we don't need any more the device list. Free it */
//    QMessageBox::information(NULL, "Title", "freedevs");
    pcap_freealldevs(alldevs);
}

void Sniffer::run(){
    printf("testing setting\n");
//    QMessageBox::information(NULL, "Title", "start run!");
//    this->sniffing();
    this->run_flag = 1;

    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char infobuf[PCAP_ERRBUF_SIZE];

    ofstream outFile;
    outFile.open("E:/winpcap-logs.txt", ios::out); // 打开模式可省

    outFile << "start testing\n";

//    printf("testing");
//    QMessageBox::information(NULL, "Title", "testing");
//    return 0;

    /* Open the adapter */
    if ( (adhandle= pcap_open_live(this->dev->name,  // name of the device
                                   65536,     // portion of the packet to capture.
                                   // 65536 grants that the whole packet will be captured on all the MACs.
                                   PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                                   1000,      // read timeout
                                   //                             NULL,      // remote authentication
                                   errbuf     // error buffer
                                   ) ) == NULL)
    {
        sprintf(infobuf, "Unable to open the adapter. %s is not supported by WinPcap");
        QMessageBox::information(NULL, "Title", infobuf);
//        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
//        return -1;
        return ;
    }

//    QMessageBox::information(NULL, "Title", "testing1");

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        sprintf(infobuf, "This program works only on Ethernet networks.");
//        QMessageBox::information(NULL, "Title", infobuf);
//        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
//        return -1;
        return ;
    }

//    sprintf(infobuf, "listening on %s...", this->dev->description);
//    QMessageBox::information(NULL, "Title", infobuf);
    printf("listening on %s...\n", this->dev->description);
    outFile << "start listening...\n";


//    /* start the capture */
//    pcap_loop(adhandle, 0, packet_handler, NULL);

    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    int i=0;
//    this->run_flag = 0;
    /* Retrieve the packets */
//    while(this->run_flag && (i<100) && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
    while(this->run_flag && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
        printf("%d", i++);
        outFile << "id" << i << " ";
        if(res == 0)
            /* Timeout elapsed */
            continue;

        outFile << "1...";
        Package *p = new Package;
        outFile << "2...";
        save_header(p, header);
        outFile << "3...";
        analyzing(pkt_data, p);
        outFile << "emit data, ";
        emit this->sendTableData(p);
//        QThread::sleep(1);
//        (*w).add_tabledata();

    }

    outFile << "\nall finished\n";
    outFile.close();
    pcap_close(adhandle);
//    delete adhandle;
//    QMessageBox::information(NULL, "Title", "testing3");
}


//void Sniffer::done(){
//    printf("done\n");
//}

void Sniffer::update_devsnum(){
    this->devsnum = 0;
    pcap_if_t *d;
    for(d=this->alldevs; d; d=d->next){
        ++this->devsnum;
    }
}

int Sniffer::get_devsname(string ** ss, int * num){
    *ss = new string[this->devsnum];
    pcap_if_t *d;
    int i = 0;
    for(d=this->alldevs; d; d=d->next){
        (*ss)[i++] = d->name;
    }
    *num = this->devsnum;
    return 0;
}

int Sniffer::set_dev(int idx){
    /* Jump to the selected adapter */
    pcap_if_t *d;
    int i;
    for(d=alldevs, i=0; i<idx; d=d->next, i++);
    this->dev = d;
    return 0;
}

//int Sniffer::sniffing(MainWindow *w){
int Sniffer::sniffing(){
    this->run_flag = 1;

    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char infobuf[PCAP_ERRBUF_SIZE];

//    printf("testing");
//    QMessageBox::information(NULL, "Title", "testing");
//    return 0;

    /* Open the adapter */
    if ( (adhandle= pcap_open_live(this->dev->name,  // name of the device
                                   65536,     // portion of the packet to capture.
                                   // 65536 grants that the whole packet will be captured on all the MACs.
                                   PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                                   1000,      // read timeout
                                   //                             NULL,      // remote authentication
                                   errbuf     // error buffer
                                   ) ) == NULL)
    {
        sprintf(infobuf, "Unable to open the adapter. %s is not supported by WinPcap");
//        QMessageBox::information(NULL, "Title", infobuf);
//        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        return -1;
    }

//    QMessageBox::information(NULL, "Title", "testing1");

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        sprintf(infobuf, "This program works only on Ethernet networks.");
//        QMessageBox::information(NULL, "Title", infobuf);
//        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        return -1;
    }

//    sprintf(infobuf, "listening on %s...", this->dev->description);
//    QMessageBox::information(NULL, "Title", infobuf);
    printf("listening on %s...\n", this->dev->description);


//    /* start the capture */
//    pcap_loop(adhandle, 0, packet_handler, NULL);

    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    ethe_header *eh;
    ip_header *ih;
    tcp_header *th;
    udp_header *uh;


    int i=0;
//    this->run_flag = 0;
    /* Retrieve the packets */
//    while(this->run_flag && (i<5) && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
    while(this->run_flag && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
        printf("%d", i++);
        if(res == 0)
            /* Timeout elapsed */
            continue;

        Package *p = new Package;
        save_header(p, header);
        analyzing(pkt_data, p);
//        emit
//        (*w).add_tabledata();

    }

    pcap_close(adhandle);
//    delete adhandle;
//    QMessageBox::information(NULL, "Title", "testing3");

    return 0;
}


void Sniffer::save_header(Package *p, struct pcap_pkthdr *header){
    time_t local_tv_sec;
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&p->time, &local_tv_sec);
    p->len = header->len;
}


int Sniffer::analyzing(const u_char *pkt_data, Package *p){
//    ofstream outFile;
//    outFile.open("E:/winpcap-data.csv", ios::out); // 打开模式可省
//    outFile << "time,usec,len,mac_src,mac_dst,type1,"
//            << "version,headlen,TOS,len,ident,flag,offset,TTL,type2,crc,"
//            << "ip_src,ip_dst,"
//            << "sport,dport,seq/len,ack/crc,headlen,flags,winlen,crc,urgep,"
//            << endl;

//    print_pakheader(&outFile, header);
    p->data = pkt_data;
    p->eh = (ethe_header *) pkt_data;
//    print_etheheader(&outFile, eh);

    if(p->eh->type == 8){
        p->ih = (ip_header *) (pkt_data + 14);
//        print_ipheader(&outFile, ih);
        if(p->ih->proto == 6){
            p->th = (tcp_header *) (pkt_data + 14 + p->get_iphead_len() * 4);
//            print_tcpheader(&outFile, th);
        } else if(p->ih->proto == 17){
            p->uh = (udp_header *) (pkt_data + 14 + p->get_iphead_len() * 4);
//            print_udpheader(&outFile, uh);
        }
    }
//    outFile << endl;

//        outFile.close();

}

int Sniffer::stop(){
    this->run_flag = 0;
//    QMessageBox::information(NULL, "Title", "testing thread");

    return 0;
}
