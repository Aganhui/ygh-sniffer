#include "protocol.h"
#include<iostream>
using namespace std;

#define ADDR_BUF 256


Package::Package(){
    this->data = NULL;
    this->eh = NULL;
    this->ih = NULL;
    this->th = NULL;
    this->uh = NULL;
}

//u_int Package::get_iphead_len(){
//    if(this->ih)
//        return this->ih->ver_ihl & 0x0f;
//    else{
//        printf("error: package ih is none");
//        return -1;
//    }
//}

string Package::get_time(){
    char timestr[16];
    strftime( timestr, sizeof timestr, "%H:%M:%S", &this->time);
    return timestr;
}

u_int Package::get_len(){
    return this->len;
}

string Package::get_protocol(){
    if(this->th)
        return "TCP";
    else if(this->uh)
        return "UDP";
    else
        return "Others";
}

string Package::get_ip_str(ip_address *ia){
    char addr_buf[ADDR_BUF];
    sprintf(addr_buf, "%d.%d.%d.%d",
            ia->byte1, ia->byte2, ia->byte3, ia->byte4);
    return addr_buf;
}

string Package::get_mac_str(ethe_addr *ea){
    char addr_buf[ADDR_BUF];
    sprintf(addr_buf, "%d:%d:%d:%d:%d:%d",
            ea->byte1, ea->byte2, ea->byte3, ea->byte4, ea->byte5, ea->byte6);
    return addr_buf;
}

string Package::get_src_ip(){
    if(this->ih)
        return this->get_ip_str(&this->ih->saddr);
    else
        return NONE;
}

string Package::get_dst_ip(){
    if(this->ih)
        return this->get_ip_str(&this->ih->daddr);
    else
        return NONE;
}

u_int Package::get_src_port(){
    if(this->th)
        return this->th->sport;
    else if(this->uh)
        return this->uh->sport;
    else
        return -1;
}

u_int Package::get_dst_port(){
    if(this->th)
        return this->th->dport;
    else if(this->uh)
        return this->uh->dport;
    else
        return -1;
}
