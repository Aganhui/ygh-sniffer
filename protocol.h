#ifndef PROTOCOL_H
#define PROTOCOL_H

#endif // PROTOCOL_H

#include<winsock2.h>
#include<iostream>
using namespace std;

#include<time.h>
#define NONE "none"

typedef struct ethe_addr{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}ethe_addr;

typedef struct ethe_header{
    ethe_addr daddr;
    ethe_addr saddr;
    u_short type;
}ethe_header;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP header*/
typedef struct tcp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int seq_id;
    u_int ack_id;
    u_short len_type;
    u_short winlen;			// Len of window
    u_short crc;            // Checksum
    u_short urgep;          // Urgent pointer
    // Optional (times 8)
}tcp_header;


/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;


class Package{
public:
    Package();
    struct tm time;
    u_int len;
    const u_char *data;
    ethe_header *eh;
    ip_header *ih;
    tcp_header *th;
    udp_header *uh;

public:
    string get_time();
    u_int get_len();
    string get_protocol();

    string get_src_mac(){
        return this->get_mac_str(&this->eh->saddr);
    };
    string get_dst_mac(){
        return this->get_mac_str(&this->eh->daddr);
    };
    u_int get_eh_type(){
        return this->eh->type;
    };

    u_int get_version(){
        return this->ih->ver_ihl >>4;
    };
    u_int get_iphead_len(){
        return this->ih->ver_ihl & 0x0f * 4;
    };
    u_int get_tos(){
        return this->ih->tos;
    };
    u_int get_total_len(){
        return this->ih->tlen;
    };
    u_int get_indenti(){
        return this->ih->identification;
    };
    u_int get_flag(){
        return this->ih->flags_fo >> 13;
    };
    u_int get_offset(){
        return this->ih->flags_fo & 0b0001111111111111;
    };
    u_int get_ttl(){
        return this->ih->ttl;
    };
    u_int get_ih_type(){
        return this->ih->proto;
    };
    string get_src_ip();
    string get_dst_ip();

    u_int get_src_port();
    u_int get_dst_port();
    u_int get_seq(){
        return this->th->seq_id;
    };
    u_int get_ack(){
        return this->th->ack_id;
    };
    u_int get_tcphead_len(){
        return this->th->len_type >> 12;
    };
    u_int get_ack_flag(){
        return this->th->len_type & 0b0000000000010000;
    };
    u_int get_syn_flag(){
        return this->th->len_type & 0b0000000000000010;
    };
    u_int get_fin_flag(){
        return this->th->len_type & 0b0000000000000001;
    };
    u_int get_window_size(){
        return this->th->winlen;
    };

    u_int get_udphead_len(){
        return this->uh->len;
    };



private:
    string get_ip_str(ip_address *ia);
    string get_mac_str(ethe_addr *ma);

};

