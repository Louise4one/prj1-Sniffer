//数据包格式分析
#ifndef DATAFORMAT_H
#define DATAFORMAT_H

typedef unsigned char uchar;//1
typedef unsigned short ushort;//2
typedef unsigned int uint;//3
typedef unsigned long ulong;//4

//MAC帧
//6byte destination address
//6byte source address
//2byte type
typedef struct ether_head{
    uchar ethernet_destination_host[6];
    uchar ethernet_source_host[6];
    ushort type;
}ETHER_HEAD;

//IPv4
//4bit version
//4bit head length
//8bit TOS/DS_byte
//16bit total length
//16bit id
//16bit flag+offset
//8bit ttl
//8bit protocol
//16bit checksum
//32bit source ip address
//32bit destination ip address
typedef struct ip_header{
    uchar version_and_head_length; //未满一字节，拼起来
    uchar TOS;
    ushort total_length;
    ushort id;
    ushort flag_offset;
    uchar ttl;
    uchar protocol;
    ushort checksum;
    uint source_ip_address;
    uint destination_ip_address;
}IP_HEADER;

//TCP
//16bit source port
//16bit destination port
//32bit sequence number
//32bit ack number
//4bit header length
//6bit reserve
//6bit flags
//16bit window size
//16bit checksum
//16bit urgent
typedef struct tcp_header{
    ushort source_port;
    ushort destination_port;
    uint sequence_number;
    uint ack_number;
    uchar header_length;
    uchar flags;
    ushort window_size;
    ushort checksum;
    ushort urgent;
} TCP_HEADER;

//UDP
//16bit source port
//16bit destination port
//16bit data package length
//16bit checksum
typedef struct udp_header{
    ushort source_port;
    ushort destination_port;
    ushort data_length;
    ushort checksum;
} UDP_HEADER;

//ARP
//2byte hardware type
//2byte protocol type
//1byte mac length
//1byte ip length
//2byte operation type
//6byte source mac address
//4byte source ip address
//6byte destination mac address
//4byte destination ip address
typedef struct arp_header{
    ushort hardware_type;
    ushort protocol_type;
    uchar mac_length;
    uchar ip_length;
    ushort op_code;
    uchar source_mac_addr[6];
    uchar source_ip_addr[4];
    uchar destination_mac_addr[6];
    uchar destination_ip_addr[4];
} ARP_HEADER;

//ICMP
//1byte type
//1byte code
//2byte checksum
//2byte id
//2byte sequence
//option
typedef struct icmp_header{
    uchar type;
    uchar code;
    ushort checksum;
    ushort id;
    ushort sequence;
} ICMP_HEADER;

//DNS
//16bit id
//16bit flag
//16bit question
//16bit answer RRs
//16bit authority RRs
//16bit additional RRs
typedef struct dns_header{
    ushort id;
    ushort flag;
    ushort question;
    ushort answer;
    ushort authority;
    ushort additional;
} DNS_HEADER;

#endif // DATAFORMAT_H
