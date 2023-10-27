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



#endif // DATAFORMAT_H
