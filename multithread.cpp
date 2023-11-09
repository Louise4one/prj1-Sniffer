#include "multithread.h"
#include <QDebug>
#include "dataformat.h"
#include "datapackage.h"
#include <QObject>

MultiThread::MultiThread()
{
    this->isDone = false;
    this->pointer = nullptr;
    this->header = nullptr;
    this->pkt_data = nullptr;
}

QString MultiThread::byteToString(uchar *str, int size){
    QString res = "";
    for (int i = 0; i < size; i++) {
        char high = str[i] >> 4;
        char low = str[i] & 0xF;
        if(high >= 0x0A){
            high += 0x41 - 0x0A;
        }else {
            high += 0x30;
        }
        if(low >= 0x0A){
            low += 0x41 - 0x0A;
        }else {
            low += 0x30;
        }
        res.append(high);
        res.append(low);
    }
    return res;
}

bool MultiThread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer != nullptr){
        return true;
    }else {
        return  false;
    }
}

void MultiThread::setFlag(){
    this->isDone = true;
}

void MultiThread::resetFlag(){
    this->isDone = false;
}

void MultiThread::run(){//不停捕捉数据包
    while(true){
        if(isDone){
            break;
        }else {
            int res = pcap_next_ex(pointer, &header, &pkt_data);
            if(res == 0){ //无效数据包
                continue ;
            }
            //用于输出时间戳
            local_time_sec = header->ts.tv_sec;
            localtime_s(&local_time, &local_time_sec);
            strftime(timeString, sizeof (timeString),"%H:%M:%S", &local_time);
          //  qDebug()<<timeString;

            QString info = "";
            int type = ethernetPackageHandle(pkt_data, info);
            if(type){
                DataPackage data;
                uint len = header->len;
                data.setInfo(info);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
                data.setPackageType(type);
                data.setPointer(pkt_data, len);
                emit send(data);
            }else {
                continue ;
            }
        }
    }
}

int MultiThread::ethernetPackageHandle(const uchar *packet_content, QString &info){
    ETHER_HEAD *ethernet;
    ushort content_type;
    ethernet = (ETHER_HEAD *)(packet_content);
    content_type = ntohs(ethernet->type);

    switch (content_type) {
    case 0x0800:{//IP
        int ipPackage = 0;
        int res = ipPackageHandle(packet_content, ipPackage);
        switch (res) {
        case 1:{  //ICMP
            info = icmpPackageHandle(packet_content);
            return 2;
        }
        case 6:{  //TCP
            return tcpPackageHandle(packet_content, info, ipPackage);
        }
        case 17:{  //UDP
            return udpPackageHandle(packet_content, info);
        }
        default:
            break;
        }
        break;
    }
    case 0x0806:{//ARP
        info = arpPackageHandle(packet_content);
        return 1;
    }
    default:
        break;
    }
    return 0;
}

int MultiThread::ipPackageHandle(const uchar *packet_content, int &ipPackage){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);  //14byte是以太网头部
    int protocol = ip->protocol;
    ipPackage = (ntohs(ip->total_length) - ((ip->version_and_head_length) & 0x0F) * 4); //数据长度
    return protocol;
}

int MultiThread::tcpPackageHandle(const uchar *packet_content, QString &info, int ipPackage){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);  //14byte是以太网头部，20byte是ip头部
    ushort source_port = ntohs(tcp->source_port);
    ushort destination_port = ntohs(tcp->destination_port);
    QString proSend = "";
    QString proRecv = "";
    int type = 3;
    int real_header_length = (tcp->header_length >> 4) * 4;
    int tcp_data_length = ipPackage - real_header_length;

    if(source_port == 443 || destination_port == 443){  //443
        if(source_port == 443){
            proSend = "(https)";
        }else if(destination_port == 443){
            proRecv = "(https)";
        }
    }
    info += QString::number(source_port) + proSend + "->" + QString::number(destination_port) + proRecv;

    QString flag = "";
    if(tcp->flags & 0x08){
        flag += "PSH,";
    }
    if(tcp->flags & 0x10){
        flag += "ACK,";
    }
    if(tcp->flags & 0x02){
        flag += "SYN,";
    }
    if(tcp->flags & 0x20){
        flag += "URG,";
    }
    if(tcp->flags & 0x01){
        flag += "FIN,";
    }
    if(tcp->flags & 0x04){
        flag += "RST,";
    }
    if(flag != ""){
        flag = flag.left(flag.length() - 1);
        info += " [" + flag + "]";
    }

    uint sequence_number = ntohl(tcp->sequence_number);
    uint ack_number = ntohl(tcp->ack_number);
    ushort window_size = ntohs(tcp->window_size);
    info += " Seq=" + QString::number(sequence_number) + " Ack=" + QString::number(ack_number) + " window=" + QString::number(window_size) + " Len=" + QString::number(tcp_data_length);
    return type;
}

int MultiThread::udpPackageHandle(const uchar *packet_content, QString &info){
    UDP_HEADER *udp;
    udp = (UDP_HEADER*)(packet_content + 14 + 20);
    ushort destination_port = ntohs(udp->destination_port);
    ushort source_port = ntohs(udp->source_port);
    if(destination_port == 53 || source_port == 53){  //DNS
        info = dnsPackageHandle(packet_content);
        return 5;
    } else {
        QString res = QString::number(source_port) + "->" + QString::number(destination_port);
        ushort data_length = ntohs(udp->data_length);
        res += " length=" + QString::number(data_length);
        info = res;
        return 4;
    }
}

QString MultiThread::arpPackageHandle(const uchar *packet_content){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);

    ushort op = ntohs(arp->op_code);
    QString res = "";
    uchar *destination_addr = arp->destination_ip_addr;
    QString des_ip_string = QString::number(*destination_addr) + "."
                          + QString::number(*(destination_addr + 1)) + "."
                          + QString::number(*(destination_addr + 2)) + "."
                          + QString::number(*(destination_addr + 3));
    uchar *source_addr = arp->source_ip_addr;
    QString src_ip_string = QString::number(*source_addr) + "."
                          + QString::number(*(source_addr + 1)) + "."
                          + QString::number(*(source_addr + 2)) + "."
                          + QString::number(*(source_addr + 3));

    uchar *source_mac_addr = arp->source_mac_addr;
    QString src_mac_string = byteToString(source_mac_addr, 1) + ":"
                          + byteToString((source_mac_addr + 1), 1) + ":"
                          + byteToString((source_mac_addr + 2), 1) + ":"
                          + byteToString((source_mac_addr + 3), 1) + ":"
                          + byteToString((source_mac_addr + 4), 1) + ":"
                          + byteToString((source_mac_addr + 5), 1);

    if(op == 1){  //询问
        res = "Who has " + des_ip_string + "? Tell " + src_ip_string;
    } else if (op == 2) {  //问答
        res = src_ip_string + " is at " + src_mac_string;
    }

    return res;
}

QString MultiThread::dnsPackageHandle(const uchar *packet_content){
    DNS_HEADER* dns;
    dns = (DNS_HEADER*)(packet_content + 14 + 20 + 8);  //8是UDP头部长度
    ushort id = ntohs(dns->id);
    ushort type = dns->flag;
    QString info = "";
    if((type & 0xf800) == 0x0000){  //QR位
        info = "Standard query ";
    }else if ((type & 0xf800) == 0x8000) {
        info = "Standard query response ";
    }
    QString name = "";
    char* domain = (char*)(packet_content + 14 + 20 + 8 + 12);  //数据部分
    while(*domain != 0x00){  //0x00代表结尾
        if(domain != nullptr && (*domain) <= 64){  //小于64则表示该部分长度
            int length = *domain;
            domain ++;
            for (int k = 0; k < length; k++) {
                name += (*domain);
                domain ++;
            }
            name += ".";
        } else {
            break;
        }
    }
    if(name != ""){
        name = name.left(name.length() - 1);
    }
    return info + "0x" + QString::number(id, 16) + " " + name;
}

QString MultiThread::icmpPackageHandle(const uchar *packet_content){
    ICMP_HEADER* icmp;
    icmp = (ICMP_HEADER*)(packet_content + 14 + 20);  //封装在IP
    uchar type = icmp->type;
    uchar code = icmp->code;
    QString res = "";
    switch (type) {
    case 0:{
        if(code == 0){
            res = "Echo response (ping command response)";
        }
        break;
    }
    case 3:{
        if(code == 0){
            res = "Network unreachable";
        }
        else if(code == 1){
            res = "Host unreachable";
        }
        else if (code == 2) {
            res = "Protocol unreachable";
        }
        else if(code == 3){
            res = "Port unreachable";
        }
        else if(code == 4){
            res = "Fragmentation is required, but DF is set";
        }
        else if (code == 5) {
            res = "Source route selection failed";
        }
        else if (code == 6) {
            res = "Unknown target network";
        }
        break ;
    }
    case 5:{
        res = "Relocation";
        break ;
    }
    case 8:{
        if(code == 0){
            res = "Echo request (ping command request)";
        }
        break ;
    }
    default: break;
    }
    return res;
}
