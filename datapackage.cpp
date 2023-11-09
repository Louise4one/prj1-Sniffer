#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    //初始化
    this->time_stamp = "";
    this->data_length = 0;
    this->package_type = 0;
    this->packet_content = nullptr;
}

QString DataPackage::byteToString(uchar *str, int size){
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

void DataPackage::setInfo(QString info){
    this->info = info;
}

void DataPackage::setPointer(const uchar *packet_content, uint size){
    this->packet_content = (uchar *)malloc(size);
    memcpy((char*)(this->packet_content), packet_content, size);
}

void DataPackage::setTimeStamp(QString time_stamp){
    this->time_stamp = time_stamp;
}

void DataPackage::setDataLength(uint data_length){
    this->data_length = data_length;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getTimeStamp(){
    return this->time_stamp;
}

QString DataPackage::getPackageType(){
    switch (this->package_type) {
    case 1:
        return "ARP";
    case 2:
        return "ICMP";
    case 3:
        return "TCP";
    case 4:
        return "UDP";
    case 5:
        return "DNS";
    default:
        return "";
    }
}

QString DataPackage::getInfo(){
    return info;
}

void DataPackage::setPackageType(int type){
    this->package_type = type;
}

QString DataPackage::getDestination(){
    if(this->package_type == 1){
        return this->getDesMacAddr();
    }else {
        return this->getDesIpAddr();
    }
}

QString DataPackage::getSource(){
    if(this->package_type == 1){
        return this->getSrcMacAddr();
    }else {
        return this->getSrcIpAddr();
    }
}

QString DataPackage::getDesMacAddr(){
    ETHER_HEAD *eth;
    eth = (ETHER_HEAD*)(packet_content);
    uchar *addr = eth->ethernet_destination_host;
    if(addr){
        QString res = byteToString(addr, 1) + ":"
                    + byteToString((addr + 1), 1) + ":"
                    + byteToString((addr + 2), 1) + ":"
                    + byteToString((addr + 3), 1) + ":"
                    + byteToString((addr + 4), 1) + ":"
                    + byteToString((addr + 5), 1);
        
        if(res == "FF:FF:FF:FF:FF:FF"){  //广播地址
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        } else {
            return res;
        }
    }
}

QString DataPackage::getSrcMacAddr(){
    ETHER_HEAD *eth;
    eth = (ETHER_HEAD*)(packet_content);
    uchar *addr = eth->ethernet_source_host;
    if(addr){
        QString res = byteToString(addr, 1) + ":"
                    + byteToString((addr + 1), 1) + ":"
                    + byteToString((addr + 2), 1) + ":"
                    + byteToString((addr + 3), 1) + ":"
                    + byteToString((addr + 4), 1) + ":"
                    + byteToString((addr + 5), 1);
        
        if(res == "FF:FF:FF:FF:FF:FF"){  //广播地址
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        } else {
            return res;
        }
    }
}

QString DataPackage::getMacType(){
    ETHER_HEAD *eth;
    eth = (ETHER_HEAD *)(packet_content);
    ushort type = ntohs(eth->type);
    if(type == 0x0800){
        return "IPv4(0x0800)";
    }else if (type == 0x0806) {
        return "ARP(0x0806)";
    }else {
        return "";
    } 
}

QString DataPackage::getDesIpAddr(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    sockaddr_in DesIp;
    DesIp.sin_addr.s_addr = ip->destination_ip_address;
    return QString(inet_ntoa(DesIp.sin_addr));
}

QString DataPackage::getSrcIpAddr(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    sockaddr_in SrcIp;
    SrcIp.sin_addr.s_addr = ip->source_ip_address;
    return QString(inet_ntoa(SrcIp.sin_addr));
}

QString DataPackage::getIpVersion(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    return QString::number(ip->version_and_head_length >> 4);
}

QString DataPackage::getIpHeadLength(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = "";
    int length = ip->version_and_head_length & 0x0F;
    if(length == 5){
        res = "20 bytes (5)";
    }else{
        res = QString::number(length * 5) + "bytes (" + QString::number(length) + ")";
    }
    return res;
}

QString DataPackage::getIpTos(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number(ntohs(ip->TOS));
    return res;
}

QString DataPackage::getIpTotalLength(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number(ntohs(ip->total_length));
    return res;
}

QString DataPackage::getIpIdentification(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number(ntohs(ip->id), 16);
    return res;
}

QString DataPackage::getIpFlag(){
    IP_HEADER *ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8, 16);
    return res;
}

QString DataPackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    QString res = QString::number(bit);
    return res;
}

QString DataPackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
    return res;
}

QString DataPackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
    return res;
}

QString DataPackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number(ntohs(ip->flag_offset) & 0x1FFF);
    return res;
}

QString DataPackage::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    QString res = QString::number(ip->ttl);
    return res;
}

QString DataPackage::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:
        return "ICMP (1)";
    case 6:
        return "TCP (6)";
    case 17:
        return "UDP (17)";
    default:
        return "";
    }
}

QString DataPackage::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(packet_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

QString DataPackage::getArpOperationCode(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    int code = ntohs(arp->op_code);
    if(code == 1){
        res = "request(1)";
    } else if(code == 2) {
        res = "reply(2)";
    }
    return res;
}

QString DataPackage::getArpProtocolType(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    int type = ntohs(arp->protocol_type);
    if(type == 0x0800){
        res = "IPv4(0x0800)";
    }else {
        res = QString::number(type);
    }
    return res;
}

QString DataPackage::getArpHardwareType(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    int type = ntohs(arp->hardware_type);
    if(type == 1){
        res = "Ethernet(1)";
    }else {
        res = QString::number(type);
    }
    return res;
}

QString DataPackage::getArpProtocolLength(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = QString::number(arp->ip_length);
    return res;
}

QString DataPackage::getArpHardwareLength(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = QString::number(arp->mac_length);
    return res;
}

QString DataPackage::getArpSrcIpAddr(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    uchar *addr = arp->source_ip_addr;
    res += QString::number(*addr) + "."
         + QString::number(*(addr+1)) + "."
         + QString::number(*(addr+2)) + "."
         + QString::number(*(addr+3));
    return res;
}

QString DataPackage::getArpDesIpAddr(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    uchar *addr = arp->destination_ip_addr;
    res += QString::number(*addr) + "."
         + QString::number(*(addr+1)) + "."
         + QString::number(*(addr+2)) + "."
         + QString::number(*(addr+3));
    return res;
}

QString DataPackage::getArpSrcMacAddr(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    uchar *addr = arp->source_mac_addr;
    res += byteToString(addr,1) + ":"
         + byteToString((addr+1),1) + ":"
         + byteToString((addr+2),1) + ":"
         + byteToString((addr+3),1) + ":"
         + byteToString((addr+4),1) + ":"
         + byteToString((addr+5),1);
    return res;
}

QString DataPackage::getArpDesMacAddr(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    QString res = "";
    uchar *addr = arp->destination_mac_addr;
    res += byteToString(addr,1) + ":"
         + byteToString((addr+1),1) + ":"
         + byteToString((addr+2),1) + ":"
         + byteToString((addr+3),1) + ":"
         + byteToString((addr+4),1) + ":"
         + byteToString((addr+5),1);
    return res;
}

QString DataPackage::getTcpSourcePort(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = "";
    int port = ntohs(tcp->source_port);
    if(port == 443){
        res = "https(443)";
    }else{
        res = QString::number(port);
    }
    return res;
}

QString DataPackage::getTcpDestinationPort(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = "";
    int port = ntohs(tcp->destination_port);
    if(port == 443){
        res = "https(443)";
    }else{
        res = QString::number(port);
    }
    return res;
}

QString DataPackage::getTcpSequence(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(ntohl(tcp->sequence_number));
    return res;
}

QString DataPackage::getTcpAcknowledgment(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(ntohl(tcp->ack_number));
    return res;
}

QString DataPackage::getTcpHeaderLength(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = "";
    int length = (tcp->header_length >> 4);
    if(length == 5){
        res = "20 bytes (5)";
    }else{
        res = QString::number(length*4) + " bytes (" + QString::number(length) + ")";
    }
    return res;
}

QString DataPackage::getTcpRawHeaderLength(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(tcp->header_length >> 4);
    return res;
}

QString DataPackage::getTcpFlags(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(tcp->flags, 16);
    return res;
}

QString DataPackage::getTcpPSH(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(((tcp->flags) & 0x08) >> 3);
    return res;
}

QString DataPackage::getTcpACK(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(((tcp->flags) & 0x10) >> 4);
    return res;
}

QString DataPackage::getTcpSYN(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(((tcp->flags) & 0x02) >> 1);
    return res;
}

QString DataPackage::getTcpURG(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(((tcp->flags) & 0x20) >> 5);
    return res;
}

QString DataPackage::getTcpFIN(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number((tcp->flags) & 0x01);
    return res;
}

QString DataPackage::getTcpRST(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(((tcp->flags) & 0x04) >> 2);
    return res;
}

QString DataPackage::getTcpWindowSize(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(ntohs(tcp->window_size));
    return res;
}

QString DataPackage::getTcpCheckSum(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(ntohs(tcp->checksum), 16);
    return res;
}

QString DataPackage::getTcpUrgentPointer(){
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER*)(packet_content + 14 + 20);
    QString res = QString::number(ntohs(tcp->urgent));
    return res;
}
