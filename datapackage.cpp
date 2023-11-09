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
    case 6:
        return "TLS";
    case 7:
        return "SSL";
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

QString DataPackage::getArpOperationCode(){
    ARP_HEADER *arp;
    arp = (ARP_HEADER*)(packet_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1){
        res  = "request(1)";
    } else if(code == 2) {
        res = "reply(2)";
    }
    return res;
}
