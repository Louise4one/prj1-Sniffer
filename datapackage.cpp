#include "datapackage.h"
#include <QMetaType>

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    //初始化
    this->time_stamp = "";
    this->data_length = 0;
    this->package_type = 0;
}

QString DataPackage::byteToString(char *str, int size){
    QString res = "";
    for (int i = 0; i < size; i++) {
        char high = str[i] >> 4;
        char low = str[i] & 0xF;
        if(high > 0x0A){
            high += 0x41 - 0x0A;
        }else {
            high += 0x30;
        }
        if(low > 0x0A){
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

void DataPackage::setPointer(const uchar *packet_content, int size){
    this->packet_content = packet_content;
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
    return this->time_stamp;
}
