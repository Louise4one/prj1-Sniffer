#include "multithread.h"
#include <QDebug>
#include "dataformat.h"
#include "datapackage.h"
#include <QObject>

MultiThread::MultiThread()
{
    this->isDone = true;
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
    this->isDone = true;
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
                int len = header->len;
                data.setInfo(info);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
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
        info = "ip";
        return 1;
    }
    case 0x0806:{//ARP
        info = "arp";
        return 1;
    }
    default:
        return 0;
    }
    return 0;
}
