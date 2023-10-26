#include "multithread.h"
#include <QDebug>

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
            } else {
                //后面再写
            }
        }
    }
}
