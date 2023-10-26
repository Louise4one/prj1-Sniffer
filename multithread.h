#ifndef MULTITHREAD_H
#define MULTITHREAD_H
#include <QThread>
#include "pcap.h"

class MultiThread:public QThread
{
public:
    MultiThread();
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    void run() override;
private:
    pcap_t *pointer;
    struct pcap_pkthdr *header;  //数据包头部
    const u_char *pkt_data;  //数据包内容
    time_t local_time_sec;  //时间戳
    struct tm local_time;
    char timeString[16];  //时间以字符串呈现
    bool isDone;
};

#endif // MULTITHREAD_H
