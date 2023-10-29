#ifndef MULTITHREAD_H
#define MULTITHREAD_H
#include <QThread>
#include "pcap.h"
#include "datapackage.h"
#include <QObject>

class MultiThread:public QThread
{
    Q_OBJECT
public:
    MultiThread();
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    void run() override;
    int ethernetPackageHandle(const uchar *packet_content, QString &info); //从MAC层解析数据
    int ipPackageHandle(const uchar *packet_content, int &ipPackage);  //处理ip数据包
    int tcpPackageHandle(const uchar *packet_content, QString &info, int &ipPackage); //处理ARP数据包
signals:
    void send(DataPackage data);
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
