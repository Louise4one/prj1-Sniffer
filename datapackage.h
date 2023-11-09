#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "dataformat.h"
#include <QString>

class DataPackage
{

protected:
    static QString byteToString(uchar *str, int size); //用于显示16进制内容
public:
    const uchar *packet_content; //内容指针
private:
    uint data_length;
    QString time_stamp;
    QString info;
    int package_type;
public:
    DataPackage();
    //设置
    void setDataLength(uint data_length);
    void setTimeStamp(QString time_stamp);
    void setPackageType(int type);
    void setPointer(const uchar *packet_content, uint size);
    void setInfo(QString info);

    //获取
    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();
    QString getDestination();
    QString getSource();
    
    QString getDesMacAddr();
    QString getSrcMacAddr();
    QString getMacType();
    
    QString getDesIpAddr();
    QString getSrcIpAddr();
    QString getIpVersion();

    QString getArpOperationCode();
    QString getArpProtocolType();
    QString getArpHardwareType();
    QString getArpProtocolLength();
    QString getArpHardwareLength();
    QString getArpSrcMacAddr();
    QString getArpDesMacAddr();
    QString getArpSrcIpAddr();
    QString getArpDesIpAddr();
};

#endif // DATAPACKAGE_H
