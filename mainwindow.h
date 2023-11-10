#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "winsock2.h"
#include "datapackage.h"
#include <QObject>
#include <QVector>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();//用于显示网卡设备
    int capture(); //抓包

private slots:
    void on_comboBox_currentIndexChanged(int index);

    void on_tableWidget_cellClicked(int row, int column);
    
    void on_checkBox_stateChanged(int arg1);

    void on_checkBox_2_stateChanged(int arg1);

    void on_checkBox_3_stateChanged(int arg1);

    void on_checkBox_4_stateChanged(int arg1);

    void on_checkBox_5_stateChanged(int arg1);

public slots:
    void HandleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_device;
    pcap_if_t *device;
    pcap_t *pointer;
    QVector<DataPackage>pData;
    int countNumber; //数据包个数
    char errbuf[PCAP_ERRBUF_SIZE];
    int selectRow;  //选中的那一行
    //过滤
    struct bpf_program filter;
    char *filter_app = "";
    bool status[5];
    void filterChange(bool status[5]);
};

#endif // MAINWINDOW_H
