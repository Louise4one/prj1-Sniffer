#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "winsock2.h"
#include "datapackage.h"
#include <QObject>

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

public slots:
    void HandleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_device;
    pcap_if_t *device;
    pcap_t *pointer;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // MAINWINDOW_H
