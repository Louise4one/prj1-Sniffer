#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
}

MainWindow::~MainWindow()
{
    delete ui;
}
//用于显示网卡设备
void MainWindow::showNetworkCard(){
    int n = pcap_findalldevs(&all_device, errbuf);
    if(n == -1){
        ui->comboBox->addItem("error: " + QString(errbuf));
    }else{
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose card");
        for(device = all_device; device!=nullptr; device=device->next){
            QString device_name = device->name;
            device_name.replace("\\Device\\", "");  //不是必需的
            QString des = device->description; //描述符
            QString item = device_name + des;
            ui->comboBox->addItem(item);
        }
    }

}
