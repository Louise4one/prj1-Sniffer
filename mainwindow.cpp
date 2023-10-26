#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <multithread.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
    static bool index = false;
    MultiThread *thread = new MultiThread;
    connect(ui->actionRunAndStop, &QAction::triggered, this, [=](){
        index = !index;
        //多线程

        if(index){
            //开始
            int res = capture();
            if(res != -1 && pointer != nullptr){
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionRunAndStop->setIcon(QIcon(":/pause.png"));
                ui->comboBox->setEnabled(false);
            }
        }else{
            //暂停
            thread->resetFlag();
            thread->quit();
            thread->wait();
            ui->actionRunAndStop->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            pcap_close(pointer);
            pointer = nullptr;
        }
    });//lambda表达式
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

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0){
        for(device = all_device; i < index - 1; device = device->next, i++){
            ; //把device指向选择的设备
        }
    }
    return ;
}

int MainWindow::capture(){
    if(device!=nullptr){
        pointer = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    }else {
        return -1;
    }
    if(!pointer){
        pcap_freealldevs(all_device);//释放
        device = nullptr;
        return -1;
    }else {//否则设备打开成功
        if(pcap_datalink(pointer) != DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_device);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}
