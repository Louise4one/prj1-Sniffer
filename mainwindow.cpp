#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <QDebug>
#include <QObject>
#include <multithread.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->toolBar->addAction(ui->actionRunAndStop);
    ui->toolBar->addAction(ui->actionClear);
    countNumber = 0;
    selectRow = -1;  //一开始没有选择
    showNetworkCard();
    static bool index = false;
    MultiThread *thread = new MultiThread;
    ui->comboBox->setEnabled(true);
    pData.clear();
    device = nullptr;
    pointer = nullptr;

    connect(ui->actionRunAndStop, &QAction::triggered, this, [=]{
        index = !index;

        if(index){
            ui->tableWidget->clearContents(); //清空
            ui->tableWidget->setRowCount(0);
            ui->treeWidget->clear();
            countNumber = 0;
            selectRow = -1;

            int dataSize = this->pData.size();
            for (int i = 0; i < dataSize; i++) {
                free((char *)(this->pData[i].packet_content));
                this->pData[i].packet_content = nullptr;
            }
            QVector<DataPackage>().swap(pData);  //和空容器交换
            //开始
            int res = capture();
            if(res != -1 && pointer != nullptr){  //设备打开成功
                thread->setPointer(pointer);
                thread->resetFlag();
                thread->start();
                ui->actionRunAndStop->setIcon(QIcon(":/pause.png"));
                ui->comboBox->setEnabled(false);
                countNumber = 0;
            } else {  //打开失败
                index = !index;
                countNumber = 0;
            }
        }else{
            //暂停
            thread->setFlag();
            thread->quit();
            thread->wait();
            ui->actionRunAndStop->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            pcap_close(pointer);
        }
    });//lambda表达式

    connect(thread, &MultiThread::send, this, &MainWindow::HandleMessage);

    ui->toolBar->setMovable(false);
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);

    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,150);
    ui->tableWidget->setColumnWidth(5,150);
    ui->tableWidget->setColumnWidth(6,1000);

    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);
}

MainWindow::~MainWindow()
{
    int dataSize = this->pData.size();
    for (int i = 0; i < dataSize; i++) {
        free((char*)(this->pData[i].packet_content));
        this->pData[i].packet_content = nullptr;
    }
    QVector<DataPackage>().swap(pData);
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

void MainWindow::HandleMessage(DataPackage data){

   // qDebug()<<"test debug"<<endl;
   // qDebug()<<data.getTimeStamp()<<" "<<data.getInfo();
    ui->tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "TCP"){  //颜色不是必需的
        color = QColor(216, 191, 216);
    }
    else if(type == "UDP"){
        color = QColor(144, 238, 144);
    }
    else if(type == "ARP"){
        color = QColor(238, 238, 0);
    }
    else if(type == "DNS"){
        color = QColor(255, 255, 224);
    }
    else {
        color = QColor(255, 218, 185);
    }

    ui->tableWidget->setItem(countNumber, 0, new QTableWidgetItem(QString::number(countNumber)));  //序号
    ui->tableWidget->setItem(countNumber, 1, new QTableWidgetItem(data.getTimeStamp()));  //时间戳
    ui->tableWidget->setItem(countNumber, 2, new QTableWidgetItem(data.getSource()));  //源地址
    ui->tableWidget->setItem(countNumber, 3, new QTableWidgetItem(data.getDestination()));  //目的地址
    ui->tableWidget->setItem(countNumber, 4, new QTableWidgetItem(type));  //协议
    ui->tableWidget->setItem(countNumber, 5, new QTableWidgetItem(data.getDataLength()));  //长度
    ui->tableWidget->setItem(countNumber, 6, new QTableWidgetItem(data.getInfo()));  //信息

    for (int i = 0; i < 7; i++) {
        ui->tableWidget->item(countNumber, i)->setBackgroundColor(color);
    }
    countNumber ++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(row == selectRow){
        return ;
    }else {
        ui->treeWidget->clear();
        selectRow = row;
        QString DesMac = pData[selectRow].getDesMacAddr();
        QString SrcMac = pData[selectRow].getSrcMacAddr();
        QString type = pData[selectRow].getMacType();
        QString tree = "Ethernet, Destination: " + DesMac + ", Source: " + SrcMac;
        QTreeWidgetItem *item = new QTreeWidgetItem(QStringList() << tree);
        ui->treeWidget->addTopLevelItem(item);
        item->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + DesMac));
        item->addChild(new QTreeWidgetItem(QStringList() << "Source: " + SrcMac));
        item->addChild(new QTreeWidgetItem(QStringList() << "Type: " + type));

        QString packageType = pData[selectRow].getPackageType();
        if(packageType == "ARP"){
            QString arpOpCode = pData[selectRow].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + arpOpCode);
            ui->treeWidget->addTopLevelItem(item2);
            QString hardwareType = pData[selectRow].getArpHardwareType();
            QString protocolType = pData[selectRow].getArpProtocolType();
            QString hardwareSize = pData[selectRow].getArpHardwareLength();
            QString protocolSize = pData[selectRow].getArpProtocolLength();
            QString srcMacAddr = pData[selectRow].getArpSrcMacAddr();
            QString desMacAddr = pData[selectRow].getArpDesMacAddr();
            QString srcIpAddr = pData[selectRow].getArpSrcIpAddr();
            QString desIpAddr = pData[selectRow].getArpDesIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type: " + hardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type: " + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size: " + hardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size: " + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode: " + arpOpCode));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address: " + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address: " + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address: " + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address: " + desIpAddr));
            return ;
        }else {
            QString srcIpAddr = pData[selectRow].getSrcIpAddr();
            QString desIpAddr = pData[selectRow].getDesIpAddr();

            QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src: " + srcIpAddr + ", Dst: " + desIpAddr);
            ui->treeWidget->addTopLevelItem(item3);
            QString version = pData[selectRow].getIpVersion();
            QString headerLength = pData[selectRow].getIpHeadLength();
            QString tos = pData[selectRow].getIpTos();
            QString totalLength = pData[selectRow].getIpTotalLength();
            QString id = "0x" + pData[selectRow].getIpIdentification();
            QString flags = pData[selectRow].getIpFlag();
            if(flags.size()<2){
                flags = "0" + flags;
            }
            flags = "0x" + flags;
            QString fragmentOffset = pData[selectRow].getIpFragmentOffset();
            QString ttl = pData[selectRow].getIpTTL();
            QString protocol = pData[selectRow].getIpProtocol();
            QString checksum = "0x" + pData[selectRow].getIpCheckSum();
            item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version: " + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length: " + headerLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS: " + tos));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length: " + totalLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification: " + id));

            QString reservedBit = pData[selectRow].getIpReservedBit();
            QString DF = pData[selectRow].getIpDF();
            QString MF = pData[selectRow].getIpMF();
            QString FLAG = ",";

            if(reservedBit == "1"){
                FLAG += "Reserved bit";
            }
            else if(DF == "1"){
                FLAG += "Don't fragment";
            }
            else if(MF == "1"){
                FLAG += "More fragment";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags: " + flags + FLAG);
            item3->addChild(bitTree);
            QString temp1 = "";
            if(reservedBit == "1"){
                temp1 = "Set";
            }else {
                temp1 = "Not set";
            }
            QString temp2 = "";
            if(DF == "1"){
                temp2 = "Set";
            }else {
                temp2 = "Not set";
            }
            QString temp3 = "";
            if(MF == "1"){
                temp3 = "Set";
            }else {
                temp3 = "Not set";
            }
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit: " + temp1));
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment: " + temp2));
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment: " + temp3));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset: " + fragmentOffset));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live: " + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol: " + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum: " + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address: " + srcIpAddr));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address: " + desIpAddr));

            int dataLength = totalLength.toUtf8().toInt() - 20;
            if(packageType == "TCP"){
                QString desPort = pData[selectRow].getTcpDestinationPort();
                QString srcPort = pData[selectRow].getTcpSourcePort();
                QString ack = pData[selectRow].getTcpAcknowledgment();
                QString seq = pData[selectRow].getTcpSequence();
                QString headerLength = pData[selectRow].getTcpHeaderLength();
                int rawLength = pData[selectRow].getTcpRawHeaderLength().toUtf8().toInt();
                dataLength -= (rawLength * 4);
                QString flag = pData[selectRow].getTcpFlags();
                flag = "0x00" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port: " + srcPort + ", Dst Port: " + desPort + ",Seq: " + seq + ", Ack: " + ack + ", Len: " + QString::number(dataLength));
                ui->treeWidget->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port: " + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port: " + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) : " + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) : " + ack));

                QString sLength = QString::number(rawLength,2);
                while(sLength.size()<4)
                    sLength = "0" + sLength;
                item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Head Length: " + headerLength));

                QString PSH = pData[selectRow].getTcpPSH();
                QString URG = pData[selectRow].getTcpURG();
                QString ACK = pData[selectRow].getTcpACK();
                QString RST = pData[selectRow].getTcpRST();
                QString SYN = pData[selectRow].getTcpSYN();
                QString FIN = pData[selectRow].getTcpFIN();
                QString FLAG = "";

                QString temp4, temp5, temp6, temp7, temp8, temp9 = "Not set";
                if(PSH == "1"){
                    FLAG += "PSH,";
                    temp4 = "Set";
                }
                if(URG == "1"){
                    FLAG += "UGR,";
                    temp5 = "Set";
                }
                if(ACK == "1"){
                    FLAG += "ACK,";
                    temp6 = "Set";
                }
                if(RST == "1"){
                    FLAG += "RST,";
                    temp7 = "Set";
                }
                if(SYN == "1"){
                    FLAG += "SYN,";
                    temp8 = "Set";
                }
                if(FIN == "1"){
                    FLAG += "FIN,";
                    temp9 = "Set";
                }
                FLAG = FLAG.left(FLAG.length()-1);
                if(SYN == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
                }
                if(SYN == "1" && ACK == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
                }
                QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags: " + flag + " (" + FLAG + ")");
                item4->addChild(flagTree);
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG): " + temp5));
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK): " + temp6));
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH): " + temp4));
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST): " + temp7));
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN): " + temp8));
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN): " + temp9));

                QString window = pData[selectRow].getTcpWindowSize();
                QString checksum = "0x" + pData[selectRow].getTcpCheckSum();
                QString urgent = pData[selectRow].getTcpUrgentPointer();
                item4->addChild(new QTreeWidgetItem(QStringList()<<"window: " + window));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum: " + checksum));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer: " + urgent));
            }
        }
    }
    
}
