# coding:utf-8
# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from PN import *
import os
import sys
import threading
import time

class pnthread(threading.Thread):
    def __init__(self, name=None):
        threading.Thread.__init__(self, name=name)

    def run(self):
        print("name"+self.name)


def inputCMD():
    while True:
        print("s 扫描局域网内设备")
        print("p 打印扫描到的设备")
        print("c 修改设备属性")
        print("a 显示所有网卡")
        num = input("")
        if num == 's':
            pn.sendScanPacket()
        elif num=='p':
            printalldevice()
        elif num=='c':#修改设备名称
            setnum = int(input("输入要修改的设备编号:"))
            if setnum< len(PnPacket.pnDeviceList) or setnum>=0:
                print("n  修改设备名:如:pnadpdater")
                print("i  修改ip    如:192.168.0.3")
                print("m  修改掩码   如:255.255.255.0")
                print("g  修改网关   如:192.168.0.1")
                setconfig = input("")
                if setconfig == 'n':
                    namestr=input("输入名称:")
                    PnPacket.SetDeviceNamebyIndex(setnum,namestr)
                elif setconfig =='i':
                    ipstr = input("输入ip:")
                    PnPacket.SetDeviceIPbyIndex(setnum,ipstr)
                elif setconfig=='m':
                    maskstr= input("请输入掩码")
                elif setconfig =='g':
                    gatewaystr = input("请输入网关")
                else:
                    print("暂时未开通敬请期待")
        elif num=='a':
            PnPacket.show_all_devices()





def test():
    while True:
        print("this is test")
        time.sleep(1)
def printalldevice():
        pn.printalldevice()
if __name__ == '__main__':
    pn=PnPacket()
    pn.GetallNetCard()
    pn.sendScanPacket()
    t2 = threading.Thread(target=inputCMD)
    t1 = threading.Thread(target=pn.recvpakcet)
    #t3 = threading.Thread(target = printalldevice)
    t2.start()
    t1.start()
    #t3.start()






