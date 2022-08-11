
from winpcapy import *
from ctypes import *
import netifaces





class DcpRequestType():
    Requestall = 0xfefe
    SetConfig =  0xfefd
    ResponsAll =0xfeff

class ServiceType():
    Request = 0
    ResponseSuccess =1
class DcpOptions():
    OptionIP =1
    OptionDeviceProperties = 2
    OptionDHCP =3
    OptionControl =5
class DcpSubOption():
    SubOptionMac =1
    SubOptionTypeofStation =1
    SubOptionIp = 2
    SubOptionStationName =2
    SubOptionDeviceID = 3
    SubOptionDeviceRole =4
    SubOptionDHCPClientIndentifier = 61
    SubOptionStartTransaction =1
    SubOptionEndTransaction = 1
    SubOptionRsponse =4
class DcpInfoKey():
    DeviceNum=0
    DeviceName=1
    DeviceType=2
    DeviceIP=3
    DeviceNetMask=4
    DeviceGateWay=5
    DeviceMac=6
    DeviceRole=7
    VenderID=8
    DeviceID=9
class PnPacket:
    netCardNamelist =[]
    devideDeslist = []
    devideName =""
    devideDes = ""
    lastSeq=0  #记录当前发包前的流水号
    seq =0  #发一包增加一个流水号
    Mac=""
    selCardNum = 0
    keylist=["DeviceNum","DeviceName","DeviceType","DeviceIP","DeviceNetMask","DeviceGateWay","DeviceMac","DeviceRole","VenderID","DeviceID"]
    valueInitList=[0,"","","","","","","","",""]
    pnDeviceList=[{}]
    def __init(self):
        print("init")
    @staticmethod
    def get_all_devices():
        with WinPcapDevices() as devices:
            i = 0
            print(type(devices))
            for device in devices:
                #print("netCard:", i, device.name, device.description)
                PnPacket.devideDeslist.append(device.description)
                PnPacket.netCardNamelist.append(device.name)
                i = i + 1
    @staticmethod
    def show_all_devices():
        with WinPcapDevices() as devices:
            i = 0
            print(type(devices))
            for device in devices:
                print("netCard:", i, device.name, device.description)
                i = i + 1
    @staticmethod
    def GetallNetCard():
        PnPacket.get_all_devices()
        PnPacket.show_all_devices()
        while True:
            sel_num = int(input("选择的网卡编号:"))
            if sel_num < 0 or sel_num > len(PnPacket.netCardNamelist):
                print("输入错误")
                continue
            else:
                selCardNum=sel_num
                PnPacket.devideDes = PnPacket.devideDeslist[sel_num].decode("utf-8")
                selectCardName = PnPacket.netCardNamelist[sel_num]
                break

        CardNameStr = str(selectCardName.decode('utf-8'))
        PnPacket.devideName=CardNameStr.split('\\')[2].split('_')[1]
        print("now select netcard name :" + PnPacket.devideName)
        print("now select netcard des :" + PnPacket.devideDes)
    @staticmethod
    def GetCardMac():
        interfacelist = netifaces.interfaces()
        cardinfo = netifaces.ifaddresses(PnPacket.devideName)
        mac = cardinfo[netifaces.AF_LINK]
        PnPacket.Mac = mac[0]["addr"]
    @staticmethod
    def StopCapture():
        print("StopCapture---------------------------------")
        WinPcapUtils.StopCapture(PnPacket.devideDes)
    @staticmethod
    def sendScanPacket():
        scan_request_hex_template = "010ecf000000%(src_mac)s8892fefe0500" \
                                    "%(xiq_seq)s00c00004ffff0000" + 34 * "00"
        PnPacket.GetCardMac()
        macbuf = PnPacket.Mac.replace(':', '')

        seqstr = format(PnPacket.seq, '#010x').replace('0x', '')
        #print(seqstr)
        packet = scan_request_hex_template % {
            "src_mac": macbuf,
            "xiq_seq": seqstr
        }
        scanpacket = bytes.fromhex(packet)
        #print(scanpacket)
        print("send Pakcet on %s" %PnPacket.devideName)
        print("send Pakcet on %s" % PnPacket.devideDes)
        PnPacket.SendPacket(scanpacket)
        PnPacket.pnDeviceList.clear()

    @staticmethod
    def packet_callback(win_pcap, param, header, pkt_data):
        type_frame = pkt_data[12:14]
        dcp_frame = "8892"
       # print(type_frame)
        #print(type_frame.hex())
        if(type_frame.hex() == dcp_frame):
            PnPacket.parseDcpPacket(pkt_data)
    @staticmethod
    def parseResponsAll(data,srcMac):#解析返回的所有设备
        datalen = len(data)
        tmpLen = 0
        deviceinfo = dict(zip(PnPacket.keylist,PnPacket.valueInitList))
        deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceNum]]=len(PnPacket.pnDeviceList)
        deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceMac]]=srcMac
        #print("pndevicelist  size %d" % PnPacket.pnDeviceList.count())
       # print("pndevicelist  size %d" % len(PnPacket.pnDeviceList))
        while datalen>tmpLen:#遍历所有信息项
            #print("tmpLen %d " % tmpLen)
            #print("datalen %d " % datalen)
            headFrame = data[tmpLen:tmpLen+4]
            optionFrame= headFrame[0:1]
            subOptionFrame = headFrame[1:2]
            DcpBlockLenthFrame = headFrame[2:4]
            tmpLen += 4
            Option = int.from_bytes(optionFrame,byteorder='big',signed=False)
            SubOption = int.from_bytes(subOptionFrame,byteorder='big',signed=False)
            DcpBlockLenth = int.from_bytes(DcpBlockLenthFrame,byteorder='big',signed=False)
            # print("Option  %d " %Option)
            # print("SubOption  %d " % SubOption)
            # print("DcpBlockLenth  %d " % DcpBlockLenth)
            if Option == DcpOptions.OptionDeviceProperties:#如果是属性
                if SubOption == DcpSubOption.SubOptionTypeofStation:  #设备类型
                    DeviceTypeFrame=data[tmpLen+2:tmpLen+DcpBlockLenth]
                   # print(DeviceTypeFrame)
                    str_data = str(DeviceTypeFrame, encoding='utf-8')
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceType]] = str_data
                    # print(str_data)
                    #print(str(DeviceTypeFrame, encodings='utf-8'))
                elif SubOption == DcpSubOption.SubOptionStationName: #设备名称
                    DeviceNameFrame = data[tmpLen+2:tmpLen+DcpBlockLenth]
                    str_data = str(DeviceNameFrame, encoding='utf-8')
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceName]] = str_data
                    # print(str_data)
                    #print(str(DeviceNameFrame,encodings='utf-8'))
                elif SubOption == DcpSubOption.SubOptionDeviceID:   #设备ID
                    DeviceIdFrame = data[tmpLen+2:tmpLen+DcpBlockLenth]
                    VenderIDFrame = DeviceIdFrame[0:2]
                    DeviceIDFrame = DeviceIdFrame[2:4]
                    VenderIDStr = "0x"+"".join(["{:#04x}".format(a).replace("0x",'') for a in VenderIDFrame])
                    DeviceIDStr = "0x"+"".join(["{:#04x}".format(a).replace("0x",'') for a in DeviceIDFrame])
                    deviceinfo[PnPacket.keylist[DcpInfoKey.VenderID]] = VenderIDStr
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceID]] = DeviceIDStr
                    # print(VenderIDStr)
                    # print(DeviceIDStr)
                elif SubOption == DcpSubOption.SubOptionDeviceRole:  #设备角色
                    pass
                else:
                    pass
            elif Option == DcpOptions.OptionIP:#如果是ip
                if SubOption == DcpSubOption.SubOptionIp:
                    IPInfoFrame = data[tmpLen + 2:tmpLen + DcpBlockLenth]
                    IpFrame = IPInfoFrame[0:4]
                    MaskFrame = IPInfoFrame[4:8]
                    GatewayFrame = IPInfoFrame[8:12]
                    IPstr= ".".join([str(a) for a in IpFrame])
                    Maskstr = ".".join([str(a) for a in MaskFrame])
                    GateWaystr = ".".join([str(a) for a in GatewayFrame])
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceIP]] = IPstr
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceNetMask]] = Maskstr
                    deviceinfo[PnPacket.keylist[DcpInfoKey.DeviceGateWay]] = GateWaystr
                elif SubOption == DcpSubOption.SubOptionMac:
                    pass
                else:
                    pass
            tmpLen += DcpBlockLenth
            if int.from_bytes(data[tmpLen:tmpLen+1],byteorder='big',signed=False) ==0:
                tmpLen+=1
        # print("------------------------------------------------------------------------")
        #
        PnPacket.pnDeviceList.append(deviceinfo)
        # for pndevice in PnPacket.pnDeviceList:
        #     print(pndevice)
        # print("------------------------------------------------------------------------")

    @staticmethod
    def parseResponse(data):  # 解析设置结果
        OptionFrame=data[10:]
        print(OptionFrame)
        MainOption = int.from_bytes(OptionFrame[0:1],byteorder='big',signed=False)
        MainSubOption = int.from_bytes(OptionFrame[1:2],byteorder='big',signed=False)
        DcpBlockLength = int.from_bytes(OptionFrame[2:4],byteorder='big',signed=False)
        Option = int.from_bytes(OptionFrame[4:5],byteorder='big',signed=False)
        SubOption = int.from_bytes(OptionFrame[5:6],byteorder='big',signed=False)
        BlockRespons = int.from_bytes(OptionFrame[6:7],byteorder='big',signed=False)
        print(Option)
        print(SubOption)
        if Option == DcpOptions.OptionIP:
            if SubOption == DcpSubOption.SubOptionIp:
                if BlockRespons == 0:
                    print("设置ip成功")
                else:
                    print("设置ip失败")
        elif Option == DcpOptions.OptionDeviceProperties:
            if SubOption == DcpSubOption.SubOptionStationName:
                if BlockRespons == 0:
                    print("设置设备名成功")
                else:
                    print("设置设备名失败")





    @staticmethod
    def SetDeviceNamebyIndex(Index,namestr):
        setDviceName_request_hex_template = "%(dst_mac)s%(src_mac)s8892fefd0400" \
                                    "%(xiq_seq)s0000%(DcpDataLength)s0202%(namelength)s0001%(name)s%(padding)s050200020001"
        PnPacket.GetCardMac()
        dstmacstr = PnPacket.pnDeviceList[Index]["DeviceMac"].replace(':','')
        padding = ""
        macbuf = PnPacket.Mac.replace(':', '')
        stationnamestr = namestr.replace(' ','')
        if (len(stationnamestr) == 5):
            padding = "00"
            DcpDataLengthstr = format(len(stationnamestr) + 13, '#06x').replace('0x', '')
        else:
            DcpDataLengthstr = format(len(stationnamestr) + 12, '#06x').replace('0x', '')
        namelengthstr = format(len(namestr)+2,'#06x').replace('0x','')
        seqstr = format(PnPacket.seq, '#010x').replace('0x', '')
        print(dstmacstr)
        print(DcpDataLengthstr)
        print(namelengthstr)
        print(seqstr)
        namehexstr = "".join([hex(ord(a))[2:] for a in namestr])
        packet = setDviceName_request_hex_template % {
            "dst_mac":dstmacstr,
            "src_mac": macbuf,
            "xiq_seq": seqstr,
            "DcpDataLength":DcpDataLengthstr,
            "namelength":namelengthstr,
            "name":namehexstr,
            "padding":padding
        }

        print(packet)
        setnamepacket =bytes.fromhex(packet)
        print("send Pakcet on %s" % PnPacket.devideName)
        print("send Pakcet on %s" % PnPacket.devideDes)
        PnPacket.SendPacket(setnamepacket)

    @staticmethod
    def SetDeviceNamebyMac(DstMac, namestr):
        setDviceName_request_hex_template = "%(dst_mac)s%(src_mac)s8892fefd0400" \
                                            "%(xiq_seq)s0000%(DcpDataLength)s0202%(namelength)s0001%(name)s%(padding)s050200020001"
        PnPacket.GetCardMac()
        padding =""
        dstmacstr = DstMac.replace(':', '')
        macbuf = PnPacket.Mac.replace(':', '')
        stationnamestr = namestr.replace(' ','')
        print(stationnamestr)
        print(len(stationnamestr))
        if (len(stationnamestr) == 5):
            padding="00"
            DcpDataLengthstr = format(len(stationnamestr) + 13, '#06x').replace('0x', '')
        else:
            DcpDataLengthstr = format(len(stationnamestr) + 12, '#06x').replace('0x', '')
        namelengthstr = format(len(namestr) + 2, '#06x').replace('0x', '')
        seqstr = format(PnPacket.seq, '#010x').replace('0x', '')
        print(dstmacstr)
        print(DcpDataLengthstr)
        print(namelengthstr)
        print(seqstr)
        namehexstr = "".join([hex(ord(a))[2:] for a in namestr])
        packet = setDviceName_request_hex_template % {
            "dst_mac": dstmacstr,
            "src_mac": macbuf,
            "xiq_seq": seqstr,
            "DcpDataLength": DcpDataLengthstr,
            "namelength": namelengthstr,
            "name": namehexstr,
            "padding":padding
        }
        print(packet)
        setnamepacket = bytes.fromhex(packet)
        print("send Pakcet on %s" % PnPacket.devideName)
        print("send Pakcet on %s" % PnPacket.devideDes)
        WinPcapUtils.send_packet(PnPacket.devideDes, setnamepacket)
        PnPacket.lastSeq = PnPacket.seq
        PnPacket.seq = PnPacket.seq + 1
    @staticmethod
    def SetDeviceIPbyIndex(Index,ipstr):
        if Index>len(PnPacket.pnDeviceList):
            print("超出范围")
            return
        setDviceIp_request_hex_template = "%(dst_mac)s%(src_mac)s8892fefd0400" \
                                    "%(xiq_seq)s0000%(DcpDataLength)s0102%(IPInfolength)s0001%(ip)s%(netmask)s%(gateway)s"
        # ac6417f5183f
        # a85e455a5c6e
        # 8892
        # fefd
        # 0400
        # 00000002
        # 000000120102000e0001c0a804ffffff0c0a801
        PnPacket.GetCardMac()
        #keylist = ["DeviceNum", "DeviceName", "DeviceType", "DeviceIP", "DeviceNetMask", "DeviceGateWay", "DeviceMac",
         #          "DeviceRole", "VenderID", "DeviceID"]
        dstmacstr = PnPacket.pnDeviceList[Index]["DeviceMac"].replace(':','')#修改的设备的mac
        macbuf = PnPacket.Mac.replace(':', '')
        DcpDataLength= 18
        IPInfolength=14
        DcpDataLengthstr= format(DcpDataLength,'#06x').replace('0x','')
        print("DcpDataLengthstr:"+DcpDataLengthstr)
        IPInfolengthstr= format(IPInfolength,'#06x').replace('0x','')
        print("IPInfolengthstr:"+IPInfolengthstr)
        seqstr = format(PnPacket.seq, '#010x').replace('0x', '')
        print("seqstr:"+seqstr)
        maskstr=PnPacket.pnDeviceList[Index]["DeviceNetMask"]
        gatewaystr = PnPacket.pnDeviceList[Index]["DeviceGateWay"]

        iphexstr =  "".join([format(int(a),"#04x")[2:] for a in str(ipstr).split('.')])
        maskhexstr = "".join([format(int(a),"#04x")[2:] for a in str(maskstr).split('.')])
        gatewayhexstr =  "".join([format(int(a),"#04x")[2:] for a in str(gatewaystr).split('.')])
        print("iphexstr:"+iphexstr)
        print("maskhexstr:" + maskhexstr)
        print("gatewayhexstr:" + gatewayhexstr)
        packet = setDviceIp_request_hex_template % {
            "dst_mac": dstmacstr,
            "src_mac": macbuf,
            "xiq_seq": seqstr,
            "DcpDataLength": DcpDataLengthstr,
            "IPInfolength": IPInfolengthstr,
            "ip":iphexstr,
            "netmask":maskhexstr,
            "gateway":gatewayhexstr
        }

        print(packet)
        setippacket =bytes.fromhex(packet)

        print("send Pakcet on %s" % PnPacket.devideName)
        print("send Pakcet on %s" % PnPacket.devideDes)
        PnPacket.SendPacket(setippacket)
    @staticmethod
    def SendPacket(packet):
        WinPcapUtils.send_packet(PnPacket.devideDes,packet)
        PnPacket.lastSeq = PnPacket.seq
        PnPacket.seq =PnPacket.seq+1
    @staticmethod
    def SetDeviceNetMask(NetMaskstr):
        pass
    @staticmethod
    def printalldevice():

        for deviceinfo in PnPacket.pnDeviceList:
            for value in deviceinfo.values():
                print(str(value)+"              ",end="")
            print("")

    @staticmethod
    def parDcpPakcetInfo(FrameID,data,srcMac):
        if FrameID ==DcpRequestType.Requestall:#请求贞帧获取所有的设备
            pass
        elif FrameID == DcpRequestType.ResponsAll:#应答帧 收到的pn设备的信息
            PnPacket.parseResponsAll(data,srcMac)
        elif FrameID == DcpRequestType.SetConfig:#设置名称 ip 等
                print("FrameID")
                print(FrameID)
                PnPacket.parseResponse(data)
        else:
            pass
            #print("FrameId")
            #print(FrameID)


    @staticmethod
    def parseDcpPacket(data):
        pos = 0
        dst_mac_frame = data[0:pos+7]
        pos+=6
        src_mac_frame = data[pos:pos+6]
        # print(src_mac_frame)
        srcMacstr = ":".join([hex(a).replace("0x","") for a in src_mac_frame])
        # print(srcMacstr)
        pos += 6
        type_Frame = data[pos:pos+2]
        pos+=2
        ID_Frame = data[pos:pos+2]
        pos += 2
        ServerID = data[pos:pos+1]
        pos+=1
        ServerType  = data[pos:pos+1]
        pos+=1
        Xiq = data[pos:pos+4]
        #print("self.lastSeq=%d" % PnPacket.lastSeq)
        # print("Xiq=%d" % int.from_bytes(Xiq,byteorder='big',signed=False))
        if PnPacket.lastSeq!=int.from_bytes(Xiq,byteorder='big',signed=False):
           # print("seq not equal")
            return
        # print("seq %d " % PnPacket.seq)
        # print("xid %d " % int.from_bytes(Xiq,byteorder='big',signed=False))
        pos+=6
        DcpDataLength = data[pos:pos+2]
        pos+=2
        dcpinfolength = int.from_bytes(DcpDataLength,byteorder='big',signed=False)
        if DcpRequestType.ResponsAll==int.from_bytes(ID_Frame, byteorder='big', signed=False):
            DcpOptionFrame = data[-dcpinfolength:]
            PnPacket.parDcpPakcetInfo(int.from_bytes(ID_Frame, byteorder='big', signed=False), DcpOptionFrame,
                                      srcMacstr)
        elif DcpRequestType.SetConfig==int.from_bytes(ID_Frame, byteorder='big', signed=False):
            PnPacket.parDcpPakcetInfo(int.from_bytes(ID_Frame, byteorder='big', signed=False), data[16:],
                                      srcMacstr)

    @staticmethod
    def recvpakcet():
        #print("recive Pakcet on Card:" + PnPacket.devideName)
        WinPcapUtils.capture_on(PnPacket.devideDes, PnPacket.packet_callback)