#!/usr/bin/python 
# -*- coding: utf-8 -*- 
from idaapi import *
from idautils import *
from idc import *


def get_string(addr):
    if Dword(addr) >MinEA() and Dword(addr) < MaxEA():
        return get_string(Dword(addr))
    else:
        result = ""
        while True:
            if idc.Byte(addr) != 0:
                result += chr(Byte(addr))
            else:
                break
            addr += 1
        return result
def getTargetAddressData(addr):   #addr 代表目标函数的地址
    for x in XrefsTo(addr,flags=0):
        currentaddr = x.frm
        #print hex(currentaddr)
        code_time = 0 
        while  code_time!=5:    #上5条指令
            currentaddr = PrevHead(currentaddr) #获取当前地址的前一个地址
            if GetMnem(currentaddr) == 'LDR':
                disasm_code = idc.GetDisasm(currentaddr)
                if "R2" in disasm_code: #参数三保存函数名
                    #print hex(currentaddr),disasm_code
                    data_addr = GetOperandValue(currentaddr,1)  #获取地址中的第几个值 例如mov eax，exe.0x4000  1所代表的是exe.0x4000这个值 也就是说data  = 0x4000  这个地址
                    if data_addr > MinEA() and data_addr < MaxEA():
                        name = get_string(data_addr)
                        rename_func_by_addr(currentaddr,name)
                    break
            code_time = code_time+1
#用name重名func_addr所在的函数
def rename_func_by_addr(func_addr,name):
    try: 
        func_startEA = get_func(func_addr).startEA
    except: #可能获取不到函数
        #print hex(func_addr)
        return 
    #print name
    MakeName(func_startEA,name)
loginfo = LocByName("loginfo") #函数名
getTargetAddressData(loginfo)