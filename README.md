# Exphub
Exphub[漏洞利用脚本工具库]  
目前包括Webloigc、Struts2、Tomcat的漏洞利用脚本，均为亲测可用的脚本文件，尽力补全所有脚本文件的使用说明文档  
部分脚本或程序是从网上搜集的，若有版权要求联系即改  

最后更新：2020/04/02  

## Readme
文件格式：cve-1111-1111_xxxx.py  
**文件种类[xxxx]:**  
- cve-1111-1111_**poc** 仅检测漏洞是否存在
- cve-1111-1111_**command** 直接远程命令执行，无法交互
- cve-1111-1111_**shell** 直接获取目标Shell,可以交互
- cve-1111-1111_**webshell** 自动或手动上传Webshell

**文件格式[py]:**  
- cve-xxxx.**py** Python文件，包括py2和py3，具体哪个文件是哪个版本参照说明(执行即可见)，推荐py2.7和py3.7
- cve-xxxx.**sh** Shell脚本，需要Linux环境运行，执行即见说明，无发行版要求
- cve-xxxx.**jar** Java文件，执行方式均为`java -jar cve-1111-1111_XXXX.jar`,推荐Java1.8.121
- cve-xxxx.**php** PHP文件，直接使用`php`命令执行即可
- cve-xxxx.**txt** 一些无法编写成脚本的漏洞Payload，将直接写成txt文本，文本内记录如何使用(一般为GET/POST请求

## Weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py) weblogic_ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py) weblogic_ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py) Weblogic_wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar) Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
