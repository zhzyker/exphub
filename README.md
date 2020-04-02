# Exphub
Exphub[漏洞利用脚本库]  
目前包括Webloigc、Struts2、Tomcat的漏洞利用脚本，均为亲测可用的脚本文件，尽力补全所有脚本文件的使用说明文档，优先更新高危且易利用的漏洞利用脚本  
部分脚本或程序是从网上搜集的，若有版权要求联系即改  

最后更新：2020/04/02  

# Readme
Exphub包括多种不同名称、类型、格式、后缀的文件，这些文件可以大致分为[漏洞验证脚本]、[远程命令执行脚本]、[远程命令执行脚本]、[Webshell上传脚本]  
脚本文件示例：cve-1111-1111_xxxx.py  

脚本文件种类[xxxx]:  
- cve-1111-1111_**poc** [漏洞验证脚本] 仅检测验证漏洞是否存在
- cve-1111-1111_**command** [远程命令执行脚本] 通过脚本文件向目标系统发送命令并执行，无法交互
- cve-1111-1111_**shell** [远程命令执行脚本] 直接反弹Shell，或者提供简单的交互Shell以传递命令,基础交互
- cve-1111-1111_**webshell** [Webshell上传脚本] 自动或手动上传Webshell  

脚本文件格式[py]:  
- cve-xxxx.**py** Python文件，包括py2和py3，具体哪个文件是哪个版本参照说明(执行即可见)，推荐py2.7和py3.7
- cve-xxxx.**sh** Shell脚本，需要Linux环境运行，执行即见说明，无发行版要求
- cve-xxxx.**jar** Java文件，执行方式均为`java -jar cve-xxxx.jar`,推荐Java1.8.121
- cve-xxxx.**php** PHP文件，直接使用`php`命令执行即可
- cve-xxxx.**txt** 无法编写成可执行文件的漏洞Payload，将直接写成txt文本，文本内记录如何使用(一般为GET/POST请求

## Weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py) weblogic_ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py) weblogic_ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py) Weblogic_wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar) Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  

## Struts2
[**struts2-052_command.py**](https://github.com/zhzyker/exphub/blob/master/struts2/struts2-052_command.py) Struts2 REST插件远程代码执行漏洞
