# exphub
漏洞的直接利用工具合集，包括操作系统、Web中间件、CMS等  
最后更新：2020/04/02  

文件格式：**cve-1111-1111_xxxx.py**  
xxxx字段包括以下内容  
- poc 仅检测漏洞是否存在
- command 直接远程命令执行，无法交互
- shell 直接获取目标shell,可以交互
- webshell 自动或手动上传webshell
- 

### weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py)  weblogic_ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py)  weblogic_ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py)  Weblogic_wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar)  Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
