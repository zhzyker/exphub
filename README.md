# exphub
漏洞的直接利用工具合集，包括操作系统、Web中间件、CMS等  
最后更新：2020/04/02  

文件格式：cve-1111-1111_**XXXX**.**py** 
#### 文件种类[XXXX]:  
- poc 仅检测漏洞是否存在
- command 直接远程命令执行，无法交互
- shell 直接获取目标Shell,可以交互
- webshell 自动或手动上传Webshell
#### 文件格式[py]: 
- py Python文件，执行环境和版本肯有所差异，具体是py2还是py3每个文件有些说明(执行即可见)，推进py2.7和py3.7
- jar Java文件，执行方式均为`java -jar cve-1111-1111_XXXX.jar`,推荐java1.8.121
- php Php文件，直接使用`php`命令既可执行``


### weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py) weblogic_ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py) weblogic_ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py) Weblogic_wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar) Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
