## exphub
漏洞的直接利用工具合集，包括操作系统、Web中间件、CMS等  
最后更新：2020/04/02  

### 文件内容说明
文件格式：cve-1111-1111_xxxx.py
**文件种类[xxxx]:**  
- cve-1111-1111_**poc** 仅检测漏洞是否存在
- cve-1111-1111_**command** 直接远程命令执行，无法交互
- cve-1111-1111_**shell** 直接获取目标Shell,可以交互
- cve-1111-1111_**webshell** 自动或手动上传Webshell

**文件格式[py]:**  
- cve-xxxx.**py** Python文件，文件有py2和py3的，具体那个文件那个版本参照说明(执行即可见)，推进py2.7和py3.7
- cve-xxxx.**sh** Shell脚本，需要Linux环境运行，执行即见说明，无发行版要求
- cve-xxxx.**jar** Java文件，执行方式均为`java -jar cve-1111-1111_XXXX.jar`,推荐java1.8.121
- cve-xxxx.**php** PHP文件，直接使用`php`命令执行即可
- cve-xxxx.**txt** 一些无法编写成脚本的漏洞payload，将直接写成txt文本，文本内记录如何使用(一般为GET/POST请求

## weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_scan.py) weblogic_ssrf扫描内网端口利用脚本 [[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2014-4210_ssrf_redis_shell.py) weblogic_ssrf漏洞内网redis未授权getshell脚本[[使用]](https://freeerror.org/d/483-ssrf)  
[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_poc.py) Weblogic_wls-wsat远程命令执行漏洞检测脚本[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/cve-2017-3506_webshell.jar) Weblogic wls-wsat远程命令执行漏洞利用，上传Webshell[[使用]](https://freeerror.org/d/468-cve-2017-3506-weblogic-wls-wsat)  
