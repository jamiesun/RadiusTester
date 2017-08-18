RadiusTester
============

RadiusTester是一个radius测试客户端，支持命令行和GUI两种方式。

## runtime environment  - 运行环境

[python2.7+](http://python.org/)

[pyrad2.0](https://github.com/wichert/pyrad)

[gevent1.0](https://github.com/SiteSupport/gevent)

[PyQt4](http://www.riverbankcomputing.co.uk)

## Using GUI  -  使用GUI版本

> qtester.py

> Generate an executable file python C:\\pyinstaller-2.0\\pyinstaller.py qtester.spec

## Using command  -  使用命令行版本

    tester.py [-h] [--auth [AUTH]] [--acct {start,stop,update,on,off}]
                     [-u USERNAME] [-p PASSWORD] [-e {pap,chap}] [-n REQUESTS]
                     [-d [DEBUG]] [-o TIMEOUT]

    optional arguments:
      -h, --help            show this help message and exit
      --auth [AUTH]         radius auth test
      --acct {start,stop,update,on,off}
                            radius acct test
      -u USERNAME, --username USERNAME
                            radius auth username
      -p PASSWORD, --password PASSWORD
                            radius auth password
      -e {pap,chap}, --encrypt {pap,chap}
                            radius auth password encrypt type
      -n REQUESTS, --requests REQUESTS
                            request number
      -d [DEBUG], --debug [DEBUG]
                            is debug
      -o TIMEOUT, --timeout TIMEOUT
                            socket timeout


### authenticator test：

> tester.py --auth -u testname -p 123456 -n 10000 -d -e chap


### acctounting test :

> tester.py --acct start -d



## packet attrs config  消息属性配置

Modify the configuration file tester.cfg

    [server]
    host = 192.168.8.122
    authport = 1812
    acctport = 1813
    authsecret = secret
    acctsecret = secret

    [auth_attrs]
    NAS-IP-Address = 192.168.8.122
    Calling-Station-Id = 00-01-24-80-B3-9C



    [acct_attrs]
    NAS-IP-Address = 192.168.8.122
    NAS-Port = 0
    NAS-Identifier = trillian
    Called-Station-Id = 00-04-5F-00-0F-D1
    Calling-Station-Id = 00-01-24-80-B3-9C
    Framed-IP-Address = 192.168.8.122


    [acct_attrs_start]


    [acct_attrs_stop]
    Acct-Input-Octets = 772138064
    Acct-Output-Octets = 786765986
    Acct-Session-Time = 3600
    Acct-Terminate-Cause = 1

    [acct_attrs_update]
    Acct-Input-Octets = 772138064
    Acct-Output-Octets = 786765986
    Acct-Session-Time = 3600
    Acct-Terminate-Cause = 1

    [acct_attrs_on]

    [acct_attrs_off]















