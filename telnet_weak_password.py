# /usr/bin/python
# coding:utf-8

"""
@Filename: TWPW.py
@Modified Time: 2016/11/7  10:08
@Modified By：Erick
"""

from connect_telnet import GetVaildTelentIP

# Telnet weak Password
def telnet_weakpwd(service, ip, port):
    vul_code = 0
    vul_detail = ''
    return_message = [vul_code, vul_detail]
    gvtp = GetVaildTelentIP()
    
    mydict = (
        "shouji:phone", "admin:admin", "zte:zte", "admin:12345", "admin:password", 
        "root:admin", "admin:123456", "root:zte",  "root:root",  "admin:root", 
        "root:123456", "root:xc3511", "admin:7ujMko0admin", "admin:xc3511", "root:vizxv", 
        "root:password", "zte:password", "root:huaweiosta", "winda:huawei", "ubnt:ubnt", 
        "root:Zte521", "root:7ujMko0vizxv", "root:7ujMko0admin", "root:system", "admin:pass", "user:user")

    for item in mydict:
        username = item.split(':')[0]
        password = item.split(':')[1]
        print " Trying User:", username, "  Password:", password, "     on ", ip

        try:
            result = gvtp.thread_Task(str(ip), username, password)
            if result != -1:
                print ip + ": is vulnerable!"
                vul_code = 1
                vul_detail = item
                return_message = [vul_code, vul_detail]
                break
            else:  # result ==0
                continue
        except Exception, e:
            print ' plug-in module does not work or not vulnerable.'
            print e
            pass
    print return_message
    return return_message
