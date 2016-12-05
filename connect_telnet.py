# /usr/bin/python
# coding:utf-8

"""
@Filename: connect_telnet.py
@Modified Time: 2016/11/7  10:08
@Modified By：Erick
"""


import telnetlib
import re
import pdb


class GetVaildTelentIP(object):


    def __init__(self):
        self.mydict = (
        "root:123456", "root:root",  "root:xc3511", "root:vizxv", "root:admin", "admin:admin", "admin:password", "zte:zte", "root:password", "root:huaweiosta", "winda:huawei", "ubnt:ubnt", "root:Zte521", "root:7ujMko0vizxv", "root:7ujMko0admin", "root:system", "admin:7ujMko0admin", "admin:pass", "user:user")


    def thread_Task(self, ip, username=None, password=None):
        # pdb.set_trace()
        try:
            t = telnetlib.Telnet(ip, timeout=3)
        except:
            print 'This is invalid IP: %s' % ip
            raise

        try:
            t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=2)
        except:
            t.close()

        try:
            t.write(username.encode('ascii') + "\r\n".encode('ascii'))
        except:
            t.close()
        #pdb.set_trace()
        #print t.read_very_eager()
        try:
            t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=2)
            #t.read_until(':')
        except:
            t.close()

        try:
            t.write(password.encode('ascii') + "\r\n".encode('ascii'))
        except:
            t.close()
        # 正则匹配
        try:
            n, match, previous_text = t.expect([r'.+?\$\s*$', r'.+?#\s*$', r'.+?[^:]>\s*$', r'.+?[^:]>[%s-%s]*$' % (chr(0), chr(32)), r'.+?-\s*$'], 3)
            #print previous_text
            #res = re.findall(r'.+?#$', previous_text)
            #print res
        except:
            return -1
        else:
            print n
            return n


if __name__ == '__main__':

    gvtp = GetVaildTelentIP()
    #pdb.set_trace()
    gvtp.thread_Task('192.168.1.1','root','root')
