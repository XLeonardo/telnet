# /usr/bin/python
# coding:utf-8

"""
@Filename: telnet_weakpasswd_v2.py
@Modified Time: 2018/05/24  16:08
@Modified By: Erick
"""

import telnetlib
import multiprocessing
import threading
import re
import time
import random

valid_information = []


def thread_task(ip, port, username, password):
    time.sleep(random.uniform(1, 2))

    print(" Trying User:", username, "  Password:", password, "  on ", ip)

    try:
        t = telnetlib.Telnet(ip, port, timeout=3)
    except:
        print('This is invalid IP: %s %s' % (ip, port))
        return -2
    else:
        if username:
            try:
                t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=3)
            except:
                t.close()
            try:
                t.write(username.encode('ascii') + "\r\n".encode('ascii'))
            except:
                t.close()
        else:
            time.sleep(1)
            result = t.read_until("Password:", timeout=2)
            screen_echo = str(result).lower()
            if 'press return to activate console' in screen_echo:
                # print('Need to enter something:')
                try:
                    t.write("\r\n".encode('ascii'))
                except:
                    t.close()

        try:
            t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=3)
        except:
            t.close()
        try:
            t.write(password.encode('ascii') + "\r\n".encode('ascii'))
        except:
            t.close()

        # 正则匹配
        try:
            n, match, previous_text = t.expect(
                [r'.+?\$\s*$', r'.+?#\s*$', r'#\s*$', r'.+?[^:]>\s*$', r'.+?[^:]>[%s-%s]*$' % (chr(0), chr(32)),
                 r'.+?-\s*$'], 3)
        except:
            return -1
        else:
            return n


def password_less_login(ip, port=23, username='shouji', password='phone'):
    """
    尝试 免密登陆 或者 无用户名登陆，并返回结果
    :param ip:
    :param port:
    :param username:
    :param password:
    :return:
    """
    global valid_information
    only_password_flag = False
    detail = None

    try:
        t = telnetlib.Telnet(ip, port, timeout=3)
        time.sleep(1)
        result = t.read_until("Password:", timeout=2)
        screen_echo = str(result).lower()
        # print screen_echo

        if 'press return to activate console' in screen_echo:
            # 'Press RETURN to activate console . . .' some device need to input enter
            # print('Need to enter something:')
            try:
                t.write("\r\n".encode('ascii'))
            except:
                t.close()
            result = t.read_until("Password:", timeout=2)
            screen_echo = str(result).lower()
            # print screen_echo

    except Exception as e:
        print('[-]This is invalid IP: %s %s\n' % (ip, port), e)
        return -2, detail, only_password_flag
    else:
        screen_echo_list = screen_echo.strip("\r\n").split('\r\n')

        # print(screen_echo_list)

        if len(screen_echo) >= 3:
            end_of_screen_echo = " ".join(screen_echo_list[-3:])
        else:
            end_of_screen_echo = " ".join(screen_echo_list[-2:])

        # print(end_of_screen_echo)

        if 'password' in end_of_screen_echo:
            only_password_flag = True
        else:
            try:
                t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=3)
            except:
                t.close()

            try:
                t.write(username.encode('ascii') + "\r\n".encode('ascii'))
            except:
                t.close()

        try:
            t.read_until(':' or ':>' or ': ' or ':[%s-%s]*' % (chr(0), chr(32)), timeout=3)
        except:
            t.close()

        try:
            t.write(password.encode('ascii') + "\r\n".encode('ascii'))
        except:
            t.close()

        # 正则匹配
        try:
            n, match, previous_text = t.expect(
                [r'.+?\$\s*$', r'.+?#\s*$', r'#\s*$', r'.+?[^:]>\s*$', r'.+?[^:]>[%s-%s]*$' % (chr(0), chr(32)),
                 r'.+?-\s*$'], 3)
        except:
            return -1, detail, only_password_flag
        else:
            if n != -1:
                print("[+]Found an No Authentication IP: " + ip)
                detail = ":"
                valid_information.append(detail)
            return n, detail, only_password_flag


def telnet_wpw_task_list(service, ip, port, protocol_num, no_password_flag=False):
    task_list = []

    admin_passwd_dict = (
        "admin:admin", "zte:zte", "admin:12345", "admin:password",
        "root:admin", "admin:123456", "root:zte", "root:root", "admin:root",
        "root:123456", "root:xc3511", "admin:7ujMko0admin", "admin:xc3511", "root:vizxv",
        "root:password", "zte:password", "root:huaweiosta", "winda:huawei", "ubnt:ubnt",
        "root:Zte521", "root:7ujMko0vizxv", "root:7ujMko0admin", "root:system", "admin:pass",
        "user:user"
    )

    only_pass_dict = (
        "admin", "root", "123456"
    )

    if no_password_flag:
        for item in only_pass_dict:
            username = None
            password = item
            tul = (ip, port, username, password)
            task_list.append(tul)
    else:
        for item in admin_passwd_dict:
            username = item.split(':')[0]
            password = item.split(':')[1]
            tul = (ip, port, username, password)
            task_list.append(tul)

    return task_list


def multi_thread(lis):
    global valid_information
    threads = []

    # 多线程获取指纹
    for i in range(len(lis)):
        t = threading.Thread(target=telnet_process, args=(lis[i],))
        threads.append(t)

    for i in range(len(lis)):
        threads[i].start()
    for i in range(len(lis)):
        threads[i].join(timeout=15)


def telnet_process(temp_info):
    global valid_information

    ip = temp_info[0]
    port = temp_info[1]
    username = temp_info[2]
    password = temp_info[3]

    try:
        result = thread_task(str(ip), port, username, password)
    except Exception as e:
        print(' plug-in module does not work or not vulnerable.', e)
    else:
        if result == -2:
            # cannot use telnet to the target
            return
        elif result != -1:
            print("[+] " + str(ip) + ": is vulnerable!")
            if username:
                vul_detail = username + ":" + password
            else:
                vul_detail = ":" + password
            # print vul_detail
            valid_information.append(vul_detail)
            # print valid_information
            return vul_detail


def telnet_wpw_poc_multi(service, ip, port=23, protocol_num=1):
    """
    通过利用 多线程 同时检测目标。全字典检测，如果命中多个结果，会将结果汇总返回
    优缺点：漏检率较高，速度较快
    :param service:
    :param ip:
    :param port:
    :param protocol_num:
    :return:
    """
    vul_code = 0
    vul_detail = ''
    return_message = [vul_code, vul_detail]

    global valid_information

    result = password_less_login(ip, port)
    print(result)
    number = result[0]
    detail = result[1]

    if number == -2:
        print("Cannot telnet with this IP.")
        return return_message

    elif detail != ':':
        flag = result[2]
        lis = telnet_wpw_task_list(service, ip, port, protocol_num, flag)
        # multi_thread process
        multi_thread(lis)

    if valid_information is not None:
        print(valid_information)
        vul_code = 1
        vul_detail = valid_information
        return_message = [vul_code, vul_detail]

    return return_message


def telnet_wpw_poc_simple(service, ip, port=23, protocol_num=1):
    """
    通过利用普通 for 循环检测，如发现命中结果，直接返回，不再进行后续字典探测
    优缺点： 漏检率较低，速度较慢
    :param service:
    :param ip:
    :param port:
    :param protocol_num:
    :return:
    """
    vul_code = 0
    vul_detail = ''
    return_message = [vul_code, vul_detail]

    global valid_information

    result = password_less_login(ip, port)
    # print result
    number = result[0]
    detail = result[1]

    if detail == ':':
        vul_code = 1
        vul_detail = detail
        return_message = [vul_code, vul_detail]
    else:
        if number == -2:
            print("Cannot telnet with this IP.")
            return return_message

        else:
            flag = result[2]
            lis = telnet_wpw_task_list(service, ip, port, protocol_num, flag)
            for handler in lis:
                detail = telnet_process(handler)
                if detail is not None:
                    vul_code = 1
                    vul_detail = detail
                    return_message = [vul_code, vul_detail]
                    break
    return return_message


if __name__ == '__main__':
    print telnet_wpw_poc_simple('telnet', '192.168.1.1', 23, 1)




