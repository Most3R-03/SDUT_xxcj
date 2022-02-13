# coding = utf-8
import requests
import json
import uuid
import base64
from Crypto.Cipher import AES
import base64
from Crypto import Random
from Crypto.Hash import SHA
from urllib import request
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import smtplib
from email.mime.text import MIMEText
# email 用于构建邮件内容
from email.header import Header
import time
#rsa加密，通常对加密结果进行base64编码
import sys
import os
import sys
import io
import datetime
import demjson

debug=1
url_1 = "http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/api/lapp/springboard?yyid=xxsj_front"
url_reporlist="http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/api/collectMessage/reportList"
url_reportdatails="http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/api/collectMessage/reportDetails"
url_submitmessage="http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/api/collectMessage/submitMessage"
url_recall="http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/api/collectMessage/recall"
#unique_code="*********d-93ad-2ada162f89c5" #打开设备生成的唯一码
#access_token="*********5F+h9rrpEDz3rdf95Y6lFHP+54xO+jyam4ewEY0HrmxNJZKG5*********zE32GBt1EwlOiBFtTnP/qd3LQB1qJkhG1x40RzsAAP1Ozh5mA8kLAPP2a4tq*********ajNTvT2ZJ4A=="  #会话session
X_Requested_With="com.lysoft.android.lyyd.report.mobile.sdlg"      #客户端标识
url_location="http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html#/writeTask?************************************"
u_a="Mozilla/5.0 (Linux; Android 5.1.1; SM-G977N Build/LMY48Z; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36"  #客户端
from_addr = '****' #qq邮箱地址 登录账号
password = '********'  # qq邮箱授权码
to_addr = '****@qq.com'  # 发送方地址 要发送提示的账号
# 发信服务器
smtp_server = 'smtp.qq.com'
global userInfoAeskey    #文件中的aeskey
global aes_key           #本地生成并发送到服务端AESkey
global private_key       #服务端发送于本地的私钥
global public_key        #申请得到的RSA公钥
# 标准头
headers = \
    {
        "Connection": "keep-alive",
        "Host": "mcp.sdut.edu.cn:8080",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": u_a,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "unique-code": "unique_code",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "X-Requested-With": "com.lysoft.android.lyyd.report.mobile.sdlg",
        "access-token": "access_token",
    }

#用于请求公钥的头
headers_public = \
    {
         "Asym-Key": "public",
         "User-Agent": u_a,
         "Accept-Encoding": "gzip, deflate",
         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ja;q=0.5",
         "Referer": "http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html",
         "Accept": "*/*"
    }
#用于请求私钥的头
headers_private = \
    {
        "Asym-Key": "private",
        "User-Agent": u_a,
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ja;q=0.5",
        "Referer": "http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html",
        "Accept": "*/*",
        "Origin": "http://mcp.sdut.edu.cn:8080",
        "Content-Type": "text/plain;charset=UTF-8"
    }

def create_detail_day():
    daytime = datetime.datetime.now().strftime('day' + '%Y_%m_%d')
    detail_time = daytime
    return detail_time
#用于把输出存放于日志
def make_print_to_file(path='./'):
    class Logger(object):
        def __init__(self, filename="Default.log", path="./"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
            self.terminal = sys.stdout
            self.log = open(os.path.join(path, filename), "a", encoding='utf8')

        def write(self, message):
            self.terminal.write(message)
            self.log.write(message)

        def flush(self):
            pass

    sys.stdout = Logger(create_detail_day() + '.log', path=path)
    print(create_detail_day().center(60, '*'))

#生成UUID-base64编码-取2-18位
def get_AesKey():
    uuid1 = str(uuid.uuid1())  #生成uuid
    #uuid = "7a0ad040-81dc-****-98a3-478940c****"
    if debug==1:print("---uuid:"+uuid1)
    uuid_utf8 = uuid1.encode('utf-8')   #转换成utf8编码
    base64_uuid = base64.b64encode(uuid_utf8)   #base64编码
    if debug==1:print("---uuid_base64:"+str(base64_uuid))
    str_2_18 = str(base64_uuid[2:18])[2:-1]   #取2-18位
    return str_2_18

#以下是AES加解密函数。
class EncryptDate:
    def __init__(self, key):
        self.key = key  # 初始化密钥
        self.length = AES.block_size  # 初始化数据块大小
        self.aes = AES.new(self.key, AES.MODE_ECB)  # 初始化AES,ECB模式的实例
        # 截断函数，去除填充的字符
        self.unpad = lambda date: date[0:-ord(date[-1])]

    def pad(self, text):
        """
        #填充函数，使被加密数据的字节码长度是block_size的整数倍
        """
        count = len(text.encode('utf-8'))
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return entext

    def encrypt(self, encrData):  # 加密函数
        res = self.aes.encrypt(self.pad(encrData).encode("utf8"))
        msg = str(base64.b64encode(res), encoding="utf8")
        return msg

    def decrypt(self, decrData):  # 解密函数
        res = base64.decodebytes(decrData.encode("utf8"))
        msg = self.aes.decrypt(res).decode("utf8")
        return self.unpad(msg)
#将公钥字符串处理为pem证书
def handle_pub_key(key):  #将公钥处理成pem证书格式
    """
    处理公钥
    公钥格式pem，处理成以-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾的格式
    :param key:pem格式的公钥，无-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾
    :return:
    """
    start = '-----BEGIN PUBLIC KEY-----\n'
    end = '-----END PUBLIC KEY-----'
    result = ''
    # 分割key，每64位长度换一行
    divide = int(len(key) / 64)
    divide = divide if (divide > 0) else divide + 1
    line = divide if (len(key) % 64 == 0) else divide + 1
    for i in range(line):
        result += key[i * 64:(i + 1) * 64] + '\n'
    result = start + result + end
    return result
#处理RSA加密
def get_param(message, public_key):   #
    """
    处理长消息 不经过 这个处理回报下面error
    OverflowError: 458 bytes needed for message, but there is only space for 117
    :param message 消息
    :param public_key 公钥
    :return:
    """
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(public_key)
    crypto = b''
    divide = int(len(message) / 117)
    divide = divide if (divide > 0) else divide + 1
    line = divide if (len(message) % 117 == 0) else divide + 1
    for i in range(line):
        crypto += rsa.encrypt(message[i * 117:(i + 1) * 117].encode(), pubkey)

    crypto1 = base64.b64encode(crypto)
    return crypto1.decode()
#RSA加密函数
def rsa_encrypt(message,pubilc_key):     #RSA加密
    """校验RSA加密 使用公钥进行加密"""
    # 导入公钥，返回一个RSA秘钥对象
    public_key = RSA.importKey(pubilc_key)

    # 创建用于执行PKCS#1 v1.5加密或解密的密码, publicKey: RSA秘钥对象，rand_func=None: 随机字节函数
    # 当rand_func为固定字节时，需要将PKCS1_v1_5.py 文件 87行的 self._randfunc(1) 改 self._randfunc
    cipher = Cipher_pkcs1_v1_5.new(public_key)

    # 对需要加密的消息进行PKCS#1 v1.5加密，再使用Base64对类似字节的对象进行编码。
    cipher_text = base64.b64encode(cipher.encrypt(message.encode())).decode()
    return cipher_text

#传入数据必须为utf8编码，即e
#unique-code获取方法，首先生成aeskey(get_aeskey())，然后把aeskey进行js中的encode编码为aeskey_encode，然后进行{sk:aeskey_encode}，
# 之后访问公钥网址获取公钥，将返回的data数据与sk:aeskey_encode一同进行进行publickeyencrypt()加密，然后进行私钥获取(body中为)
#示例数据：
# 返回的data：M********QUAA4GNADCBiQKBgQCAYYAF5a/+WuXTf3COIrH/Rtxy5qN3fr5hIlIAo3KpfudqooJuG4KpCjscpvmUvIelpbL88
# qPvqZn4yswnGPQ********hITYH2oELV4rZm9IJplbU7gqpkz/5o/Ysqe/qYaMUblxjt4f3X+FBFVBOCHRJ+m6YQIDAQAB
#经过publicketencrypt之后的；
#UOohTrzZO1s3Z+80y3wNhZhtr************lMFvi3MlzyAWoLC5gQcgQLjaHyX5vAact5No1dYJMriGLn2oI7TsPe7ve22wpOAC6Kmy99uQ42bZJNoDzVRPuA45SFvp0M5o/ZQRYrCTndbYl1IU2xoho=
#
'''    

            
            function encode(e) {
                var _keyStr="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                var t, n, a, s, o, i, c, u = "", l = 0;
                for (e = e; l < e.length; )
                    s = (t = e.charCodeAt(l++)) >> 2,
                    o = (3 & t) << 4 | (n = e.charCodeAt(l++)) >> 4,
                    i = (15 & n) << 2 | (a = e.charCodeAt(l++)) >> 6,
                    c = 63 & a,
                    isNaN(n) ? i = c = 64 : isNaN(a) && (c = 64),
                    u = u + _keyStr.charAt(s) + _keyStr.charAt(o) + _keyStr.charAt(i) + _keyStr.charAt(c);
                return u
            }
            


decode=execjs.compile(
            function decode(e) {
                var _keyStr="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                var t, n, a, s, o, i, c = "", u = 0;
                for (e = e.replace(/[^A-Za-z0-9+/=]/g, ""); u < e.length; )
                    t = _keyStr.indexOf(e.charAt(u++)) << 2 | (s = _keyStr.indexOf(e.charAt(u++))) >> 4,
                    n = (15 & s) << 4 | (o = _keyStr.indexOf(e.charAt(u++))) >> 2,
                    a = (3 & o) << 6 | (i = _keyStr.indexOf(e.charAt(u++))),
                    c += String.fromCharCode(t),
                    64 !== o && (c += String.fromCharCode(n)),
                    64 !== i && (c += String.fromCharCode(a));
                return c 
            }'''


#获取Unique-code：生成AES_key-base64编码-GET得到公钥-用公钥对AESkey加密-请求私钥(带有公钥加密的data)-将私钥利用生成的AESkey进行解密-作为unique-code
def get_Unique():  #通过本地生成uuid然后进行加密为aes，然后获得私钥，通过aes解密此私钥获得uuid
    global aes_key    #声明为全局函数，后期会一直用到这个aes
    aes_key=str(get_AesKey()).encode('utf-8') #生成aeskey
    key_encode=base64.b64encode(aes_key) #进行base64编码
    if (debug==1):print("---key_encode:"+str(key_encode))
    respone_2=requests.get("http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/open/security/asym/key",headers=headers_public) #GET得到公钥
    if debug==1:print("---respone_public_key:"+respone_2.text)
    gouzao = "{sk: '"+str(key_encode)[2:-1]+"'}"  #对key进行构造，变成如下massage的格式
    #message="{sk: '****E9ESTNZeQ=='}"
    json_repone=json.loads(respone_2.text)
    public_key = handle_pub_key(json_repone["data"])   #解析出data数据
    if debug==1:print("---public_key_pem:"+public_key)
    parm=rsa_encrypt(gouzao,public_key)   #利用get得到的公钥对构造的aes密钥进行加密
    if debug==1:print("---pubilc_key_encrypt:"+parm)
    respone_2 = requests.post(url="http://mcp.sdut.edu.cn:8080/mobileapi_ydxy/open/security/asym/key",headers=headers_private,data=parm) #进行私钥请求，头为pravite，data为公钥加密的aes密钥
    print("---respone_private_key:"+respone_2.text)
    json_repone2=json.loads(respone_2.text)
    private_key=json_repone2['data']    #对服务器回应的私钥进行解密
    eg1=EncryptDate(aes_key)  #aes解密
    post_uuid=eg1.decrypt(str(private_key))   #利用构造的aes密钥解密私钥，生成uuid
    if debug==1:print("---post_uuid:"+post_uuid)
    return post_uuid


def get_cookies(url):  #从返回跳转的网志中获得cookies
    ret=str(url).split("writeTask?")[-1]   #分割文本
    #if debug==1:print("cookies:"+ret)
    return ret
def get_userinfo_Aes():
    html=requests.get("mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html")
    
#获取access_token：利用本地自带的AESkey解析网址中所带的cookies-用自己的AESkey加密此key
def get_access_token(url):  #从url中解析出access-token
    cookies=get_cookies(url)
    #print(cookies)
    userInfoAeskey = base64.b64decode("VmxNbUkzTkRBdE5UWmpNaQ==".encode("utf8"))  # 需要从文件中采集运行decode解析。
    if debug==1:print("---userInfoAeskey:"+str(userInfoAeskey))
    # print(key)
    eg = EncryptDate(userInfoAeskey)  #利用网页中的userinfoaeskey变量对网址后半部进行解析，解析出cookies
    cookies=eg.decrypt(cookies)    #aes解密
    if debug==1:print("---cookies:"+cookies)
    eg=EncryptDate(aes_key)   #提取出的cookies再用之前生成过的aes_key进行aes加密
    access_token=eg.encrypt(cookies)
    if debug==1:print("---access-token:"+access_token)
    return access_token
#请求需要填报的数据，underway为正在采集中，past为已经采集过的。需要access_token unique_code参数作为头
def get_info(access_token,unique_code,past):  #past参数为0：查看未采集，参数为1：查看采集   返回一个data的数组，其中xlh数据用于向其请求详细数据
    if past==0:
        data = '{isPast: "underway", pageSize: 10, startIndex: 1}'
    elif past==1:
        data = '{isPast: "past", pageSize: 10, startIndex: 1}'      #对以往数据进行采集
    if debug == 1: print("---post_get_info:" + data)
    eg=EncryptDate(aes_key)
    data=eg.encrypt(data)   #用自己密钥加密之后post到reporlist地址，然后返回采集数据
    if debug==1:print("---post_get_info:"+data)
    headers_info = \
        {
            "Connection": "keep-alive",
            "Host": "mcp.sdut.edu.cn:8080",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": u_a,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "unique-code": unique_code,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "X-Requested-With": "com.lysoft.android.lyyd.report.mobile.sdlg",
            "access-token": access_token,
        }
    respone_info=requests.post(url_reporlist,headers=headers_info,data=data)
    respone_info=respone_info.text
    if debug==1:print("---respone_info:"+str(respone_info))
    json_info=json.loads(respone_info)
    data_yuan=json_info['data']
    eg=EncryptDate(aes_key)
    data_decode=eg.decrypt(data_yuan)
    if debug==1:print("---data_decode:"+data_decode)
    json_data=json.loads(data_decode)
    return json_data

#获取采集任务的详细信息，需要access_token，unique_code,taskid  返回json   status 填报过为0，未填报为-2
def get_detail_info(access_token,unique_code,taskid,status):
    data="{taskId: '"+str(taskid)+"', status: '"+str(status)+"'}"
    if debug==1:print("---post_get_detail_info_decode:"+data)
    eg=EncryptDate(aes_key)
    data=eg.encrypt(data)   #用自己密钥加密之后post到reporlist地址，然后返回采集数据
    if debug==1:print("---post_get_detail_info:"+data)
    headers_info = \
        {
            "Connection": "keep-alive",
            "Host": "mcp.sdut.edu.cn:8080",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": u_a,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "unique-code": unique_code,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "X-Requested-With": "com.lysoft.android.lyyd.report.mobile.sdlg",
            "access-token": access_token,
        }
    respone_info = requests.post(url_reportdatails, headers=headers_info, data=data)
    respone_info=respone_info.text
    if debug==1:print("---respone_detail_info:"+str(respone_info))
    json_info=json.loads(respone_info)
    data_yuan=json_info['data']
    eg=EncryptDate(aes_key)
    data_decode=eg.decrypt(data_yuan)
    if debug==1:print("---data_decode:"+data_decode)
    json_data=json.loads(data_decode)
    return json_data
#提交填报数据，需要一个数据组成的json，access_token,unique_code
def submit_message(sub_json,access_token,unique_code):
    if debug==1:print("---submit:"+sub_json)
    headers_info = \
        {
            "Connection": "keep-alive",
            "Origin": "http://mcp.sdut.edu.cn:8080",
            "Refere": "http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html",
            "User-Agent": u_a,
            "Accept": "*/*",
            "unique-code": unique_code,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ja;q=0.5",
            "access-token": access_token,
            "Content-Type":"multipart/form-data; boundary=----WebKitFormBoundaryxDI8NBB7hGZA3j2q"
        }

    sub_json_real=json.loads(sub_json)
    eg=EncryptDate(aes_key)
    sub_encode_aes=eg.encrypt(sub_json)
    print(sub_encode_aes)
    body = '------WebKitFormBoundaryxDI8NBB7hGZA3j2q\r\nContent-Disposition: form-data; name="data"\r\n\r\n'+sub_encode_aes+"\r\n------WebKitFormBoundaryxDI8NBB7hGZA3j2q--\r\n"
    respone_info = requests.post(url_submitmessage, headers=headers_info, data=body)
    json_respone=json.loads(respone_info.text)
    if debug==1:print("---respone_info:"+str(respone_info.text))
    responee_info=json_respone['data']
    if responee_info=="":
        return "网络延迟出现错误！"
    else:
        respone_decode=eg.decrypt(responee_info)
        if debug==1:print("---respone_submitmessage:"+respone_decode)
        return 1
#撤销填写所用函数，需要access-token,unique-code,taskid
def recall_message(to_ac,uniq,taskid):
    data="{xlh: '"+str(taskid)+"'}"
    headers_info = \
        {
            "Connection": "keep-alive",
            "Origin": "http://mcp.sdut.edu.cn:8080",
            "Refere": "http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html",
            "User-Agent": u_a,
            "Accept": "*/*",
            "unique-code": uniq,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ja;q=0.5",
            "access-token": to_ac,
        }
    eg=EncryptDate(aes_key)
    sub_encode_aes=eg.encrypt(data)
    respone_info = requests.post(url_recall, headers=headers_info, data=sub_encode_aes)
    json_respone = json.loads(respone_info.text)
    if debug == 1: print("---respone_info:" + str(respone_info.text))
    responee_info = json_respone['data']

#用于qq邮箱登录,成功发送有邮件
def qq_mail_login(from_addr,password,to_addr,smtp_server,neirong):
    # 用于构建邮件头


    # 邮箱正文内容，第一个参数为内容，第二个参数为格式(plain 为纯文本)，第三个参数为编码
    msg = MIMEText('信息采集成功！\n'+neirong, 'plain', 'utf-8')

    # 邮件头信息
    msg['From'] = Header(from_addr)
    msg['To'] = Header(to_addr)
    msg['Subject'] = Header('信息采集成功，今天不用惦记信息采集啦宝贝~~')
    # 开启发信服务，这里使用的是加密传输
    server = smtplib.SMTP_SSL(smtp_server)
    server.connect(smtp_server, 465)

    # 登录发信邮箱
    server.login(from_addr, password)
    if debug==1:print("---邮箱登录成功")
    # 发送邮件
    server.sendmail(from_addr, to_addr, msg.as_string())
    print('---邮件发送成功')
    server.quit()  # 退出登录
#错误发送邮件
def qq_mail_error(from_addr,password,to_addr,smtp_server):
    # 邮箱正文内容，第一个参数为内容，第二个参数为格式(plain 为纯文本)，第三个参数为编码
    msg = MIMEText('信息采集出错了，快去自己签到~~', 'plain', 'utf-8')

    # 邮件头信息
    msg['From'] = Header(from_addr)
    msg['To'] = Header(to_addr)
    msg['Subject'] = Header('信息采集出错了，快去自己签到~~')
    # 开启发信服务，这里使用的是加密传输
    server = smtplib.SMTP_SSL(smtp_server)
    server.connect(smtp_server, 465)

    # 登录发信邮箱
    server.login(from_addr, password)
    if debug==1:print("---邮箱登录成功，准备发送警告邮件")
    # 发送邮件
    server.sendmail(from_addr, to_addr, msg.as_string())
    print('---警告邮件发送成功')
    server.quit()  # 退出登录
#返回一个json用于提交数据
def last_json_to_submit(json1,taskid):
    json_sub='{"taskId":"'+str(taskid)+'","formDataJson":'+ str(json1["desformdatajson"])+',"fieldConfig":[],"status":"-1","imgsId":[]}'
    print(json_sub)
#自动识别出要填写的json
def auto_shibie(get_json_underway,taskid,get_json_past):
    json_dict={}

    jsong=demjson.decode(get_json_underway["desformdatajson"])
    print(jsong)
    for j in jsong:
        if j!="user_id" and j!="sfz" and j!="csrq":
            json_dict[j] = jsong[j]
            print(jsong[j])
    print(json_dict)
    #get_json=demjson.decode(get_json)
   # print(get_json["fieldconfig"][0]["small_modules"])
    #get_json_underway = demjson.decode(get_json_underway)
    item=len(get_json_underway["fieldconfig"][0]["small_modules"])
    for i in range(item):
        id_name=get_json_underway["fieldconfig"][0]["small_modules"][i]["id"]
        print("---"+str(get_json_underway["fieldconfig"][0]["small_modules"][i]))
        try:
            option_no=""
            json_dict[id_name] = option_no
            option_no=get_json_underway["fieldconfig"][0]["small_modules"][i]["options"][0]  #把id和options第一个元素对应起来
            print(get_json_underway["fieldconfig"][0]["small_modules"][i]["options"][0])
            json_dict[id_name] = option_no

            print("---"+id_name+":"+option_no)

        except:
            continue
    if debug==1:print("---json_dict"+str(json_dict))
    get_json_past = demjson.decode(get_json_past["desformdatajson"])
    item2=len(get_json_past)
    print(item2)
    print("---" + str(get_json_past))
    for i in range(item2):
        print(get_json_past)
        for id_name2 in get_json_past:
            try:
                if id_name2 in json_dict:
                    print()
                    option_no2 = get_json_past[id_name2]

                    json_dict[id_name2] = option_no2
                    print("---"+id_name2+":"+option_no2)
                else:
                    continue

            except:
                continue

    #print(get_json["desformdatajson"])

    json_ret=demjson.encode(json_dict,encoding='utf-8')
    json_ret='{"taskId":"'+str(taskid)+'","formDataJson":'+json_ret.decode('utf8')+',"fieldConfig":[],"status":"-1","imgsId":[]}'
    if debug==1:print("json_submit:"+json_ret)
    return json_ret

def get_taskid(json,n):
    json='{"xlh":"c****a67****476d-b97e****aaa83c","name":"本专科学生健康信息采集****","creator":"****","start_time":"2022-02-01 05:00:00","end_time":"2022-02-01 12:00:00","userid":"****","isfill":"0","rn":1}'
    zhuanhuan=demjson.encode(json)
  #  print("aaa"+zhuanhuan["xlh"])


if __name__ == '__main__':
    make_print_to_file(path="./log")   #进行print日志输出，
    print('explanation'.center(80, '*'))
    if debug==1:print("---DEBUG MODEL---")
    if 1:
        if debug==1:print("---session:"+url_location)
        unq = get_Unique()
        ac_to = get_access_token(url_location)
        json_info_past = get_info(ac_to, unq, 1)[0]  # 获取过去的第一个信息填报
        json_info_underway = get_info(ac_to, unq, 0)[0]  # 取第一个信息填报数据
        if debug==1:print("---json_info_underway:"+str(json_info_underway))
        if debug==1:print("---json_info_past:"+str(json_info_past))
        taskid_past = str(json_info_past["xlh"])  # 获取填过的taskid
        taskid_underway = str(json_info_underway["xlh"])  # 获取当前的taskid
        if debug==1:print("---taskid_submit_underway:"+str(taskid_underway))
        if debug == 1: print("---taskid_submit_past:" + str(taskid_past))
        #print(get_info(ac_to, unq, 1))
        status_past=json_info_past['isfill']
        status_underway = json_info_underway['isfill']
        print(status_underway)
        get_json_past = get_detail_info(ac_to, unq, str(taskid_past),str(status_past))  # 获取信息填报的详细内容
        get_json_underway = get_detail_info(ac_to, unq, str(taskid_underway),str(status_underway))  # 获取详细内容，
        get_json = auto_shibie(get_json_underway, str(taskid_underway), get_json_past)
        if debug==1:print("---submit_json:"+str(get_json))

        ret=submit_message(get_json, ac_to, unq)
        if ret!=1:
            qq_mail_error(from_addr, password, to_addr, smtp_server)
        # recall_message(ac_to,unq)  #撤销可以
        qq_mail_login(from_addr,password,to_addr,smtp_server,get_json)

   # except:
    #    qq_mail_error(from_addr,password,to_addr,smtp_server)

    if debug == 1: print("-------END-------")
    print('END: explanation'.center(80, '*'))



