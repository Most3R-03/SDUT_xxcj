# SDUT_xxcj
这是一个山东理工大学信息采集的py脚本，仅仅只用于个人学习使用，请不要利用此脚本对他人信息进行非法操作。开发此脚本的初衷仅仅是帮助总是忘记信息采集导致记过的同学进行信息采集。  

有问题请联系763026400@qq.com。

# 使用前准备

如果你仅仅是想使用此脚本进行自动化的信息采集，强烈建议你看完这篇README  

你只需要使用抓包技能对app进行http的抓包，IOS端建议使用Stream、或者利用fiddler进行http代理。这里默认你已经安装好并准备好进行http抓包  

首先，用手机打开山东理工大学app，进入选择应用界面，开启抓包(仅http即可)，在手机界面正常进行信息采集，接下来你需要找出这条http请求:  

![image](https://user-images.githubusercontent.com/29743002/154071847-bea47784-3d2f-4a18-8ab9-0722db2c0513.png)

你需要将Location这里的网址复制出来，放到py的url_location变量中(在文件的前几行)：  

url_location="http://mcp.sdut.edu.cn:8080/h5_separation/info_collect/index.html#/writeTask?v0O3eo6NCMeZmBcJZakb5mWpJ2+tbnD/l0Bc+tHkJPLY6S3CNzw72M0mYprnfLHim7o5a7cmwltETH6CM"  

脚本默认使用QQ邮箱进行填报通知，如果不需要通知或者别的方式你可以手动修改代码进行接入，比如利用QQ协议。  

from_addr = 'your@qq.com'  # qq邮箱登录地址  
password = 'shouquanma'  # qq邮箱授权码,可以去qq邮箱官网申请此授权码。  
to_addr = 'your@qq.com'  # 需要发送的地址  
smtp_server = 'smtp.qq.com'  # 默认协议
global userInfoAeskey  # 该变量为JS文件中的AES密钥，暂时没有变，为base64解码之后的(VmxNbUkzTkRBdE5UWmpNaQ==)

接下来就是python的常规操作了：  

pip3 install requests    将py中所有import的库利用此命令全部安装  

python3 sdut_xxcj.py  

执行无误后就可以把它挂到服务器中定时执行了，为保证日志保存，请在目录创建log文件夹存放日志输出。  

成功或者失败都会进行邮箱邮件提示。  

# 自动填报逻辑

首先，脚本会读取你以前的第一条信息提交数据，然后提取出你提交过的信息，作为此次提交的一部分，例如，地址、是否核酸检测等等。然后读取未填报信息，利用其返回的保存数据首先进行默认补全。最后默认将未填报所有问题设置为第一个选项，例如，是否接受过核算检测？ A否 B是，会默认选择A否。将所有信息默认填报后提交。  

如果你想修改提交信息，你需要自己利用submit_message函数进行提交，需要按照json的格式提交到服务器。

# Unique-code和access-token获取原理

获取Unique-code：生成AES_key->base64编码->GET得到公钥->用公钥对AESkey加密->请求私钥(带有公钥加密的data)->将私钥利用生成的AESkey进行解密->作为unique-code  

获取access_token：利用本地自带的AESkey解析网址中所带的cookies->用自己的AESkey加密此key  

# 可以持续多长时间

暂时没有细细的统计，应该可以持续很久，如果重新登陆app需要重新添加locational地址。(请不要将自己的access-token和unique-code泄露！！！)  
