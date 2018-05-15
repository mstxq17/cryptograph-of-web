### ECB加密及其攻击方式(ddctf-2018题为例子)探讨



Author:xq17

**0x1 ECB加密原理**

------------

- 分组加密

  分组密将需要进行加密的明文序列划分为若干固定长度的分组,然后使用固定长度的密钥加密固定长度的分组得到等长的加密分组

- ECB模式

  ECB(Electronic CodeBook，电码本)模式是分组密码的一种最基本的工作模式。在该模式下，待处理信息被分为大小合适的分组，然后分别对每一分组独立进行加密或解密处理

  加密和解密流程如下图

  ![1.png](http://image.3001.net/images/20150115/14212875849501.png!small)

**0x2 ECB加密缺陷**

ECB自身操作模式就比较基础,易于实现,分组的独立性便容易导致出现一些tips

由于对每个分块采用相同的key进行加密便意味着不同的分组相同的明文会得到相同的密文，这样便可以容易遭受明文攻击



**0x3 DDCTF-2018 安全通信题 分析AES ECB模式缺陷**

[国外文章讲解ECB攻击](https://zachgrace.com/2015/04/17/attacking-ecb.html)

或者google keyword:ecb attack 查阅更多相关文章

这里我按照自己的理解 show a example 讲解下ecb模式

```
def aes_encrypt(key, plaintext):
plaintext += get_padding(plaintext)
aes = AES.new(key, AES.MODE_ECB)
cipher_text = aes.encrypt(plaintext).encode('hex')
return cipher_text
```

plaintext:A   ciphertext(hex):400af2ca8e8409dfe36e6ff66e50ad99

假设明文分组为2(按顺序2个组成一个分组)

plaintext:AA ciphertex(hex):4c56e0ed0847c20cd90ee27630378622

那么我想问下当plaintext:AAA的时候你能写出密文是什么吗

明文分组: AA|A 根据分组加密原理 可以推知密文为上面的拼接

4c56e0ed0847c20cd90ee27630378622 400af2ca8e8409dfe36e6ff66e50ad99



这样子对于一个明文: {可控点}secret 我们便可以通过控制可控点然后比较密文进行逐个字符攻击  这里我输入1s|ec|re|t  那么最后一组便是t的加密  我们便可以通过循环可打印字符将t给爆破出来 然后继续控制 直到把secret完全解密(这种办法有很大局限性 我们的要知道最后一个字符才行 这个也有他的好处,我们不需要知道可控点+secret的结构 比较方便)  

关于改进的方法下面阐述，这里掠过



**为了更好演示这个利用过程**

贴上ddctf misc类型安全通信 的code:

``` python
#!/usr/bin/env python
import sys
import json
from Crypto.Cipher import AES
from Crypto import Random

def get_padding(rawstr):
remainder = len(rawstr) % 16
if remainder != 0:
return '\x00' * (16 - remainder)
return ''

def aes_encrypt(key, plaintext):
plaintext += get_padding(plaintext)
aes = AES.new(key, AES.MODE_ECB)
cipher_text = aes.encrypt(plaintext).encode('hex')
return cipher_text

def generate_hello(key, name, flag):
message = "Connection for mission: {}, your mission's flag is: {}".format(name, flag)
return aes_encrypt(key, message)

def get_input():
return raw_input()

def print_output(message):
print(message)
sys.stdout.flush()

def handle():
print_output("Please enter mission key:")
mission_key = get_input().rstrip()

print_output("Please enter your Agent ID to secure communications:")
agentid = get_input().rstrip()
rnd = Random.new()
session_key = rnd.read(16)

flag = '<secret>'
print_output(generate_hello(session_key, agentid, flag))
while True:
    print_output("Please send some messages to be encrypted, 'quit' to exit:")
    msg = get_input().rstrip()
    if msg == 'quit':
        print_output("Bye!")
        break
    enc = aes_encrypt(session_key, msg)
    print_output(enc)
if name == "main":
handle()
```

``` python
def get_padding(rawstr):
remainder = len(rawstr) % 16
if remainder != 0:
return '\x00' * (16 - remainder)#这里可以很简单看出来16字节一个分组 不足则用'\x00'进行填充
return '' 
```

加密flag代码	

```
message = "Connection for mission: {}, your mission's flag is: {}".format(name, flag) #这里很明显name我们是可以控制的 flag被写入了需要加密的明文 这样子和我上面举的例子就比较类似 flag可以被我们通过控制padding length逐字节爆破出来
```



根据题目code我们得到了加密的流程  

以16为分组 得到的结果进行hex encode（32长度）

这里先讲下我比较偷懒和比较蠢的做法

由于flag的格式最后面一个字符必然是}

所以这里我写了小脚本自动取填充

```
#coding=utf-8
import socket
import string
mission_key = '''570ddb32ebcb382bdd0a62f437c4f769'''
padd_ = ""
flag=""
for x in range(1,16):
    padd_=x*'A'
    print padd_
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect(('116.85.48.103',5002))
    s.recv(1024)
    s.send(mission_key+'\n')
    s.recv(1024)
    s.send(padd_+'\n')
    c=s.recv(1024).rstrip()
    s.recv(1024)
    s.send('}'+'\n')
    ss=s.recv(1024).rstrip()[:32]
    if c[-32:]==ss:
        flag="}"
        break
        s.close()
print 'start'
for j in range(1,16):
    padd_+='A'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect(('116.85.48.103',5002))
    s.recv(1024)
    s.send(mission_key+'\n')
    s.recv(1024)
    s.send(padd_+'\n')
    cc=s.recv(1024).rstrip()
    for i in string.printable:
        s.recv(1024)
        s.send(i+flag+'\n')
        ss=s.recv(1024).rstrip()
        if(ss==cc[-32:]):
            flag=i+flag
            print flag
            break
s.close()
print 'start'
k=1
for j in range(16,32):
    padd_+='A'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect(('116.85.48.103',5002))
    s.recv(1024)
    s.send(mission_key+'\n')
    s.recv(1024)
    s.send(padd_+'\n')
    cc=s.recv(1024).rstrip()
    for i in string.printable:
        s.recv(1024)
        s.send(i+flag[:-k]+'\n')
        ss=s.recv(1024).rstrip()
        if(ss==cc[-64:-32]):
            flag=i+flag
            print flag
            break
    k+=1
    print k
for j in range(32,48):
    padd_+='A'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect(('116.85.48.103',5002))
    s.recv(1024)
    s.send(mission_key+'\n')
    s.recv(1024)
    s.send(padd_+'\n')
    cc=s.recv(1024).rstrip()
    for i in string.printable:
        s.recv(1024)
        s.send(i+flag[:-k]+'\n')
        ss=s.recv(1024).rstrip()
        if(ss==cc[-96:-64]):
            flag=i+flag
            print flag
            break
    k+=1
    print k
s.close()

# Connection for mission: , your mission's flag is: 
```



这里4个循环 一开始先爆破出填充多少个字符导致最后'}'成为一个分组

之后的循环就是爆破前面的字符

假设我们需要爆破的字符ddctf{123456789ABCDEF}

这里为什么要用那么多循环呢 你想想加密流程就知道了

当我们爆破的字符已经达到了16位(23456789ABCDEF})

 这个时候16位已经成为一个分组了但是我们前面那个ddctf{1还没有爆破出来我们还需要继续爆破 

这个时候我们继续填充的话就要取{i}23456789ABCDEF 去循环i打印字符进行爆破

这个时候 '}'这个溢出成为最后一个分组 '123456789ABCDEF'成为了倒数第二个分组

也就是cc[-64:-32] 进行爆破———这个点其实很好理解 自己动手理解下加密流程便可以看懂代码





**接下来是介绍比较实用和比较有效的解法：**

参考某大神code:

```
#coding=utf-8
import socket
import string
mission_key = '''570ddb32ebcb382bdd0a62f437c4f769'''
a='''1234567890123456789012345678901234567890'''#最初的agent_id
flag='DDCTF{'
msg="flag is: DDCTF{"
for x in range(1,33):#长度32位
    agent=a[:40-x]+'\n'#每次变换agent
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    s.connect(('116.85.48.103',5002))
    s.recv(1024)
    s.send(mission_key+'\n')
    s.recv(1024)
    s.send(agent)
    c=s.recv(1024).rstrip()
    for i in string.printable:
        s.recv(1024)
        s.send(msg+i+'\n')
        ss=s.recv(1024).rstrip()[:32]
        if(ss==c[160:192]):
            msg=msg[1:]+i
            flag+=i
            print flag
            break
    s.close()
print flag+'}'

# Connection for mission: , your mission's flag is: 
```





这里讲解下这个代码的思路 

首先这个代码的前提是他的代码目的是提取32位字符:

我们分析下原加密代码中的	

``` 
message "Connection for mission: {可控点}, your mission's flag is: DDCTF{7ec4e929f4b93b6fbd3506dd8df5e816}"//这里我直接填充flag方便讲解
```

 首先我们print len("Connection for mission: , your mission's flag is: DDCTF{") =56=16x4-8=64-8

```
Connection for mission: , your mission's flag is: DDCTF{
```

继续计算这个

```
Connection for mission: AAAAAAAA, your mission's flag is: DDCTF{ #len 64=16X4 
```

```
Connection for mission: AAAAAAAA, your mission's #len 48=16X3
```

这里代码用 a='''1234567890123456789012345678901234567890'''

等价 a=“AAAAAAAA90123456789012345678901234567890” #len 8+32

这里的意思就是

```
Connection for mission: AAAAAAAA90123456789012345678901234567890, your mission's  #len 16x3+32=16x5
```

这里恰好能够分成6个分组

后面我们需要爆破的是这个

```
flag is: DDCTF{7ec4e929f4b93b6fbd3506dd8df5e816}
```

由于flag is: DDCTF{ 长度15 这个东西+加上一个字符 便是16 也是一个分组

那么我们通过减少a的长度

比如

a='''123456789012345678901234567890123456789''' 减少一个字符

加密的时候就会变成

```
message "Connection for mission: 123456789012345678901234567890123456789, your mission's flag is: DDCTF{7ec4e929f4b93b6fbd3506dd8df5e816}"
```

这个时候 后面的字符就会向前偏移一个位置

```
flag is: DDCTF{7
```

便会成为第六组的加密的值(原来是flag is: DDCTF{)

我们只需要比较c[160:192]

这样子就爆破出了第一个然后继续循环爆破就可以了

因为我们减少字符只会改变后面的分组数量

其实本质就是:

**我们先增长加密字符串然后在减少字符串使其经过第六组**

这里我们需要填充32个字符意味我们可以得到32个数据

我们填充48便可以得到48个数据 填充的时候需要是16的倍数也就是bloclk size的大小





**0x4 总结**

局限： {可控}+secret   

如果对最后一种方法还不理解，很有可能是我表达能力和理解能力的问题

可以移步到专业文章：[ECB攻击](https://zachgrace.com/2015/04/17/attacking-ecb.html)

由于是菜鸟第一次接触密码学，可能诸多纰漏，希望各位师傅能多多指点

