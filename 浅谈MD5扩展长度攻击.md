### 浅谈MD5扩展长度攻击###

**0x1 MD5加密原理**

md5简要叙述:

MD5以512位分组来处理输入的信息，且每一分组又被划分为16个32位子分组，经过了一系列的处理后，算法的输出由四个32位分组组成，将这四个32位分组级联后将生成一个128位散列值。

![流程图](https://gss0.bdstatic.com/-4o3dSag_xI4khGkpoWK1HF6hhy/baike/s%3D220/sign=0d21201058ee3d6d26c680c973176d41/c75c10385343fbf2ee0d9594b17eca8065388f67.jpg)



首先了解下大端字节序:高字节存于低内存地址 低字节存于内存高地址 (内存表达形式)   example:0x6A 6B 6C 6D (单位为字节 倒过来即可)

小端字节序：写在代码的变量顺序 eample:0x6D6C6B6A

**0x2 MD5扩展攻击的目的**

攻击场景：

1.假设我们实现文件下载file=filename&hash=md5($key.filename)

然后判断hash是否等于md5($key.filename) 如果相等就进行下载

也就是说这里我们只要推出config.php 的md5($key.'config.php')的hash

那么就可以实现任意下载config.php的功能

2.某ctf的题目 有点为出题而出题的意思

```
<?php
include "secret.php";
@$username=(string)$_POST['username'];
function enc($text){
    global $key;
    return md5($key.$text);
}
if(enc($username) === $_COOKIE['verify']){
    if(is_numeric(strpos($username, "admin"))){
        die($flag);
    }
    else{
        die("you are not admin");
    }
}
else{
    setcookie("verify", enc("guest"), time()+60*60*24*7);
    setcookie("len", strlen($key), time()+60*60*24*7);
}
show_source(__FILE__);
```

原理同上



小结:就是在不知道key的具体值的时候 我们可以通过某些条件比如key的长度 某个已知明文通过MD5($key.已知明文)MD5值去推MD5(\$key.任意值)的MD5



**0x3 MD5扩展攻击的具体实现流程(例子分析)**



```
include "secret.php";
@$username=(string)$_POST['username'];
function enc($text){
    global $key;
    return md5($key.$text);
}
```

$key很明显写在了secret.php文件里面 enc函数就是经典上面所举的例子

```
if(enc($username) === $_COOKIE['verify']){
    if(is_numeric(strpos($username, "admin"))){
        die($flag);
    }
    else{
        die("you are not admin");
    }
}
else{
    setcookie("verify", enc("guest"), time()+60*60*24*7);
    setcookie("len", strlen($key), time()+60*60*24*7);
}
show_source(__FILE__);
```

很明显就可以知道代码需要的是我们传入一个带有admin的任意值

然后把cookie设置为MD5($key.带有admin的任意值)这样子就实现了相等

所以我们的目的就是构造出这个带有admin的任意值使其和$key拼接之后的md5我们可以算出来

已知条件:

cookie 里面有strlen($key) =>$key的长度 

有guest的MD5($key.'guest')=>MD5($key.'guest') 题目：78cfc57d983b4a17e55828c001a3e781

攻击流程:

首先了解78cfc57d983b4a17e55828c001a3e781这个值怎么来的

这里假设$key=abc

MD5(abcguest)  **MD5以512比特为一组进行分组加密得到ABCD变量最后ABCD变量的级联就是最后的MD5值 **

信息如果不够64字节的长度就会进行00填充 在message后面加\x80代表填充

78cfc57d983b4a17e55828c001a3e781 32个字节拆分为4组 每组进行大端字节序的转换就得到最后的ABCD四个变量

abcguest 8字节 8x8=64bit 长度为:64(十进制)->0x40(十六进制) 进行填充到448bit 56 字节 56-8=48 字节

61 62 63 67 75 65 73 74 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

512-448=64bit=8字节  后面8字节补充信息长度 按小端字节序填充

61 62 63 67 75 65 73 74 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  

然后64字节 64/16=4  每四个字节分成16组

M0:61 62 63 67

….

M15:00 00 00 00

**进行分组处理:**

每一分组的算法流程如下：

第一分组需要将上面四个链接变量复制到另外四个变量中：A到a，B到b，C到c，D到d。**从第二分组开始的变量为上一分组的运算结果**（重点这里），即A = a， B = b， C = c， D = d。

主循环有四轮（MD4只有三轮），每轮循环都很相似。第一轮进行16次操作。每次操作对a、b、c和d中的其中三个作一次非线性函数运算，然后将所得结果加上第四个变量，文本的一个子分组和一个常数。再将所得结果向左**环移**一个不定的数，并加上a、b、c或d中之一。最后用该结果取代a、b、c或d中之一。

以下是每次操作中用到的四个非线性函数（每轮一个）。

F( X ,Y ,Z ) = ( X & Y ) | ( (~X) & Z )

G( X ,Y ,Z ) = ( X & Z ) | ( Y & (~Z) )

H( X ,Y ,Z ) =X ^ Y ^ Z

I( X ,Y ,Z ) =Y ^ ( X | (~Z) )

（&是与（And），|是或（Or），~是非（Not），^是异或（Xor））

这四个函数的说明：如果X、Y和Z的对应位是独立和均匀的，那么结果的每一位也应是独立和均匀的。

F是一个逐位运算的函数。即，如果X，那么Y，否则Z。函数H是逐位奇偶操作符。

假设Mj表示消息的第j个子分组（从0到15），常数ti是4294967296*abs( sin(i) ）的整数部分，i 取值从1到64，单位是弧度。（4294967296=232）

现定义：

FF(a ,b ,c ,d ,Mj ,s ,ti ) 操作为 a = b + ( (a + F(b,c,d) + Mj + ti) << s)

GG(a ,b ,c ,d ,Mj ,s ,ti ) 操作为 a = b + ( (a + G(b,c,d) + Mj + ti) << s)

HH(a ,b ,c ,d ,Mj ,s ,ti) 操作为 a = b + ( (a + H(b,c,d) + Mj + ti) << s)

II(a ,b ,c ,d ,Mj ,s ,ti) 操作为 a = b + ( (a + I(b,c,d) + Mj + ti) << s)

**注意：“<<”表示循环左移位，不是左移位。**





第二分组开始的变量为上一分组的运算结果 通过这句话

我们就可以知道假如我们输入的是大于64字节的message那么就会有两组

数据 也就是说 假如我们知道了第一组的明文和密文 那么第一组的密文就会成为第二组的初始化变量然后进行一系列运算的到message的加密值

通俗的来讲就是说 我们把md5加密的过程分开了两部分 

$key->中间值->最终结果  我们得到了中间值 便可以不需要\$key 就可以构造出hash

这里也说明了Md5扩展攻击目的就是构造一个MD5



所以说这道题目的思路便很明显了



$key 长度46 

MD5($key.'guest') =>78cfc57d 983bc4a17 e55828c0 01a3e781

逆推出A = 0x7dc5cf78 B= …….   D=0x81e7a301

[MD5加密python流程](https://blog.csdn.net/adidala/article/details/28677393)

然后我们取第二组的值然后改变量带入md5加密的源代码就可以得到hash了

这里有些细节过程: 50

先补上key 46字    节:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxguest\x80x00\x00\x00\x00\x98\x01\x00\x00\x00\x00admin

即可 51x8=401 = 0x198 后8位补长度



然后把admin和改变iv为已知的变量进行md5即可以得到

[MD5加密源码 iv变量修改进行加密参考](https://blog.csdn.net/qq_35078631/article/details/70941204)



$key.guest\x80x00\x00\x00\x00\x98\x01\x00\x00\x00\x00admin的md5值



然后修改\x 为%去掉xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

修改cookie为加密后的md5

即可得到flag



推荐自动化工具:hashpump



**0x4 防御及其思考**

修改加密方式:MD5(\$messgae.$key) 这样子我们没办法得到中间变量进去消\$key

思考：[phpwind 利用哈希长度扩展攻击进行getshell](https://www.leavesongs.com/PENETRATION/phpwind-hash-length-extension-attack.html)

吐槽:hash的扩展攻击这个点其实很早就被玩的差不多了 真实的攻击场景见到的实在是少而且ctf考点非常单一 



**0x5 彩蛋**

写到文末才发现原来有ipic这个图床神器  这个对md党简直就是福利  以后我写文档就可以做到图文并茂了                                        Author:xq17
