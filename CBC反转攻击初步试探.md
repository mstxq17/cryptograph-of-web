## CBC反转攻击初步试探

###0x1 CBC加解密原理



一图胜千言

**加密过程**

![cbc加密原理](https://ohduknodm.qnssl.com/20170525149569300467639.jpg)

**解 密过程**

![cbc解密过程](https://ohduknodm.qnssl.com/20170525149569301911892.jpg)

**要点:**

Plaintext:待加密字符串

iv:用于随机化加密的字符串

key:被一些如AES的对称加密算法使用 密钥

ciphertext:加密后的数据

- 加密过程：

  ```
  Ciphertext-0 = Encrypt(Plaintext XOR IV) 只用于第一个组块
  Ciphertext-N= Encrypt(Plaintext XOR Ciphertext-N-1) 用于第二及剩下的组块
  ```

- 解密过程

  ```
  Plaintext-0 = Decrypt(Ciphertext) XOR IV 只用于第一个组块
  Plaintext-N= Decrypt(Ciphertext) XOR Ciphertext-N-1 用于第二及剩下的组块
  ```

可以看到假设明文输入k 那么是 k xor x 然后加密s = encrypt(k xor x)

那么想解密s  那么就是decrypt(s) xor x =k  x是上一组加密的ciphertext 



### 0x2 例子讲解cbc攻击

>iscc 一道老题

先贴代码 

```
<?php
include 'sqlwaf.php';
define("SECRET_KEY", "................");
define("METHOD", "aes-128-cbc");
session_start();

function get_random_iv(){
    $iv='';
    for($i=0;$i<16;$i++){
        $iv.=chr(rand(1,255));
    }
    return $iv;
}
function login($info){
    $iv=get_random_iv();
    $plain = serialize($info);
    $cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
    $_SESSION['username'] = $info['username'];
    setcookie("iv", base64_encode($iv));
    setcookie("cipher", base64_encode($cipher));
}
function show_homepage(){
    if ($_SESSION["username"]==='admin'){
        echo '<p>Hello admin</p>';
        echo '<p>Flag is *************</p>';
    }else{
        echo '<p>hello '.$_SESSION['username'].'</p>';
        echo '<p>Only admin can see flag</p>';
    }
    echo '<p><a href="loginout.php">Log out</a></p>';
    die();
}
function check_login(){
    if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
        $cipher = base64_decode($_COOKIE['cipher']);
        $iv = base64_decode($_COOKIE["iv"]);
        if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
            $info = unserialize($plain) or die("<p>base64_decode('".base64_encode($plain)."') can't unserialize</p>");
            $_SESSION['username'] = $info['username'];
        }else{
            die("ERROR!");
        }
    }
}

if (isset($_POST['username'])&&isset($_POST['password'])) {
  $username=waf((string)$_POST['username']);
  $password=waf((string)$_POST['password']);
  if($username === 'admin'){
        exit('<p>You are not real admin!</p>');
    }else{
        $info = array('username'=>$username,'password'=>$password);
        login($info);
        show_homepage();
    }
}
else{
  if(isset($_SESSION["username"])){
        check_login();
        show_homepage();
    }
}
?>
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Paper login form</title>
      <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <div id="login">
  <form action="" method="post">
    <h1>Sign In</h1>
    <input name='username' type="text" placeholder="Username">
    <input name='password' type="password" placeholder="Password">
    <button>Sign in</button>
</div>
</body>
</html>


```



这里用了aes-128-cbc

128 比特 =16字节 = 1 block 也就是每16字节一个分组

首先登陆 username:bdmin password=123

那么他就会给你设置cookie返回加密和iv的值

```
iv=XgSsJKRlgTpaWqJ2oam1Aw%3D%3D; cipher=utVypinhBpaWKHrmGCL4jahvD47qzLL3PNSbah81FSL7FsFnmrdUa1%2BO3TBK%2F1LIXEU%2BiGr%2FBPWTA9rUAliBHg%3D%3D
```

首先通过简单的php代码把那个信息serilize一次

```
<?php
$username = (string)$_POST['username'];
$password = (string)$_POST['password'];
$info = array('username'=>$username,'password'=>$password);
echo serial
ize($info);
?>
```

得到 a:2:{s:8:"username";s:5:"bdmin";s:8:"password";s:3:"123";}

A:array 2:两个元素 s:类型 8:长度 这是序列化的表示方式

```
#! /usr/bin/python
# -*- coding:utf-8 -*-
import base64

str_ = 'a:2:{s:8:"username";s:5:"bdmin";s:8:"password";s:3:"123";}'
for i in range(4):
	print str_[i*16:(i+1)*16]
```

通过上面代码简单成16block的4组明文

```
a:2:{s:8:"userna
me";s:5:"bdmin";
s:8:"password";s
:3:"123";}
```

我们的目的是使bdmin中的b修改a

那么根据加密原理

我们只需要更改对应位置的的第一组密文即可(ps:首先他的加密的时候那个key长度和plaintext是一样的 所以是逐个字符进行异或 具体可以参考cbc加密流程)

所以我们只需要修改ciphertext第一组对应的的十位的字符即可

首先第一组ciphertext的第十位字符为:

 ```
ciphertext = 's8qkLoHqlzrjQ8fmHQZy%2Fw2b1Ii32%2B2BvSSDnAVuESib5fXZdTr6k5%2FyFWclgbPGSb13k6CaBdLSrVZVMlSzvw%3D%3D'
cipher = base64.b64decode(urllib.unquote(ciphertext))
print ord(cipher[9])

67 C
 ```

0 - 16 -1  建立对应的映射法则 me";s:5:"bdmin"; b在10位 1+9 =0+9=9 16+9=25

15 -31-16  

那么对第二组密文解密过程就是

ciphertext[25]^C = b

因为我们可以构造C 我们修改C为 成C^b =>ciphertext[25]^C^b^a=>b^b^a=>a

解密出来的就是a

所以对应的代码便是:

```
ciphertext = 's8qkLoHqlzrjQ8fmHQZy%2Fw2b1Ii32%2B2BvSSDnAVuESib5fXZdTr6k5%2FyFWclgbPGSb13k6CaBdLSrVZVMlSzvw%3D%3D'
cipher = base64.b64decode(urllib.unquote(ciphertext))
print cipher[9]
cipher = cipher[:9] + chr(ord(cipher[9]) ^ ord('b') ^ ord('a')) + cipher[10:]
print urllib.quote(cipher.encode('base64').strip())
```

构造出新的cipher修改cookie 得到返回

```
<p>base64_decode('OtUVnRUqrQi2u7P9anRE621lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjM6IjEyMyI7fQ==') can't unserialize</p>
解密后结果如下
:Õ*­¶»³ýjtDëme";s:5:"admin";s:8:"password";s:3:"123";}
这个时候你会发现b已经成功被修改为了a 达到了效果 但是因为这个要进行反序列化
而第一组数据由于我们修改了其中一个值导致了损坏(ps:我们修改的这个值组成了新的密文 那么这个密文就会进入到那个解密函数然后在进行与iv xor 进入解密函数的时候由于修改了一个值那么解密算法的流程就不对了所以导致数据的损坏)

```

但是我们可以通过cookie来控制iv的值 达到修复第一组数据的目的

code:

```
iv_ = 'a:2:{s:8:"userna'
iv = 'XgSsJKRlgTpaWqJ2oam1Aw%3D%3D'
new_iv =''
ciphertext1 = 'OtUVnRUqrQi2u7P9anRE621lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjM6IjEyMyI7fQ=='
cipher = base64.b64decode(urllib.unquote(ciphertext1))
iv = base64.b64decode(urllib.unquote(iv))
for i in range(16):
	new_iv += chr(ord(iv[i])^ord(cipher[i])^ord(iv_[i]))
print new_iv.encode('base64').strip()


```



这里需要全部0-15全部进行修改 原理同上 

得到新的iv 修改相应的cookie iv的值然后就可以获得flag

### 0x3  深入拓展和研究 

参考文章	:[CBC模式的脆弱性探讨](http://drops.xmd5.com/static/drops/tips-6619.html)

c-1(y)  xor r =0x01

=>c-1(y) ^ 前一个块 =>y 

参考加密流程 =>推出明文攻击





