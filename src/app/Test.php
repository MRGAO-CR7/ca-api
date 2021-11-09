<?php

namespace App;

// // 使用Laravel等开发框架的时候，可以使用use引用加密解密模块
// use Lib\CA\Crypto;

// 在纯PHP代码中倒入加密解密模块的文件
include __DIR__ . '/../lib/ca/Crypto.php';

// 读取配置文件
$config = parse_ini_file(__DIR__ . '/../resources/pkcs7.properties');


/***************************************** 客户端代码（开始） ***********************************************/
// 读取服务器公钥文件名称
$cer = $config['PLATFORM_DECRYPTCER'];
// 读取客户端私钥文件名称
$pfx = $config['CLIENT_DECRYPTPFX'];
// 读取客户端私钥密码
$password = $config['CLIENT_DECRYPTPFX_KEY'];

// 待加密原文
$plainText = '刘德华';
echo '原文: ' . $plainText . "\n\n";

// 签名变量用来存储加密生成的签名字符串
$signature = '';

try {
    // 进行加密并取得签名
    $cipherText = \Lib\CA\Crypto::encrypt7Sign($cer, $pfx, $password, $plainText, $signature);
} catch (Exception $e) {
    echo "加密过程中发生异常...\n";
    echo $e->getCode() . "\n";
    echo $e->getMessage() . "\n";

    exit;
}
/***************************************** 客户端代码（结束） ***********************************************/

echo "加密后...\n";
echo "密文: " . $cipherText . "\n\n";


/***************************************** 服务器端代码（开始） ***********************************************/
// 读取客户端公钥文件名称
$cer = $config['CLIENT_DECRYPTCER'];
// 读取服务器端私钥文件名称
$pfx = $config['PLATFORM_DECRYPTPFX'];
// 读取服务器端私钥密码
$password = $config['PLATFORM_DECRYPTPFX_KEY'];

try {
    // 签证签名并解密
    $result = \Lib\CA\Crypto::decrypt7Check($cer, $pfx, $password, $cipherText, $signature);
} catch (Exception $e) {
    echo "解密过程中发生异常...\n";
    echo $e->getCode() . "\n";
    echo $e->getMessage() . "\n";

    exit;
}
/***************************************** 服务器端代码（结束） ***********************************************/

echo "解密后...\n";
echo "明文: " . $result . "\n\n";
