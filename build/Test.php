<?php

include 'phar://'.__DIR__.'/ca-api.v0.0.1.phar/Crypto.php';

$config = parse_ini_file(__DIR__.'/resources/pkcs7.properties');

$cer = $config['PLATFORM_DECRYPTCER'];
$pfx = $config['CLIENT_DECRYPTPFX'];
$password = $config['CLIENT_DECRYPTPFX_KEY'];

$plainText = '刘德华';
echo '明文: ' . $plainText . "\n\n";

$signature = '';
$cipherText = Crypto::encryptPkcs7Sign($cer, $pfx, $password, $plainText, $signature);
echo "加密后...\n";
echo "密文: " . $cipherText . "\n";

$cer = $config['CLIENT_DECRYPTCER'];
$pfx = $config['PLATFORM_DECRYPTPFX'];
$password = $config['PLATFORM_DECRYPTPFX_KEY'];

$result = Crypto::decryptPkcs7Check($cer, $pfx, $password, $cipherText, $signature);
echo "解密后...\n";
echo "明文: " . $result . "\n";
