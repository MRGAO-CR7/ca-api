<?php

include 'phar://'.__DIR__.'/ca-api.v1.0.0.phar/Crypto.php';

$config = parse_ini_file(__DIR__.'/resources/pkcs7.properties');

$cer = $config['PLATFORM_DECRYPTCER'];
$pfx = $config['CLIENT_DECRYPTPFX'];
$password = $config['CLIENT_DECRYPTPFX_KEY'];

$plainText = '刘德华';
echo '明文: ' . $plainText . "\n\n";

$signature = '';
try {
    $cipherText = Crypto::encrypt7Sign($cer, $pfx, $password, $plainText, $signature);
} catch (Exception $e) {
    echo "加密过程中发生异常...\n";
    echo $e->getCode() . "\n";
    echo $e->getMessage() . "\n";

    exit;
}

echo "加密后...\n";
echo "密文: " . $cipherText . "\n\n";

$cer = $config['CLIENT_DECRYPTCER'];
$pfx = $config['PLATFORM_DECRYPTPFX'];
$password = $config['PLATFORM_DECRYPTPFX_KEY'];

try {
    $result = Crypto::decrypt7Check($cer, $pfx, $password, $cipherText, $signature);
} catch (Exception $e) {
    echo "解密过程中发生异常...\n";
    echo $e->getCode() . "\n";
    echo $e->getMessage() . "\n";

    exit;
}

echo "解密后...\n";
echo "明文: " . $result . "\n\n";
