<?php

namespace Tools\Ca;

include 'Crypto.php';

$cer = Crypto::getValue('PLATFORM_DECRYPTCER');
$pfx = Crypto::getValue('CLIENT_DECRYPTPFX');
$password = Crypto::getValue('CLIENT_DECRYPTPFX_KEY');

$plainText = '刘德华';
echo 'Plain Text: ' . $plainText . "\n";

$signature = '';
$cipherText = Crypto::encryptPkcs7Sign($cer, $pfx, $password, $plainText, $signature);
echo "Cipher Text:" . $cipherText . "\n";

$cer = Crypto::getValue('CLIENT_DECRYPTCER');
$pfx = Crypto::getValue('PLATFORM_DECRYPTPFX');
$password = Crypto::getValue('PLATFORM_DECRYPTPFX_KEY');

$result = Crypto::decryptPkcs7Check($cer, $pfx, $password, $cipherText, $signature);
echo "Plain Text:" . $result . "\n";
