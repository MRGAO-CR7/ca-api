<?php

namespace Tools\CA;

/**
 * The Model to take the contents of the file and signs them using the certificate
 * and its matching private key specified by certificate and private_key parameters.
 *
 * @author Eric Gao
 */
class Crypto
{
    /**
	 * 加密并签名方法(正式)
     *
	 * @param String $cer 加密公钥证书
	 * @param String $pfx 签名私钥证书
	 * @param String $password 签名私钥密码
	 * @param String $plainText 明文
     *
	 * @return String 密文
	 */
	public static function encryptPkcs7Sign($cer, $pfx, $password, $plainText, &$signature) {
        $path = __DIR__ . '/../../resources/';

        // generate a signature
        $signature = self::generateSignature($pfx, $password, $plainText, $path);

        // get the content of the public key
        $publicKey = file_get_contents($path . $cer);
        // get the length of the cipher
        $ivLen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        // generate a pseudo-random string of bytes
        $iv = openssl_random_pseudo_bytes($ivLen);
        // get the raw cipher text
        $rawCipherText = openssl_encrypt($plainText, $cipher, $publicKey, $options = OPENSSL_RAW_DATA, $iv);

        // generate a keyed hash value using the HMAC method
        $cert = str_replace(array("\r", "\n", "\r\n"), '', $publicKey);
        $hmac = hash_hmac('sha256', $rawCipherText, $cert, $as_binary = true);
        
        // base64 encode
        return base64_encode($iv.$hmac.$rawCipherText);
    }

    /**
	 * 解密并验签方法(正式)
     *
	 * @param String $cer 验签公钥证书
	 * @param String $pfx 解密私钥证书
	 * @param String $password 解密私钥密码
	 * @param String $cipherText 密文字节流
     *
	 * @return String 明文
	 */
	public static function decryptPkcs7Check($cer, $pfx, $password, $cipherText, $signature) {
        $path = __DIR__ . '/../../resources/';

        // base64 decode
        $c = base64_decode($cipherText);
        // get the length of the cipher
        $ivLen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        // generate a pseudo-random string of bytes
        $iv = substr($c, 0, $ivLen);
        // get a keyed hash value
        $hmac = substr($c, $ivLen, $sha2len = 32);
        // get the raw cipher text
        $rawCipherText = substr($c, $ivLen + $sha2len);

        // get the content of the private key
        $privateKey = file_get_contents($path . $pfx);
        // decrypt the private key
        openssl_pkcs12_read($privateKey, $certs, $password);

        // decrypt the raw cipher text to get the plain text
        $plainText = openssl_decrypt($rawCipherText, $cipher, $certs['cert'], $options = OPENSSL_RAW_DATA, $iv);

        // timing attack safe comparison
        $cert = str_replace(array("\r", "\n", "\r\n"), '', $certs['cert']);
        $calcMac = hash_hmac('sha256', $rawCipherText, $cert, $as_binary = true);
        if (!hash_equals($hmac, $calcMac))
        {
            return 1113;
        }

        // get the content of the public key
        $publicKey = file_get_contents($path . $cer);
        // get the public key id
        $pubKeyId = openssl_pkey_get_public($publicKey);
        // base64 decode signature
        $signature = base64_decode($signature);

        // verify signature
        $result = openssl_verify($plainText, $signature, $pubKeyId, 'SHA256');

        // free the key from memory
        openssl_free_key($pubKeyId);

        // state whether signature is okay or not
        if ($result == 1) {
            return $plainText;
        } else if($result == 0) {
            return 1111;
        } else {
            return 1111;
        }
    }

    /**
	 * 解析配置文件并获取Key值
     *
	 * @param String $key 索引Key
	 * @return String 索引Key值
	 */
    public static function getValue($key){
        $ini_array = parse_ini_file(__DIR__ . '/../../resources/pkcs7.properties');
        return $ini_array[$key] ?? false;
    }

    /**
	 * 生成签名方法(正式)
     *
	 * @param String $pfx 签名私钥证书
	 * @param String $password 签名私钥密码
	 * @param String $plaintext 明文
	 * @param String $path 资源文件路径
     *
	 * @return String 数字签名
	 */
    public static function generateSignature($pfx, $password, $plaintext) {
        $path = __DIR__ . '/../../resources/';

        // get the content of the private key
        $privateKey = file_get_contents($path . $pfx);

        // decrypt the private key
        openssl_pkcs12_read($privateKey, $certs, $password);
        $pKeyId = openssl_pkey_get_private($certs['pkey']);

        // compute signature
        openssl_sign($plaintext, $signature, $pKeyId, 'SHA256');
        // free the key from memory
        openssl_free_key($pKeyId);

        // base64 encode signature
        return base64_encode($signature);
    }
}

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
