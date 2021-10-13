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
	 * @param String $plaintext 明文
     *
	 * @return String 密文字节流
	 */
	public static function encryptPkcs7Sign($cer, $pfx, $password, $plaintext) {
        $path = __DIR__ . '/../../resources/';

        // generate a signature
        $signature = self::generateSignature($pfx, $password, $plaintext, $path);
        // var_dump($signature);

        // get the content of the public key
        $publicKey = file_get_contents($path . $cer);
        // var_dump($publicKey);

        // get the length of the cipher
        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        // generate a pseudo-random string of bytes
        $iv = openssl_random_pseudo_bytes($ivlen);
        // get the raw cipher text
        $ciphertext_raw = openssl_encrypt($signature, $cipher, $publicKey, $options = OPENSSL_RAW_DATA, $iv);
        // generate a keyed hash value using the HMAC method
        $hmac = hash_hmac('sha256', $ciphertext_raw, $publicKey, $as_binary = true);
        
        return base64_encode($iv.$hmac.$ciphertext_raw);
    }

    /**
	 * 生成签名方法(正式)
     *
	 * @param String $pfx 签名私钥证书
	 * @param String $password 签名私钥密码
	 * @param String $plaintext 明文
	 * @param String $path 资源文件路径
     *
	 * @return String 密文字节流
	 */
    private static function generateSignature($pfx, $password, $plaintext, $path) {
        // get the content of the private key
        $privateKey = file_get_contents($path . $pfx);

        // decrypt the private key
        openssl_pkcs12_read($privateKey, $certs, $password);
        // var_dump($certs);
        $pKeyId = openssl_get_privatekey($certs['pkey']);

        // compute signature
        openssl_sign($plaintext, $signature, $pKeyId, 'SHA256');

        return base64_encode($signature);
    }

    /**
	 * 解密并验签方法(正式)
     *
	 * @param String $cer 验签公钥证书
	 * @param String $pfx 解密私钥证书
	 * @param String $password 解密私钥密码
	 * @param String $cipherText 密文字节流
     *
	 * @return 明文
	 */
	public static function decryptPkcs7Check($cer, $pfx, $password, $cipherText) {


        // $c = base64_decode($ciphertext);
        // $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        // $iv = substr($c, 0, $ivlen);
        // $hmac = substr($c, $ivlen, $sha2len=32);
        // $ciphertext_raw = substr($c, $ivlen+$sha2len);
        // $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        // $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
        // if (hash_equals($hmac, $calcmac))// timing attack safe comparison
        // {
        //     echo $original_plaintext."\n";
        // }
    }

    public static function getValue($key){
        $ini_array = parse_ini_file(__DIR__ . '/../../resources/pkcs7.properties');
        return $ini_array[$key] ?? false;
    }
}

$cer = Crypto::getValue('PLATFORM_DECRYPTCER');
$pfx = Crypto::getValue('CLIENT_DECRYPTPFX');
$password = Crypto::getValue('CLIENT_DECRYPTPFX_KEY');

$plaintext = 'TEST';
echo "Plain Text:" . $plaintext . "\n";

$cipherText = Crypto::encryptPkcs7Sign($cer, $pfx, $password, $plaintext);
echo "Cipher Text:" . $cipherText . "\n";

$cer = Crypto::getValue('CLIENT_DECRYPTCER');
$pfx = Crypto::getValue('PLATFORM_DECRYPTPFX');
$password = Crypto::getValue('PLATFORM_DECRYPTPFX_KEY');

// $result = Crypto::decryptPkcs7Check($cer, $pfx, $password, $cipherText);
// echo "Plain Text:" . $result . "\n";
