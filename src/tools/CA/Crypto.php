<?php

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
	public static function encrypt7Sign($cer, $pfx, $password, $plainText, &$signature) {

        if (empty($cer)) {
            throw new Exception('公钥不能为空', 1101);
        }
        if (empty($pfx)) {
            throw new Exception('私钥不能为空', 1101);
        }
        if (empty($password)) {
            throw new Exception('私钥密码不能为空', 1101);
        }
        if (empty($plainText)) {
            throw new Exception('待加密明文不能为空', 1101);
        }



        // get the resources' path
        $path = self::getPath() . 'resources/';

        // generate a signature
        $signature = self::generateSignature($pfx, $password, $plainText, $path);

        // get the content of the public key
        $publicKey = file_get_contents($path . $cer);

        // replace all CRLF
        $strKey = str_replace(array("\r", "\n", "\r\n"), '', $publicKey);
        // check if the public key is in the trust list
        if (!self::isTrusted($strKey)) {
            throw new Exception('指定公钥不在信任范围内', 1102);
        }

        // get the length of the cipher
        $ivLen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        // generate a pseudo-random string of bytes
        $iv = openssl_random_pseudo_bytes($ivLen);
        // get the raw cipher text
        $rawCipherText = openssl_encrypt($plainText, $cipher, $publicKey, $options = OPENSSL_RAW_DATA, $iv);

        // generate a keyed hash value using the HMAC method
        $hmac = hash_hmac('sha256', $rawCipherText, $strKey, $as_binary = true);
        
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
	public static function decrypt7Check($cer, $pfx, $password, $cipherText, $signature) {
        // get the resources' path
        $path = self::getPath() . 'resources/';

        // get the content of the public key
        $publicKey = file_get_contents($path . $cer);

        // replace all CRLF
        $strKey = str_replace(array("\r", "\n", "\r\n"), '', $publicKey);
        // check if the public key is in the trust list
        if (!self::isTrusted($strKey)) {
            throw new Exception('指定公钥不在信任范围内', 1102);
        }

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

        // replace all CRLF
        $cert = str_replace(array("\r", "\n", "\r\n"), '', $certs['cert']);

        // timing attack safe comparison
        $calcMac = hash_hmac('sha256', $rawCipherText, $cert, $as_binary = true);
        if (!hash_equals($hmac, $calcMac))
        {
            throw new Exception('解密过程中验证错误', 1113);
        }

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
            throw new Exception('证书签名验证错误(包括过期)', 1104);
        } else {
            throw new Exception('证书签名错误', 1103);
        }
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
        // get the resources' path
        $path = self::getPath() . 'resources/';

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

    /**
     * 获取当前工作目录
     *
     * @return String 当前路径
     */
    public static function getPath() {
        $firstLetter = substr(__DIR__, 0, 1);
        if ($firstLetter == '/') {
            return __DIR__ . '/../../';
        }
        
        return substr(__DIR__, 7, -18);
    }

    /**
     * check if the public key is in the trust list
     *
     * @return Boolean true if the key is listed, otherwise false
     */
    public static function isTrusted($strKey) {
        // get the resources' path
        $trustFile = self::getPath() . 'resources/trust.txt';
        // get the content of the trust file
        $trust = file_get_contents($trustFile);
        // replace all CRLF
        $trust = str_replace(array("\r", "\n", "\r\n"), '', $trust);

        return (strpos($trust, $strKey) === false) ? false : true;
    }
}
