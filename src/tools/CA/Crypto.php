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
	 * @param String &$signature 引用签名存储变量
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

        // 获取资源文件路径
        $path = self::getPath() . 'resources/';

        // 判断文件是否存在
        if (!file_exists($path . $cer)) {
            throw new Exception('公钥证书文件不存在', 1103);
        }

        // 读取公钥内容
        $publicKey = file_get_contents($path . $cer);

        // 替换回车换行
        $strKey = str_replace(array("\r", "\n", "\r\n"), '', $publicKey);
        // 检查证书是否在信任链列表中
        if (!self::isTrusted($strKey)) {
            throw new Exception('指定公钥不在信任链列表中', 1102);
        }

        // 生成签名
        $signature = self::generateSignature($pfx, $password, $plainText, $path);

        // 获取暗码长度
        $ivLen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        // 生成随机防伪字节串
        $iv = openssl_random_pseudo_bytes($ivLen);

        // 获取初始加密文本
        $rawCipherText = openssl_encrypt($plainText, $cipher, $publicKey, $options = OPENSSL_RAW_DATA, $iv);
        if (!$rawCipherText) {
            throw new Exception('加密失败', 1110);
        }

        // 使用HMAC方法生成密钥散列值
        $hmac = hash_hmac('sha256', $rawCipherText, $strKey, $as_binary = true);

        // base64加密生成密文结果
        return base64_encode($iv.$hmac.$rawCipherText);
    }

    /**
	 * 解密并验签方法(正式)
     *
	 * @param String $cer 验签公钥证书
	 * @param String $pfx 解密私钥证书
	 * @param String $password 解密私钥密码
	 * @param String $cipherText 密文字节流
	 * @param String $signature 签名字符串
     *
	 * @return String 明文
	 */
	public static function decrypt7Check($cer, $pfx, $password, $cipherText, $signature) {
        if (empty($cer)) {
            throw new Exception('公钥不能为空', 1101);
        }
        if (empty($pfx)) {
            throw new Exception('私钥不能为空', 1101);
        }
        if (empty($password)) {
            throw new Exception('私钥密码不能为空', 1101);
        }
        if (empty($cipherText)) {
            throw new Exception('待解密文不能为空', 1101);
        }

        // 获取资源文件路径
        $path = self::getPath() . 'resources/';

        // 判断文件是否存在
        if (!file_exists($path . $cer)) {
            throw new Exception('公钥证书文件不存在', 1103);
        }

        // 读取公钥内容
        $publicKey = file_get_contents($path . $cer);

        // 替换回车换行
        $strKey = str_replace(array("\r", "\n", "\r\n"), '', $publicKey);
        // 检查公钥证书是否在信任链列表中
        if (!self::isTrusted($strKey)) {
            throw new Exception('指定公钥不在信任链列表中', 1102);
        }

        // base64解密
        $c = base64_decode($cipherText);
        // 获取暗码长度
        $ivLen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        // 读取防伪字节串
        $iv = substr($c, 0, $ivLen);
        // 读取HMAC方法生成的密钥散列值
        $hmac = substr($c, $ivLen, $sha2len = 32);
        // 读取初始加密文本
        $rawCipherText = substr($c, $ivLen + $sha2len);

        // 判断文件是否存在
        if (!file_exists($path . $pfx)) {
            throw new Exception('私钥证书文件不存在', 1103);
        }

        // 读取私钥内容
        $privateKey = file_get_contents($path . $pfx);

        // 解密私钥
        openssl_pkcs12_read($privateKey, $certs, $password);
        if (empty($certs)) {
            throw new Exception('解密私钥失败('.openssl_error_string().')', 1110);
        }

        // 解密加密文本获取明文内容
        $plainText = openssl_decrypt($rawCipherText, $cipher, $certs['cert'], $options = OPENSSL_RAW_DATA, $iv);
        if (!$plainText) {
            throw new Exception('解密失败('.openssl_error_string().')', 1111);
        }

        // 替换回车换行
        $cert = str_replace(array("\r", "\n", "\r\n"), '', $certs['cert']);

        // 计时攻击安全验证(timing attack safe comparison)
        $calcMac = hash_hmac('sha256', $rawCipherText, $cert, $as_binary = true);
        if (!hash_equals($hmac, $calcMac))
        {
            throw new Exception('解密过程中验证错误', 1113);
        }

        // 获取公钥ID
        $pubKeyId = openssl_pkey_get_public($publicKey);
        // base64解密签名
        $signature = base64_decode($signature);

        // 核实签名
        $result = openssl_verify($plainText, $signature, $pubKeyId, 'SHA256');

        // 释放公钥内存
        openssl_free_key($pubKeyId);

        // 验证签名并返回结果
        if ($result == 1) {
            return $plainText;
        } else if($result == 0) {
            throw new Exception('签名无效', 1112);
        } else {
            throw new Exception('签名错误('.openssl_error_string().')', 1112);
        }
    }

    /**
	 * 生成签名方法(正式)
     *
	 * @param String $pfx 签名私钥证书
	 * @param String $password 签名私钥密码
	 * @param String $plaintext 明文
     *
	 * @return String 数字签名
	 */
    public static function generateSignature($pfx, $password, $plaintext) {
        // 获取资源文件路径
        $path = self::getPath() . 'resources/';

        // 判断文件是否存在
        if (!file_exists($path . $pfx)) {
            throw new Exception('私钥证书文件不存在', 1103);
        }

        // 读取私钥内容
        $privateKey = file_get_contents($path . $pfx);

        // 解密私钥
        openssl_pkcs12_read($privateKey, $certs, $password);
        if (empty($certs)) {
            throw new Exception('解密私钥失败('.openssl_error_string().')', 1110);
        }

        // 获取私钥ID
        $pKeyId = openssl_pkey_get_private($certs['pkey']);

        // 生成签名
        openssl_sign($plaintext, $signature, $pKeyId, 'SHA256');
        if (empty($signature)) {
            throw new Exception('生成签名失败', 1110);
        }

        // 释放私钥内存
        openssl_free_key($pKeyId);

        // base64加密签名
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
     * 检查公钥证书是否在信任链列表中
     *
	 * @param String $pubKey 公钥
     * @return Boolean 公钥证书可信任返回true, 否则返回false
     */
    public static function isTrusted($pubKey) {
        // 获取trust资源文件路径
        $trustFile = self::getPath() . 'resources/trust.txt';

        // 判断文件是否存在
        if (!file_exists($trustFile)) {
            throw new Exception('信任链文件(trust.txt)不存在', 1102);
        }

        // 读取trust文件内容
        $trust = file_get_contents($trustFile);

        // 替换回车换行
        $trust = str_replace(array("\r", "\n", "\r\n"), '', $trust);

        return (strpos($trust, $pubKey) === false) ? false : true;
    }
}
