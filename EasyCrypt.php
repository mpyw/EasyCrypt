<?php

/*********************************************/
/***************** EasyCrypt *****************/
/*********************************************/

/* EasyCrypt provides simple interface for decryptable encryption.
 * 
 * @Version: 1.2
 * @Author : CertaiN
 * @License: CC0 (No rights reserved)
 * @GitHub : http://github.com/certainist/EasyCrypt
 * 
 * Requires PHP **5.0.0** or later.
 */

class EasyCrypt {
    
    private $key;
    private $mc;
    
    /**
    * EasyCrypt::encrypt($data, $salt)
    *
    * @param string $data Raw data
    * @param string $salt Secret key
    * @return string Encrypted data
    */
    public static function encrypt($data, $salt) {
        $obj = new self($salt);
        return $obj->_encrypt($data);
    }
    
    /**
    * EasyCrypt::decrypt($data, $salt)
    *
    * @param string $data Encrypted data
    * @param string $salt Secret key
    * @return string Decrypted data
    */
    public static function decrypt($data, $salt) {
        $obj = new self($salt);
        return $obj->_decrypt($data);
    }
    
    private function __construct($salt) {
        $this->mc = mcrypt_module_open('rijndael-256', '', 'cbc', '');
        $this->key = substr(md5($salt), 0, mcrypt_enc_get_key_size($this->mc));
    }
    
    private function __destruct() {
        mcrypt_generic_deinit($this->mc);
        mcrypt_module_close($this->mc);
    }
    
    private function _encrypt($data) {
        if (PHP_OS === 'WIN32' || PHP_OS === 'WINNT') {
            srand();
            $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mc), MCRYPT_RAND);
        } else {
            $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mc), MCRYPT_DEV_URANDOM);
        }
        mcrypt_generic_init($this->mc, $this->key, $iv);
        $data = mcrypt_generic($this->mc, $data);
        return base64_encode(base64_encode($iv) . '-' . base64_encode($data));
    }
    
    private function _decrypt($data) {
        $arr = explode('-', base64_decode($data), 2);
        if (!isset($arr[1])) {
            return '';
        }
        list($iv, $data) = $arr;
        mcrypt_generic_init($this->mc, $this->key, base64_decode($iv));
        return rtrim(mdecrypt_generic($this->mc, base64_decode($data)), "\0");
    }

}