<?php

namespace mpyw\EasyCrypt;

class Cryptor
{
    private $method;
    private $length;

    /**
     * Constructor.
     * @param string $method
     */
    public function __construct($method = 'aes256')
    {
        $methods = openssl_get_cipher_methods(true);
        if (!in_array($method, $methods, true)) {
            throw new \DomainException('Unsupported cipher method.');
        }
        $this->method = $method;
        $this->length = openssl_cipher_iv_length($method);
    }

    /**
     * Get random bytes.
     * @param  int $length
     * @return string
     */
    private static function random($length)
    {
        if ($length < 1) {
            return '';
        }
        do {
            $data = openssl_random_pseudo_bytes($length, $secure);
        } while (!$secure);
        return $data;
    }

    /**
     * Encrypt with shared password.
     * @param  string $data
     * @param  string $password
     * @return string Binary string.
     */
    public function encrypt($data, $password)
    {
        $iv = self::random($this->length);
        $encrypted = openssl_encrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            // @codeCoverageIgnoreStart
            throw new \UnexpectedValueException('Failed to encrypt.');
            // @codeCoverageIgnoreEnd
        }
        return "$iv$encrypted";
    }

    /**
     * Decrypt with shared password.
     * @param  string $data     Binary string.
     * @param  string $password
     * @return string|bool      String for success, false for failure.
     */
    public function decrypt($data, $password)
    {
        $iv = substr($data, 0, $this->length);
        if (strlen($iv) !== $this->length) {
            return false;
        }
        $data = substr($data, $this->length);
        return openssl_decrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);
    }
}
