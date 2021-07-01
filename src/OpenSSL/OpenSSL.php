<?php

namespace Mpyw\EasyCrypt\OpenSSL;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\EncryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\UnsupportedCipherException;
use Mpyw\EasyCrypt\IvGenerator\RandomIvGenerator;

class OpenSSL
{
    /**
     * @var string
     */
    protected $method;

    /**
     * @var null|bool|int
     */
    protected $tagLength = false;

    /**
     * @var null|int
     */
    protected $ivLength;

    /**
     * OpenSSL constructor.
     *
     * @param string $method
     */
    public function __construct(string $method)
    {
        $methods = openssl_get_cipher_methods(true);

        if (!in_array($method, $methods, true)) {
            throw new UnsupportedCipherException($method);
        }

        $this->method = $method;
    }

    /**
     * @param  string           $data
     * @param  string           $password
     * @param  string           $iv
     * @return EncryptionResult
     */
    public function encrypt(string $data, string $password, string $iv = ''): EncryptionResult
    {
        $encrypted = $this->useTag()
            ? openssl_encrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv, $tag)
            : openssl_encrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            // @codeCoverageIgnoreStart
            throw new EncryptionFailedException(openssl_error_string());
            // @codeCoverageIgnoreEnd
        }

        return new EncryptionResult($encrypted, $tag ?? null);
    }

    /**
     * @param  string                    $data
     * @param  string                    $originalData
     * @param  string                    $password
     * @param  string                    $iv
     * @param  null|string               $tag
     * @throws DecryptionFailedException
     * @return string
     */
    public function decrypt(string $data, string $originalData, string $password, string $iv = '', ?string $tag = null): string
    {
        $decrypted = $this->useTag()
            ? openssl_decrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv, $tag ?? '')
            : openssl_decrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            $error = openssl_error_string() ?: ($this->useTag() ? 'invalid tag content.' : 'unknown error.');
            throw new DecryptionFailedException($error, $originalData);
        }

        return $decrypted;
    }

    /**
     * @return int
     */
    public function ivLength(): int
    {
        return $this->ivLength ?? ($this->ivLength = openssl_cipher_iv_length($this->method));
    }

    /**
     * @return null|int
     */
    public function tagLength(): ?int
    {
        if (!is_bool($this->tagLength)) {
            return $this->tagLength;
        }

        set_error_handler(static function () {});
        openssl_encrypt('', $this->method, '', OPENSSL_RAW_DATA, (new RandomIvGenerator())->generate($this->ivLength()), $tag);
        restore_error_handler();

        return $this->tagLength = $tag === null ? null : strlen($tag);
    }

    /**
     * @return bool
     */
    public function useTag(): bool
    {
        return $this->tagLength() !== null;
    }
}
