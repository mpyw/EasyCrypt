<?php

namespace Mpyw\EasyCrypt;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\EncryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\UnsupportedCipherException;
use Mpyw\EasyCrypt\IvGenerator\IvGeneratorInterface;
use Mpyw\EasyCrypt\IvGenerator\RandomIvGenerator;

class Cryptor implements CryptorInterface
{
    public const DEFAULT_CIPHER_METHOD = 'aes256';

    /**
     * @var string
     */
    protected $method;

    /**
     * @var int
     */
    protected $ivLength;

    /**
     * @var null|int
     */
    protected $tagLength;

    /**
     * @var IvGeneratorInterface
     */
    protected $ivGenerator;

    /**
     * Constructor.
     *
     * @param string                    $method
     * @param null|IvGeneratorInterface $ivGenerator
     */
    public function __construct(string $method = self::DEFAULT_CIPHER_METHOD, ?IvGeneratorInterface $ivGenerator = null)
    {
        $methods = openssl_get_cipher_methods(true);

        if (!in_array($method, $methods, true)) {
            throw new UnsupportedCipherException($method);
        }

        $this->method = $method;
        $this->ivLength = openssl_cipher_iv_length($method);
        $this->ivGenerator = $ivGenerator ?? new RandomIvGenerator();

        set_error_handler(function () {});
        openssl_encrypt('', $this->method, '', OPENSSL_RAW_DATA, (new RandomIvGenerator())->generate($this->ivLength), $tag);
        restore_error_handler();

        $this->tagLength = $tag === null ? null : strlen($tag);
    }

    /**
     * Encrypt with shared password.
     *
     * @param  string $data
     * @param  string $password
     * @return string Binary string.
     */
    public function encrypt(string $data, string $password): string
    {
        $iv = $this->ivGenerator->generate($this->ivLength);
        $tag = null;
        $encrypted = $this->tagLength
            ? openssl_encrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv, $tag)
            : openssl_encrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            // @codeCoverageIgnoreStart
            throw new EncryptionFailedException(openssl_error_string());
            // @codeCoverageIgnoreEnd
        }

        return "$iv$encrypted$tag";
    }

    /**
     * Decrypt with shared password.
     *
     * @param  string      $data     Binary string.
     * @param  string      $password
     * @return bool|string String on success, false on failure.
     */
    public function decrypt(string $data, string $password)
    {
        try {
            return $this->mustDecrypt($data, $password);
        } catch (DecryptionFailedException $e) {
            return false;
        }
    }

    /**
     * Decrypt with shared password.
     *
     * @param  string                                               $data     Binary string.
     * @param  string                                               $password
     * @throws \Mpyw\EasyCrypt\Exceptions\DecryptionFailedException
     * @return string                                               Return string on success.
     */
    public function mustDecrypt(string $data, string $password): string
    {
        $originalData = $data;

        $iv = substr($data, 0, $this->ivLength);
        if (strlen($iv) !== $this->ivLength) {
            throw new DecryptionFailedException('invalid iv length.', $originalData);
        }
        $data = substr($data, $this->ivLength);

        $tag = null;
        if ($this->tagLength !== null) {
            $tag = substr($data, -$this->tagLength);
            if (strlen($tag) !== $this->tagLength) {
                throw new DecryptionFailedException('invalid tag length.', $originalData);
            }
            $data = substr($data, 0, -$this->tagLength);
        }

        $decrypted = $this->tagLength
            ? openssl_decrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv, $tag)
            : openssl_decrypt($data, $this->method, $password, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            $error = openssl_error_string();
            if ($error === false) {
                $error = $this->tagLength
                    ? 'invalid tag content.'
                    : 'unknown error.'; // @codeCoverageIgnore
            }
            throw new DecryptionFailedException($error, $originalData);
        }

        return $decrypted;
    }
}
