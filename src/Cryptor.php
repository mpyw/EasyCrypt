<?php

namespace Mpyw\EasyCrypt;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\IvGenerator\IvGeneratorInterface;
use Mpyw\EasyCrypt\IvGenerator\RandomIvGenerator;
use Mpyw\EasyCrypt\OpenSSL\OpenSSL;

class Cryptor implements CryptorInterface
{
    public const DEFAULT_CIPHER_METHOD = 'aes256';

    /**
     * @var OpenSSL
     */
    protected $openssl;

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
        $this->openssl = new OpenSSL($method);
        $this->ivGenerator = $ivGenerator ?? new RandomIvGenerator();
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
        $iv = $this->ivGenerator->generate($this->openssl->ivLength());
        $encrypted = $this->openssl->encrypt($data, $password, $iv);

        return "$iv{$encrypted->data}{$encrypted->tag}";
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

        $iv = static::cutFragmentFrom($data, $this->openssl->ivLength());
        if (strlen($iv) !== $this->openssl->ivLength()) {
            throw new DecryptionFailedException('invalid iv length.', $originalData);
        }

        if ($this->openssl->useTag()) {
            $tag = static::cutFragmentFrom($data, -$this->openssl->tagLength());
            if (strlen($tag) !== $this->openssl->tagLength()) {
                throw new DecryptionFailedException('invalid tag length.', $originalData);
            }
        }

        return $this->openssl->decrypt($data, $originalData, $password, $iv, $tag ?? null);
    }

    protected static function cutFragmentFrom(string &$data, int $length): string
    {
        [$fragment, $data] = [substr($data, 0, $length), substr($data, $length)];

        if ($length < 0) {
            [$fragment, $data] = [$data, $fragment];
        }

        return $fragment;
    }
}
