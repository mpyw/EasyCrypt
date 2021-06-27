<?php

namespace Mpyw\EasyCrypt;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;

class HmacCryptor implements CryptorInterface
{
    public const DEFAULT_HMAC_ALGO = 'sha256';

    /**
     * @var CryptorInterface
     */
    protected $cryptor;

    /**
     * @var string
     */
    protected $algo;

    /**
     * Constructor.
     *
     * @param null|CryptorInterface $cryptor
     * @param string                $algo
     */
    public function __construct(?CryptorInterface $cryptor = null, string $algo = self::DEFAULT_HMAC_ALGO)
    {
        $this->cryptor = $cryptor ?? new Cryptor();
        $this->algo = $algo;
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
        return $this->cryptor->encrypt(
            $this->hmac($data, $password) . $data,
            $password
        );
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
        $decrypted = $this->cryptor->decrypt($data, $password);

        if ($decrypted === false) {
            return false;
        }

        $length = strlen($this->hmac('', ''));

        [$hmac, $message] = preg_split("/^.{1,$length}\K/s", $decrypted, 2);

        if ($this->hmac($message, $password) !== $hmac) {
            return false;
        }

        return $message;
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
        $decrypted = $this->cryptor->mustDecrypt($data, $password);

        $length = strlen($this->hmac('', ''));

        [$hmac, $message] = preg_split("/^.{1,$length}\K/s", $decrypted, 2);

        if ($this->hmac($message, $password) !== $hmac) {
            throw new DecryptionFailedException('HMAC digest does not match.', $data);
        }

        return $message;
    }

    /**
     * Generate HMAC hash.
     *
     * @param  string $data
     * @param  string $key
     * @return string
     */
    protected function hmac(string $data, string $key): string
    {
        return hash_hmac($this->algo, $data, $key, true);
    }
}
