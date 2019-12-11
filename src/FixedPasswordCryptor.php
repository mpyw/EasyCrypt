<?php

namespace Mpyw\EasyCrypt;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;

class FixedPasswordCryptor implements FixedPasswordCryptorInterface
{
    /**
     * @var string
     */
    protected $password;

    /**
     * @var CryptorInterface
     */
    protected $cryptor;

    /**
     * Constructor.
     *
     * @param string                $password
     * @param null|CryptorInterface $cryptor
     */
    public function __construct(string $password, ?CryptorInterface $cryptor = null)
    {
        $this->password = $password;
        $this->cryptor = $cryptor ?? new Cryptor();
    }

    /**
     * Encrypt with shared password.
     *
     * @param  string $data
     * @return string Binary string.
     */
    public function encrypt(string $data): string
    {
        return $this->cryptor->encrypt($data, $this->password);
    }

    /**
     * Decrypt with shared password.
     *
     * @param  string      $data Binary string.
     * @return bool|string String on success, false on failure.
     */
    public function decrypt(string $data)
    {
        return $this->cryptor->decrypt($data, $this->password);
    }

    /**
     * Decrypt with shared password.
     *
     * @param  string                    $data Binary string.
     * @throws DecryptionFailedException
     * @return string                    Return string on success.
     */
    public function mustDecrypt(string $data): string
    {
        return $this->cryptor->mustDecrypt($data, $this->password);
    }
}
