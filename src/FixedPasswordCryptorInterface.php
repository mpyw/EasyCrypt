<?php

namespace Mpyw\EasyCrypt;

interface FixedPasswordCryptorInterface
{
    /**
     * Encrypt with shared password.
     *
     * @param  string $data
     * @return string Binary string.
     */
    public function encrypt(string $data): string;

    /**
     * Decrypt with shared password.
     *
     * @param  string      $data Binary string.
     * @return bool|string String on success, false on failure.
     */
    public function decrypt(string $data);

    /**
     * Decrypt with shared password.
     *
     * @param  string                                               $data Binary string.
     * @throws \Mpyw\EasyCrypt\Exceptions\DecryptionFailedException
     * @return string                                               Return string on success.
     */
    public function mustDecrypt(string $data): string;
}
