<?php

namespace Tests;

use Mpyw\EasyCrypt\Cryptor;
use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\UnsupportedCipherException;
use Mpyw\EasyCrypt\FixedPasswordCryptor;
use PHPUnit\Framework\TestCase;

/**
 * Class FixedPasswordCryptorTest
 */
class FixedPasswordCryptorTest extends TestCase
{
    public function testAes256(): void
    {
        $cryptor = new FixedPasswordCryptor('password');
        $anotherCryptor = new FixedPasswordCryptor('passward');

        $encryptedA = $cryptor->encrypt('data');
        $encryptedB = $cryptor->encrypt('data');

        $this->assertSame('data', $cryptor->decrypt($encryptedA));
        $this->assertSame('data', $cryptor->decrypt($encryptedB));
        $this->assertNotSame($encryptedA, $encryptedB);

        $this->assertFalse($anotherCryptor->decrypt($encryptedA));
    }

    public function testRc4(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new Cryptor('RC4'));
        $anotherCryptor = new FixedPasswordCryptor('passward', new Cryptor('RC4'));

        $encryptedA = $cryptor->encrypt('data');
        $encryptedB = $cryptor->encrypt('data');

        $this->assertSame('data', $cryptor->decrypt($encryptedA));
        $this->assertSame('data', $cryptor->decrypt($encryptedB));
        $this->assertSame($encryptedA, $encryptedB);

        $this->assertNotFalse($anotherCryptor->decrypt($encryptedA));
    }

    public function testInvalidIv(): void
    {
        $cryptor = new FixedPasswordCryptor('password');
        $this->assertFalse($cryptor->decrypt(''));

        try {
            $cryptor->mustDecrypt('');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame('', $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt', $e->getOriginalMessage());
        }
    }
}
