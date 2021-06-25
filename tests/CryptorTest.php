<?php

namespace Tests;

use Mpyw\EasyCrypt\Cryptor;
use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\Exceptions\UnsupportedCipherException;
use PHPUnit\Framework\TestCase;

/**
 * Class CryptorTest
 */
class CryptorTest extends TestCase
{
    public function testInvalidMethod(): void
    {
        $this->expectException(UnsupportedCipherException::class);
        new Cryptor('invalid');
    }

    public function testAes256(): void
    {
        $cryptor = new Cryptor();

        $encryptedA = $cryptor->encrypt('data', 'password');
        $encryptedB = $cryptor->encrypt('data', 'password');

        $this->assertSame('data', $cryptor->decrypt($encryptedA, 'password'));
        $this->assertSame('data', $cryptor->decrypt($encryptedB, 'password'));
        $this->assertNotSame($encryptedA, $encryptedB);

        $this->assertFalse($cryptor->decrypt($encryptedA, 'passward'));
    }

    public function testRc4(): void
    {
        $cryptor = new Cryptor('rc4');

        $encryptedA = $cryptor->encrypt('data', 'password');
        $encryptedB = $cryptor->encrypt('data', 'password');

        $this->assertSame('data', $cryptor->decrypt($encryptedA, 'password'));
        $this->assertSame('data', $cryptor->decrypt($encryptedB, 'password'));
        $this->assertSame($encryptedA, $encryptedB);

        $this->assertNotFalse($cryptor->decrypt($encryptedA, 'passward'));
    }

    public function testInvalidIv(): void
    {
        $cryptor = new Cryptor();
        $this->assertFalse($cryptor->decrypt('', 'password'));

        try {
            $cryptor->mustDecrypt('', 'password');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame('', $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt', $e->getOriginalMessage());
        }
    }
}
