<?php

namespace Mpyw\EasyCrypt\Tests;

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

    public function testAes256Gcm(): void
    {
        $cryptor = new Cryptor('aes-256-gcm');

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

    public function testInvalidIvLength(): void
    {
        $cryptor = new Cryptor();
        $this->assertFalse($cryptor->decrypt('', 'password'));

        try {
            $cryptor->mustDecrypt('', 'password');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame('', $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid iv length.', $e->getOriginalMessage());
        }
    }

    public function testInvalidTagLength(): void
    {
        $cryptor = new Cryptor('aes-256-gcm');
        $this->assertFalse($cryptor->decrypt(str_repeat('x', 16), 'password'));

        try {
            $cryptor->mustDecrypt(str_repeat('x', 16), 'password');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame(str_repeat('x', 16), $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid tag length.', $e->getOriginalMessage());
        }
    }

    public function testInvalidTagContent(): void
    {
        $cryptor = new Cryptor('aes-256-gcm');

        $corrupted = substr_replace(
            $cryptor->encrypt('', 'password'),
            str_repeat('x', 16),
            -16
        );

        $this->assertFalse($cryptor->decrypt($corrupted, 'password'));

        try {
            $cryptor->mustDecrypt($corrupted, 'password');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame($corrupted, $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid tag content.', $e->getOriginalMessage());
        }
    }
}
