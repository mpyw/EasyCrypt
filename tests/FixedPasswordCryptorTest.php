<?php

namespace Mpyw\EasyCrypt\Tests;

use Mpyw\EasyCrypt\Cryptor;
use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
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
        $cryptor = new FixedPasswordCryptor('password', new Cryptor('rc4'));
        $anotherCryptor = new FixedPasswordCryptor('passward', new Cryptor('rc4'));

        $encryptedA = $cryptor->encrypt('data');
        $encryptedB = $cryptor->encrypt('data');

        $this->assertSame('data', $cryptor->decrypt($encryptedA));
        $this->assertSame('data', $cryptor->decrypt($encryptedB));
        $this->assertSame($encryptedA, $encryptedB);

        $this->assertNotFalse($anotherCryptor->decrypt($encryptedA));
    }

    public function testInvalidIvLength(): void
    {
        $cryptor = new FixedPasswordCryptor('password');
        $this->assertFalse($cryptor->decrypt(''));

        try {
            $cryptor->mustDecrypt('');
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame('', $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid iv length.', $e->getOriginalMessage());
        }
    }

    public function testInvalidTagLength(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new Cryptor('aes-256-gcm'));
        $this->assertFalse($cryptor->decrypt(str_repeat('x', 16)));

        try {
            $cryptor->mustDecrypt(str_repeat('x', 16));
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame(str_repeat('x', 16), $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid tag length.', $e->getOriginalMessage());
        }
    }

    public function testInvalidTagContent(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new Cryptor('aes-256-gcm'));

        $corrupted = substr_replace(
            $cryptor->encrypt(''),
            str_repeat('x', 16),
            -16
        );

        $this->assertFalse($cryptor->decrypt($corrupted));

        try {
            $cryptor->mustDecrypt($corrupted);
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame($corrupted, $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('invalid tag content.', $e->getOriginalMessage());
        }
    }
}
