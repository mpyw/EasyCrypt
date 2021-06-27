<?php

namespace Mpyw\EasyCrypt\Tests;

use Mpyw\EasyCrypt\Exceptions\DecryptionFailedException;
use Mpyw\EasyCrypt\FixedPasswordCryptor;
use Mpyw\EasyCrypt\HmacCryptor;
use PHPUnit\Framework\TestCase;

/**
 * Class HmacCryptorTest
 */
class HmacCryptorTest extends TestCase
{
    public function testWithoutHmacFailure(): void
    {
        $cryptor = new FixedPasswordCryptor('password');

        $encrypted = $cryptor->encrypt('data');
        $corrupted = "$encrypted$encrypted";
        $decrypted = $cryptor->decrypt($corrupted);

        $this->assertIsString($decrypted);
        $this->assertNotSame('data', $decrypted);
    }

    public function testWithHmacFailureOnDecryption(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        $encrypted = $cryptor->encrypt('data');
        $corrupted = "{$encrypted}{$encrypted}xxx";
        $decrypted = $cryptor->decrypt($corrupted);

        $this->assertFalse($decrypted);
    }

    public function testWithHmacFailureOnVerification(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        $encrypted = $cryptor->encrypt('data');
        $corrupted = "$encrypted$encrypted";
        $decrypted = $cryptor->decrypt($corrupted);

        $this->assertFalse($decrypted);
    }

    public function testWithHmacSuccess(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        $encrypted = $cryptor->encrypt('data');
        $decrypted = $cryptor->decrypt($encrypted);

        $this->assertIsString($decrypted);
        $this->assertSame('data', $decrypted);
    }

    /**
     * @throws \Mpyw\EasyCrypt\Exceptions\DecryptionFailedException
     */
    public function testMustDecryptWithHmacFailureOnDecryption(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        try {
            $encrypted = $cryptor->encrypt('data');
            $corrupted = "{$encrypted}{$encrypted}xxx";
            $cryptor->mustDecrypt($corrupted);
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame($corrupted, $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length', $e->getOriginalMessage());
        }
    }

    /**
     * @throws \Mpyw\EasyCrypt\Exceptions\DecryptionFailedException
     */
    public function testMustDecryptWithHmacFailureOnVerification(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        try {
            $encrypted = $cryptor->encrypt('data');
            $corrupted = "{$encrypted}{$encrypted}";
            $cryptor->mustDecrypt($corrupted);
            $this->assertTrue(false);
        } catch (DecryptionFailedException $e) {
            $this->assertSame($corrupted, $e->getData());
            $this->assertSame('Failed to decrypt.', $e->getMessage());
            $this->assertSame('HMAC digest does not match.', $e->getOriginalMessage());
        }
    }

    /**
     * @throws \Mpyw\EasyCrypt\Exceptions\DecryptionFailedException
     */
    public function testMustDecryptWithHmacSuccess(): void
    {
        $cryptor = new FixedPasswordCryptor('password', new HmacCryptor());

        $encrypted = $cryptor->encrypt('data');
        $decrypted = $cryptor->mustDecrypt($encrypted);

        $this->assertIsString($decrypted);
        $this->assertSame('data', $decrypted);
    }
}
