<?php

use mpyw\EasyCrypt\Cryptor;

/**
 * @requires PHP 7.0
 */
class CoTest extends \Codeception\TestCase\Test
{
    public function testInvalidMethod()
    {
        $this->setExpectedException(\DomainException::class);
        $cryptor = new Cryptor('invalid');
    }

    public function testAes256()
    {
        $cryptor = new Cryptor;
        $encrypted_a = $cryptor->encrypt('data', 'password');
        $encrypted_b = $cryptor->encrypt('data', 'password');
        $this->assertNotEquals($encrypted_a, $encrypted_b);
        $this->assertEquals('data', $cryptor->decrypt($encrypted_a, 'password'));
        $this->assertEquals('data', $cryptor->decrypt($encrypted_b, 'password'));
        $this->assertFalse($cryptor->decrypt($encrypted_a, 'passward'));
    }

    public function testRc4()
    {
        $cryptor = new Cryptor('RC4');
        $encrypted_a = $cryptor->encrypt('data', 'password');
        $encrypted_b = $cryptor->encrypt('data', 'password');
        $this->assertEquals($encrypted_a, $encrypted_b);
        $this->assertEquals('data', $cryptor->decrypt($encrypted_a, 'password'));
    }

    public function testInvalidIv()
    {
        $cryptor = new Cryptor;
        $this->assertFalse($cryptor->decrypt('', 'password'));
    }

}
