# EasyCrypt ![Build Status](https://github.com/mpyw/EasyCrypt/actions/workflows/test.yml/badge.svg?branch=master) [![Coverage Status](https://coveralls.io/repos/github/mpyw/EasyCrypt/badge.svg?branch=master)](https://coveralls.io/github/mpyw/EasyCrypt?branch=master) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mpyw/EasyCrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mpyw/EasyCrypt/?branch=master)

A class that provides simple interface for **decryptable** encryption.

## Requirements

- PHP: `^7.1 || ^8.0`

## Installing

```
composer require mpyw/easycrypt
```

## Usage

### Basic

```php
<?php

use Mpyw\EasyCrypt\Cryptor;

$cryptor = new Cryptor;

$secretData = '[Secret Data]';
$password = '[Password]';

$encrypted = $cryptor->encrypt($secretData, $password);
$decrypted = $cryptor->decrypt($encrypted, $password); // String on success, false on failure.

var_dump($secretData === $decrypted); // bool(true)
```

### Throw `DecryptionFailedException` when decryption failed

It throws `DecryptionFailedException` instead of returning false.

```php
$decrypted = $cryptor->mustDecrypt($encrypted, $password);
```

### Use fixed password

You can use `FixedPasswordCryptor` instead of raw `Cryptor`.
This is useful when we use a fixed password from an application config.

```php
<?php

use Mpyw\EasyCrypt\FixedPasswordCryptor;

$cryptor = new FixedPasswordCryptor('[Password]');

$secretData = '[Secret Data]';

$encrypted = $cryptor->encrypt($secretData);
$decrypted = $cryptor->decrypt($encrypted); // String on success, false on failure.

var_dump($secretData === $decrypted); // bool(true)
```
