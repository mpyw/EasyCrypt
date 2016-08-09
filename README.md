# EasyCrypt [![Build Status](https://travis-ci.org/mpyw/EasyCrypt.svg?branch=master)](https://travis-ci.org/mpyw/EasyCrypt) [![Coverage Status](https://coveralls.io/repos/github/mpyw/EasyCrypt/badge.svg?branch=master)](https://coveralls.io/github/mpyw/EasyCrypt?branch=master) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mpyw/EasyCrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mpyw/EasyCrypt/?branch=master)

A class that provides simple interface for **decryptable** encryption.  

## Installing

```
composer install mpyw/easycrypt:^3.0
```

## Usage

```php
<?php

require 'vendor/autoload.php';
use mpyw\EasyCrypt\Cryptor;

$cryptor = new Cryptor;

$secret_data = '[Secret Data]';
$password = '[Password]';

$encrypted = $cryptor->encrypt($secret_data, $password);
$decrypted = $cryptor->decrypt($enctypred, $password);

var_dump($secret_data === $decrypted); // bool(true)
```
