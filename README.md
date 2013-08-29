EasyCrypt
=========

EasyCrypt provides simple interface for decryptable encryption.

Usage
=====

```php
<?php
$raw_data = 'password1234';
$salt = 'This is vety secret key.';
$crypted_data = EasyCrypt::encrypt($raw_data, $salt);
$decrypted_data = EasyCrypt::decrypt($crypted_data, $salt);
echo $decrypted_data; // password1234
```
