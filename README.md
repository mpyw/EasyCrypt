EasyCrypt
=========

A class that provides you simple interface for **decryptable** encryption.  
Requires PHP 5.0.0 or later.

Usage
=====

```php
$raw_data = 'password1234';
$salt = 'This is vety secret key.';

$crypted_data = EasyCrypt::encrypt($raw_data, $salt);
$decrypted_data = EasyCrypt::decrypt($crypted_data, $salt);

echo $decrypted_data; // password1234
```
