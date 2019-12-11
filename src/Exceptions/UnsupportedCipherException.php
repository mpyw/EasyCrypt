<?php

namespace Mpyw\EasyCrypt\Exceptions;

use DomainException;
use Throwable;

class UnsupportedCipherException extends DomainException implements EasyCryptException
{
    /**
     * UnsupportedCipherException constructor.
     *
     * @param string          $cipher
     * @param null|\Throwable $previous
     */
    public function __construct(string $cipher, Throwable $previous = null)
    {
        parent::__construct("Unsupported cipher method: $cipher", 0, $previous);
    }
}
