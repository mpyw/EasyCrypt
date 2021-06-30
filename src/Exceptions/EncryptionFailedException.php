<?php

namespace Mpyw\EasyCrypt\Exceptions;

use Throwable;
use UnexpectedValueException;

/**
 * @codeCoverageIgnore
 */
class EncryptionFailedException extends UnexpectedValueException implements EasyCryptException
{
    use Concerns\HasOriginalMessage;

    /**
     * EncryptionFailedException constructor.
     *
     * @param string          $message
     * @param null|\Throwable $previous
     */
    public function __construct(string $message, Throwable $previous = null)
    {
        $this->originalMessage = $message;

        parent::__construct('Failed to encrypt.', 0, $previous);
    }
}
