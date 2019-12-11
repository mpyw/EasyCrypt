<?php

namespace Mpyw\EasyCrypt\Exceptions;

use Exception;
use Throwable;

class DecryptionFailedException extends Exception implements EasyCryptException
{
    use Concerns\HasOriginalMessage;

    /**
     * @var string
     */
    protected $data;

    /**
     * DecryptionFailedException constructor.
     *
     * @param string          $originalMessage
     * @param string          $data
     * @param null|\Throwable $previous
     */
    public function __construct(string $originalMessage, string $data, Throwable $previous = null)
    {
        $this->data = $data;
        $this->originalMessage = $originalMessage;

        parent::__construct('Failed to decrypt.', 0, $previous);
    }

    /**
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }
}
