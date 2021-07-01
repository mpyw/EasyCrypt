<?php

namespace Mpyw\EasyCrypt\OpenSSL;

class EncryptionResult
{
    /**
     * @var string
     */
    public $data;

    /**
     * @var null|string
     */
    public $tag;

    /**
     * EncryptionResult constructor.
     *
     * @param string      $data
     * @param null|string $tag
     */
    public function __construct(string $data, ?string $tag)
    {
        $this->data = $data;
        $this->tag = $tag;
    }
}
