<?php

namespace Mpyw\EasyCrypt\Exceptions\Concerns;

trait HasOriginalMessage
{
    /**
     * @var string
     */
    protected $originalMessage;

    /**
     * @return string
     */
    public function getOriginalMessage(): string
    {
        return $this->originalMessage;
    }
}
