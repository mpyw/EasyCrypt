<?php

namespace Mpyw\EasyCrypt\IvGenerator;

interface IvGeneratorInterface
{
    /**
     * Generate new iv/counter value.
     *
     * @param  int    $length
     * @return string
     */
    public function generate(int $length): string;
}
