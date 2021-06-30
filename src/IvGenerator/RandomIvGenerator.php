<?php

namespace Mpyw\EasyCrypt\IvGenerator;

class RandomIvGenerator implements IvGeneratorInterface
{
    /**
     * Generate new iv/counter value.
     *
     * @param  int    $length
     * @return string
     */
    public function generate(int $length): string
    {
        if ($length < 1) {
            return '';
        }

        do {
            $data = openssl_random_pseudo_bytes($length, $secure);
        } while (!$secure);

        return $data;
    }
}
