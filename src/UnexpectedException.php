<?php


namespace Enzoic;


class UnexpectedException extends \RuntimeException
{
    public function __construct(string $message = "", int $code = 500)
    {
        parent::__construct($message, $code);
    }
}