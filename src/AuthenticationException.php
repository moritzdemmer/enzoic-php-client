<?php


namespace Enzoic;


class AuthenticationException extends \RuntimeException
{
    public function __construct(string $message = "", int $code = 401)
    {
        parent::__construct($message, $code);
    }
}