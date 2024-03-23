<?php

namespace Ukeloop\ImpersonatableGuard\Events;

use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Queue\SerializesModels;

class Impersonated
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public AuthenticatableContract $originalUser,
    ) {
    }
}
