<?php

namespace Ukeloop\ImpersonatableGuard\Events;

use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Queue\SerializesModels;

class ExitImpersonation
{
    use SerializesModels;

    public function __construct(
        public string $guard,
        public ?AuthenticatableContract $user,
        public ?AuthenticatableContract $originalUser,
    ) {
    }
}
