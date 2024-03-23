<?php

namespace Ukeloop\ImpersonatableGuard\Contracts;

use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\StatefulGuard;

interface ImpersonatableGuard extends StatefulGuard
{
    public function impersonate(AuthenticatableContract $user): void;

    public function onceImpersonate(AuthenticatableContract $user): void;

    public function exitImpersonation(): void;

    public function originalUser(): ?AuthenticatableContract;

    public function impersonated(): bool;
}
