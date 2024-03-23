<?php

namespace Ukeloop\ImpersonatableGuard\Middlewares;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Ukeloop\ImpersonatableGuard\Contracts\ImpersonatableGuard;

class EnsureNotImpersonating
{
    public static function using(string $guard, string ...$others): string
    {
        return static::class.':'.implode(',', [$guard, ...$others]);
    }

    /**
     * @throws AuthorizationException
     */
    public function handle(Request $request, Closure $next, string ...$guards): mixed
    {
        $guards = empty($guards) ? [null] : $guards;

        foreach ($guards as $guardName) {
            $guard = Auth::guard($guardName);

            if ($guard instanceof ImpersonatableGuard && $guard->impersonated()) {
                throw new AuthorizationException('Cannot perform this action while impersonating another user.');
            }
        }

        return $next($request);
    }
}
