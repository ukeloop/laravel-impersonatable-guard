<?php

namespace Ukeloop\ImpersonatableGuard\Tests\Middlewares;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\Test;
use Ukeloop\ImpersonatableGuard\Guards\ImpersonatableSessionGuard;
use Ukeloop\ImpersonatableGuard\Middlewares\EnsureNotImpersonating;
use Ukeloop\ImpersonatableGuard\Tests\TestCase;

class EnsureNotImpersonatingTest extends TestCase
{
    #[Test]
    public function it_ensure_guest_is_not_impersonation(): void
    {
        $guard = 'testbentch';

        $this->assertGuest($guard);

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $this->assertFalse($impersonatableGuard->impersonated());

        $middleware = new EnsureNotImpersonating();

        $middleware->handle(new Request, function () {
            $this->assertTrue(true);
        }, $guard);
    }

    #[Test]
    public function it_ensure_user_is_not_impersonation(): void
    {
        $guard = 'testbentch';

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->be($user, $guard);

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $this->assertFalse($impersonatableGuard->impersonated());

        $middleware = new EnsureNotImpersonating();

        $middleware->handle(new Request, function () {
            $this->assertTrue(true);
        }, $guard);
    }

    #[Test]
    public function it_protect_impersonation(): void
    {
        $guard = 'testbentch';

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->assertGuest($guard);

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $impersonatableGuard->impersonate($user);

        $this->assertTrue($impersonatableGuard->impersonated());

        $middleware = new EnsureNotImpersonating();

        $this->expectException(AuthorizationException::class);

        $middleware->handle(new Request, function () {
            $this->fail();
        }, $guard);
    }

    #[Test]
    public function it_protect_impersonation_with_originalUser(): void
    {
        $guard = 'testbentch';

        /** @var User $originalUser */
        $originalUser = User::query()->forceCreate([
            'name' => 'original-user',
            'email' => 'original-user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->assertFalse($originalUser->is($user));
        $this->be($originalUser, $guard);

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $impersonatableGuard->impersonate($user);

        $this->assertTrue($impersonatableGuard->impersonated());

        $middleware = new EnsureNotImpersonating();

        $this->expectException(AuthorizationException::class);

        $middleware->handle(
            new Request,
            function () {
                $this->fail();
            },
            $guard
        );
    }
}
