<?php

namespace Ukeloop\ImpersonatableGuard\Tests\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\Test;
use Ukeloop\ImpersonatableGuard\Events\ExitImpersonation;
use Ukeloop\ImpersonatableGuard\Events\Impersonate;
use Ukeloop\ImpersonatableGuard\Events\Impersonated;
use Ukeloop\ImpersonatableGuard\Guards\ImpersonatableSessionGuard;
use Ukeloop\ImpersonatableGuard\Tests\TestCase;

class ImpersonatableSessionGuardTest extends TestCase
{
    #[Test]
    public function it_can_impersonate(): void
    {
        Event::fake();

        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->assertGuest($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $impersonatableGuard->impersonate($user);

        $this->assertAuthenticatedAs($user, $guard);
        $this->assertTrue($impersonatableGuard->impersonated());
        $this->assertNull($impersonatableGuard->originalUser());

        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Authenticated::class);

        Event::assertDispatched(fn (Impersonate $e) => $e->guard === $guard && $user->is($e->user) && $e->originalUser === null);
        Event::assertNotDispatched(Impersonated::class);
        Event::assertNotDispatched(ExitImpersonation::class);
    }

    #[Test]
    public function it_can_impersonate_with_original_user(): void
    {
        Event::fake();

        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

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

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $impersonatableGuard->impersonate($user);

        $this->assertAuthenticatedAs($user, $guard);
        $this->assertTrue($impersonatableGuard->impersonated());
        $this->assertTrue($originalUser->is($impersonatableGuard->originalUser()));

        Event::assertNotDispatched(Login::class);
        Event::assertDispatched(fn (Authenticated $e) => $e->guard === $guard && $originalUser->is($e->user));

        Event::assertDispatched(fn (Impersonate $e) => $e->guard === $guard && $user->is($e->user) && $originalUser->is($e->originalUser));
        Event::assertDispatched(fn (Impersonated $e) => $e->guard === $guard && $originalUser->is($e->originalUser));
        Event::assertNotDispatched(ExitImpersonation::class);
    }

    #[Test]
    public function it_can_exit_impersonation(): void
    {
        Event::fake();

        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $impersonatableGuard->impersonate($user);

        $this->assertTrue($impersonatableGuard->impersonated());

        $impersonatableGuard->exitImpersonation();

        $this->assertFalse($impersonatableGuard->impersonated());
        $this->assertNull($impersonatableGuard->originalUser());
        $this->assertNull($impersonatableGuard->user());

        Event::assertNotDispatched(Login::class);

        Event::assertDispatched(fn (ExitImpersonation $e) => $e->guard === $guard && $user->is($e->user) && $e->originalUser === null);
    }

    #[Test]
    public function it_can_exit_impersonation_with_original_user(): void
    {
        Event::fake();

        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

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

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $this->be($originalUser, $guard);

        $impersonatableGuard->impersonate($user);

        $this->assertTrue($impersonatableGuard->impersonated());

        $impersonatableGuard->exitImpersonation();

        $this->assertFalse($impersonatableGuard->impersonated());
        $this->assertNull($impersonatableGuard->originalUser());
        $this->assertTrue($originalUser->is($impersonatableGuard->user()));

        Event::assertNotDispatched(Login::class);

        Event::assertDispatched(fn (ExitImpersonation $e) => $e->guard === $guard && $user->is($e->user) && $originalUser->is($e->originalUser));
    }

    #[Test]
    public function it_can_set_original_user(): void
    {
        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        /** @var User $user */
        $user = User::query()->forceCreate([
            'name' => 'user',
            'email' => 'user@localhost',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        ]);

        $this->assertNull($impersonatableGuard->originalUser());

        $impersonatableGuard->setOriginalUser($user);

        $this->assertTrue($user->is($impersonatableGuard->originalUser()));
    }

    #[Test]
    public function it_inherits_base_guard_session(): void
    {
        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $baseGuard = new SessionGuard(
            $guard,
            $impersonatableGuard->getProvider(),
            $impersonatableGuard->getSession(),
        );

        $this->assertSame($baseGuard->getName(), $impersonatableGuard->getName());
    }

    #[Test]
    public function it_inherits_base_guard_recaller(): void
    {
        $guard = 'testbentch';

        $impersonatableGuard = Auth::guard($guard);

        $this->assertInstanceOf(ImpersonatableSessionGuard::class, $impersonatableGuard);

        $baseGuard = new SessionGuard(
            $guard,
            $impersonatableGuard->getProvider(),
            $impersonatableGuard->getSession(),
        );

        $this->assertSame($baseGuard->getRecallerName(), $impersonatableGuard->getRecallerName());
    }
}
