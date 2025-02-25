<?php

namespace Ukeloop\ImpersonatableGuard;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Support\ServiceProvider;
use Ukeloop\ImpersonatableGuard\Guards\ImpersonatableSessionGuard;
use Ukeloop\ImpersonatableGuard\Middlewares\EnsureNotImpersonating;

class ImpersonatableGuardServiceProvider extends ServiceProvider
{
    /**
     * @throws BindingResolutionException
     */
    public function boot(): void
    {
        $this->configureGuard();
        $this->configureMiddleware();
    }

    /**
     * @throws BindingResolutionException
     */
    protected function configureGuard(): void
    {
        $this->app->make('auth')->extend('impersonatable.session', function ($app, $name, $config): ImpersonatableSessionGuard {
            $guard = new ImpersonatableSessionGuard(
                $name,
                $app['auth']->createUserProvider($config['provider'] ?? null),
                $app['session.store'],
                rehashOnLogin: $app['config']->get('hashing.rehash_on_login', true),
            );

            // @phpstan-ignore function.alreadyNarrowedType
            if (method_exists($guard, 'setCookieJar')) {
                $guard->setCookieJar($app['cookie']);
            }

            // @phpstan-ignore function.alreadyNarrowedType
            if (method_exists($guard, 'setDispatcher')) {
                $guard->setDispatcher($app['events']);
            }

            // @phpstan-ignore function.alreadyNarrowedType
            if (method_exists($guard, 'setRequest')) {
                $guard->setRequest($app->refresh('request', $guard, 'setRequest'));
            }

            if (isset($config['remember'])) {
                $guard->setRememberDuration($config['remember']);
            }

            return $guard;
        });
    }

    /**
     * @throws BindingResolutionException
     */
    protected function configureMiddleware(): void
    {
        $this->app->make('router')->aliasMiddleware('impersonation.protect', EnsureNotImpersonating::class);
    }
}
