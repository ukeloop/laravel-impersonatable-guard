<?php

namespace Ukeloop\ImpersonatableGuard\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Auth\User;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use Ukeloop\ImpersonatableGuard\ImpersonatableGuardServiceProvider;

/**
 * @internal
 *
 * @coversNothing
 */
abstract class TestCase extends TestbenchTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(__DIR__.'/migrations');

        $this->artisan('migrate', ['--database' => 'testbench'])->run();
    }

    /**
     * @override
     *
     * {@inheritdoc}
     */
    protected function getPackageProviders($app): array
    {
        return [
            ImpersonatableGuardServiceProvider::class,
        ];
    }

    /**
     * @override
     *
     * {@inheritdoc}
     */
    protected function defineEnvironment($app): void
    {
        tap($app['config'], function (Repository $config) {
            // Setup default database to use sqlite :memory:
            $config->set('database.default', 'testbench');
            $config->set('database.connections.testbench', [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ]);

            // Setup queue database connections.
            $config->set([
                'queue.batching.database' => 'testbench',
                'queue.failed.database' => 'testbench',
            ]);

            $config->set('auth.guards.testbentch', [
                'driver' => 'impersonatable.session',
                'provider' => 'users',
            ]);

            $config->set('auth.providers.users', [
                'driver' => 'eloquent',
                'model' => User::class,
            ]);
        });
    }
}
