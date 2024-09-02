<?php

namespace Ukeloop\ImpersonatableGuard\Guards;

use Illuminate\Auth\SessionGuard as BaseSessionGuard;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Events\Dispatcher;
use Ukeloop\ImpersonatableGuard\Contracts\ImpersonatableGuard;
use Ukeloop\ImpersonatableGuard\Events\ExitImpersonation;
use Ukeloop\ImpersonatableGuard\Events\Impersonate;
use Ukeloop\ImpersonatableGuard\Events\Impersonated;

/**
 * @property ?Dispatcher $events
 */
class ImpersonatableSessionGuard extends BaseSessionGuard implements ImpersonatableGuard
{
    protected ?AuthenticatableContract $originalUser = null;

    public function impersonate(AuthenticatableContract $user): void
    {
        $originalUser = $this->impersonated() ? $this->originalUser() : $this->user();

        $this->updateImpersonateSession($originalUser?->getAuthIdentifier());

        $this->quiet(fn () => $this->login($user));

        $this->fireImpersonateEvent(user: $user, originalUser: $originalUser);

        $this->setOriginalUser($originalUser);
    }

    public function onceImpersonate(AuthenticatableContract $user): void
    {
        $originalUser = $this->impersonated() ? $this->originalUser() : $this->user();

        $this->setOriginalUser($originalUser);

        $this->setUser($user);
    }

    public function exitImpersonation(): void
    {
        $originalUser = $this->originalUser();
        $impersonatedUser = $this->user();

        $this->clearOriginalUserDataFromStorage();

        if (! is_null($originalUser)) {
            $this->quiet(fn () => $this->login($originalUser));
        } else {
            $this->quiet(fn () => $this->logout());
        }

        $this->fireExitImpersonationEvent(user: $impersonatedUser, originalUser: $originalUser);

        $this->originalUser = null;
    }

    protected function updateImpersonateSession(mixed $id): void
    {
        $this->session->put($this->getOriginalUserName(), $id);

        $this->session->migrate(true);
    }

    public function setOriginalUser(?AuthenticatableContract $originalUser): static
    {
        $this->originalUser = $originalUser;

        if ($this->originalUser) {
            $this->fireImpersonatedEvent(originalUser: $this->originalUser);
        }

        return $this;
    }

    public function originalUser(): ?AuthenticatableContract
    {
        if (! is_null($this->originalUser)) {
            return $this->originalUser;
        }

        if (! $this->impersonated()) {
            return null;
        }

        $id = $this->session->get($this->getOriginalUserName());

        if (! is_null($id) && $this->originalUser = $this->getProvider()->retrieveById($id)) {
            $this->fireImpersonatedEvent(originalUser: $this->originalUser);
        }

        return $this->originalUser;
    }

    public function impersonated(): bool
    {
        return $this->session->exists($this->getOriginalUserName());
    }

    /**
     * @override
     *
     * {@inheritdoc}
     */
    protected function clearUserDataFromStorage()
    {
        $this->clearOriginalUserDataFromStorage();

        parent::clearUserDataFromStorage();
    }

    protected function clearOriginalUserDataFromStorage(): void
    {
        $this->session->remove($this->getOriginalUserName());
    }

    protected function fireImpersonateEvent(AuthenticatableContract $user, ?AuthenticatableContract $originalUser): void
    {
        $this->events?->dispatch(
            new Impersonate(
                guard: $this->name,
                user: $user,
                originalUser: $originalUser,
            )
        );
    }

    protected function fireExitImpersonationEvent(?AuthenticatableContract $user, ?AuthenticatableContract $originalUser): void
    {
        $this->events?->dispatch(
            new ExitImpersonation(
                guard: $this->name,
                user: $user,
                originalUser: $originalUser,
            )
        );
    }

    protected function fireImpersonatedEvent(AuthenticatableContract $originalUser): void
    {
        $this->events?->dispatch(
            new Impersonated(
                guard: $this->name,
                originalUser: $originalUser,
            )
        );
    }

    protected function quiet(callable $callback): void
    {
        if (isset($this->events)) {
            $events = $this->events;
            $this->events = null;
        }

        $callback();

        if (isset($events)) {
            $this->events = $events;
        }
    }

    public function getOriginalUserName(): string
    {
        return 'impersonation_'.$this->name.'_'.sha1(static::class);
    }

    /**
     * @override
     *
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'login_'.$this->name.'_'.sha1(BaseSessionGuard::class);
    }

    /**
     * @override
     *
     * {@inheritdoc}
     */
    public function getRecallerName()
    {
        return 'remember_'.$this->name.'_'.sha1(BaseSessionGuard::class);
    }

    /**
     * Set the rehashOnLogin property for Laravel 11 and above.
     */
    public function setRehashOnLogin(bool $rehashOnLogin): void
    {
        if (property_exists($this, 'rehashOnLogin')) {
            $this->rehashOnLogin = $rehashOnLogin;
        }
    }
}
