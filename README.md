# Laravel Impersonatable Guard

This is a guard implementation in Laravel for handling user impersonation. It extends Laravel's `SessionGuard` and provides additional methods for impersonation-related functionality.

User impersonation is a feature that enables an administrator or privileged user to temporarily assume the identity of another user within the application. This capability proves valuable for troubleshooting, testing user-specific features, or providing support.

Moreover, It supports multiple authentication guards. For example, admin guard users can also impersonate web guard users.

## Security Considerations

User impersonation should be used with caution, especially in production environments. It's important to properly authenticate and authorize users before allowing them to impersonate others. Additionally, sensitive actions or pages should be protected from access while in impersonation mode to prevent unauthorized use.

## Installation

You can install this package via Composer:

```bash
composer require ukeloop/laravel-impersonatable-guard
```

## Configuration

Update your authentication configuration to use the `ImpersonatableSessionGuard` instead of Laravel's default `SessionGuard`. You need to replace the driver from `session` to `impersonatable.session`:

```php
// config/auth.php

'guards' => [
    'web' => [
        'driver' => 'impersonatable.session',
        'provider' => 'users',
    ],
],
```

## Usage

### Impersonate Users

Start impersonating the specified user. This method takes an instance of `Illuminate\Contracts\Auth\Authenticatable` representing the user to impersonate.

```php
Auth::guard('web')->impersonate($user);
```

### Once Impersonate Users

Temporarily impersonate the specified user for a single request. This method is useful for actions that need to be performed as another user without permanently switching the user context.

```php
Auth::guard('web')->onceImpersonate($user);
```

### Exit Impersonation

Stop impersonating the current user and return to the original user context.

```php
Auth::guard('web')->exitImpersonation();
```

### Get Original User

Get the original user that was being impersonated.

```php
$originalUser = Auth::guard('web')->originalUser();
```

### Check Currently impersonated state

Check if the guard is currently in an impersonated state.

```php
$isImpersonated = Auth::guard('web')->impersonated();
```

## Protect Impersonation With Middleware

You can use the middleware `impersonation.protect` to protect your routes against user impersonation. This middleware ensures that users cannot access certain routes while impersonating another user.

```php
Route::get('/protect-form-impersonation', 'ExampleController@handleImportantRequest')->middleware('impersonation.protect');
```

Protect with specified guards:

```php
Route::get('/protect-form-impersonation', 'ExampleController@handleImportantRequest')->middleware('impersonation.protect:specified-guard');
```

## Example Impersonation Controller

Example controller for impersonating users:

```php
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use RuntimeException;
use Ukeloop\ImpersonatableGuard\Contracts\ImpersonatableGuard;

class ImpersonationController extends Controller
{
    /**
     * Start impersonating the specified user.
     */
    public function impersonate(User $user): RedirectResponse 
    {
        $guard = Auth::guard('web');

        if (!$guard instanceof ImpersonatableGuard) {
            throw new RuntimeException('This guard is not allowed to impersonate.');
        }

        $guard->impersonate($user);

        return redirect('/');
    }

    /**
     * Stop impersonating the current user and return to the original user context.
     */
    public function exit(): RedirectResponse 
    {
        $guard = Auth::guard('web');

        if (!$guard instanceof ImpersonatableGuard) {
            throw new RuntimeException('This guard is not allowed to impersonate.');
        }

        $guard->exitImpersonation();

        return redirect('/');
    }
}
```

## Custom Impersonate Guard

You can create custom impersonate guards by implementing `Ukeloop\ImpersonatableGuard\Contracts\ImpersonatableGuard`.

```php
use Ukeloop\ImpersonatableGuard\Contracts\ImpersonatableGuard;

class CustomImpersonateGuard implements ImpersonatableGuard 
{
    // Define your own logic
}
```
