# Customizing Redirect URLs

## Customize Login Redirect

You can customize where a user is redirected to on login with the `loginRedirect()` method of the **app/Config/Auth.php** config file. This is handy if you want to redirect based on user group or other criteria.

```php
public function loginRedirect(): string
{
    $url = auth()->user()->inGroup('admin')
        ? '/admin'
        : shieldSetting('Auth.redirects')['login'];

    return $this->getUrl($url);
}
```

Oftentimes, you will want to have different redirects for different user groups. A simple example
might be that you want admins redirected to `/admin` while all other groups redirect to `/`.
The **app/Config/Auth.php** config file also includes methods that you can add additional logic to in order to
achieve this:

```php
public function loginRedirect(): string
{
    if (auth()->user()->can('admin.access')) {
        return '/admin';
    }

    $url = shieldSetting('Auth.redirects')['login'];

    return $this->getUrl($url);
}
```

## Customize Register Redirect

You can customize where a user is redirected to after registration in the `registerRedirect()` method of the **app/Config/Auth.php** config file.

```php
public function registerRedirect(): string
{
    $url = shieldSetting('Auth.redirects')['register'];

    return $this->getUrl($url);
}
```

## Customize Logout Redirect

The logout redirect can also be overridden by the `logoutRedirect()` method of the **app/Config/Auth.php** config file. This will not be used as often as login and register, but you might find the need. For example, if you programatically logged a user out you might want to take them to a page that specifies why they were logged out. Otherwise, you might take them to the home page or even the login page.

```php
public function logoutRedirect(): string
{
    $url = shieldSetting('Auth.redirects')['logout'];

    return $this->getUrl($url);
}
```
