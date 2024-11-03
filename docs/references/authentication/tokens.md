# Access Token Authenticator

The Access Token authenticator supports the use of revoke-able API tokens without using OAuth. These are commonly
used to provide third-party developers access to your API. These tokens typically have a very long
expiration time, often years.

These are also suitable for use with mobile applications. In this case, the user would register/sign-in
with their email/password. The application would create a new access token for them, with a recognizable
name, like John's iPhone 12, and return it to the mobile application, where it is stored and used
in all future requests.

## Access Token/API Authentication

Using access tokens requires that you either use/extend `CodeIgniter\Shield\Models\UserModel` or
use the `CodeIgniter\Shield\Authentication\Traits\HasAccessTokens` on your own user model. This trait
provides all of the custom methods needed to implement access tokens in your application. The necessary
database table, `auth_identities`, is created in Shield's only migration class, which must be run
before first using any of the features of Shield.

## Generating Access Tokens

Access tokens are created through the `generateAccessToken()` method on the user. This takes a name to
give to the token as the first argument. The name is used to display it to the user so they can
differentiate between multiple tokens.

```php
$token = $user->generateAccessToken('Work Laptop');
```

This creates the token using a cryptographically secure random string. The token
is hashed (sha256) before saving it to the database. The method returns an instance of
`CodeIgniters\Shield\Authentication\Entities\AccessToken`. The only time a plain text
version of the token is available is in the `AccessToken` returned immediately after creation.

**The plain text version should be displayed to the user immediately so they can copy it for
their use.** If a user loses it, they cannot see the raw version anymore, but they can generate
a new token to use.

```php
$token = $user->generateAccessToken('Work Laptop');

// Only available immediately after creation.
echo $token->raw_token;
```

## Revoking Access Tokens

Access tokens can be revoked through the `revokeAccessToken()` method. This takes the plain-text
access token as the only argument. Revoking simply deletes the record from the database.

```php
$user->revokeAccessToken($token);
```

Typically, the plain text token is retrieved from the request's headers as part of the authentication
process. If you need to revoke the token for another user as an admin, and don't have access to the
token, you would need to get the user's access tokens and delete them manually.

If you don't have the raw token usable to remove the token there is the possibility to remove it using the tokens secret thats stored in the database. It's possible to get a list of all tokens with there secret using the `accessTokens()` function.

```php
$user->revokeAccessTokenBySecret($secret);
```

You can revoke all access tokens with the `revokeAllAccessTokens()` method.

```php
$user->revokeAllAccessTokens();
```

## Retrieving Access Tokens

The following methods are available to help you retrieve a user's access tokens:

```php
// Retrieve a single token by plain text token
$token = $user->getAccessToken($rawToken);

// Retrieve a single token by it's database ID
$token = $user->getAccessTokenById($id);

// Retrieve all access tokens as an array of AccessToken instances.
$tokens = $user->accessTokens();
```

## Access Token Scopes

Each token can be given one or more scopes they can be used within. These can be thought of as
permissions the token grants to the user. Scopes are provided when the token is generated and
cannot be modified afterword.

```php
$token = $user->generateAccessToken('Work Laptop', ['posts.manage', 'forums.manage']);
```

By default a user is granted a wildcard scope which provides access to all scopes. This is the
same as:

```php
$token = $user->generateAccessToken('Work Laptop', ['*']);
```

During authentication, the token the user used is stored on the user. Once authenticated, you
can use the `tokenCan()` and `tokenCant()` methods on the user to determine if they have access
to the specified scope.

```php
if ($user->tokenCan('posts.manage')) {
    // do something....
}

if ($user->tokenCant('forums.manage')) {
    // do something....
}
```

## Configuration

Configure **app/Config/AuthToken.php** for your needs.

!!! note

    Shield does not expect you use the Access Token Authenticator and HMAC Authenticator
    at the same time. Therefore, some Config items are common.

### Access Token Lifetime

Tokens will expire after a specified amount of time has passed since they last have been used.

By default, this is set to 1 year.
You can change this value by setting the `$unusedTokenLifetime` value. This is
in seconds so that you can use the
[time constants](https://codeigniter.com/user_guide/general/common_functions.html#time-constants)
that CodeIgniter provides.

```php
public $unusedTokenLifetime = YEAR;
```


## Expiring Access Tokens

By default, the Access Tokens don't expire unless they meet the Access Token lifetime expiration after their last used date.

Access Tokens can be set to expire through the `generateAccessToken()` method. This takes the expiration date as the $expiresAt argument. It's also possible to update an existing HMAC key using `setAccessTokenById($HmacTokenID, $expiresAt)`

`$expiresAt` Accepts DateTime string formatted as 'Y-m-d h:i:s' or [DateTime relative formats](https://www.php.net/manual/en/datetime.formats.php#datetime.formats.relative) unit symbols (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'

```php
// Expiration date = 2024-11-03 12:00:00
$token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

// Expiration date = 2024-11-15 00:00:00
$user->setAccessTokenExpirationById($token->id, '2024-11-15 00:00:00');

// Or Expiration date = now() + 1 month + 15 days
$user->setAccessTokenExpirationById($token->id, '1 month 15 days');
```

The following support methods are also available:

`hasAccessTokenExpired(AccessToken $accessToken)` - Checks if the given Access Token has expired. Returns `true` if the Access Token has expired, `false` if not, and `null` if the expire date is not set.

```php
$token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

$this->user->hasAccessTokenExpired($token); // Returns true
```

`getAccessTokenTimeToExpire(AccessToken $accessToken, string $format = "date" | "human")` - Checks if the given Access Token has expired. Returns `true` if Access Token has expired, `false` if not, and `null` if the expire date is null.

```php
$token = $this->user->generateAccessToken('foo', ['foo:bar']);

$this->user->getAccessTokenTimeToExpire($token, 'date'); // Returns null

// Assuming current time is: 2024-11-04 20:00:00
$token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

$this->user->getAccessTokenTimeToExpire($token, 'date'); // 2024-11-03 12:00:00
$this->user->getAccessTokenTimeToExpire($token, 'human'); // 1 day ago

$token = $this->user->generateAccessToken('foo', ['foo:bar'], '2026-01-06 12:00:00');
$this->user->getAccessTokenTimeToExpire($token, 'human'); // in 1 year
```

### Access Token Expiration vs Lifetime
Expiration and Lifetime are different concepts. The lifetime is the maximum time allowed for the token to exist since its last use. Token expiration, on the other hand, is a set date in which the Access Token will cease to function.

### Login Attempt Logging

By default, only failed login attempts are recorded in the `auth_token_logins` table.

This can be modified by changing the `$recordLoginAttempt` value.

```php
public int $recordLoginAttempt = Auth::RECORD_LOGIN_ATTEMPT_FAILURE;
```

If you don't want any logs, set it to `Auth::RECORD_LOGIN_ATTEMPT_NONE`.

If you want to log all login attempts, set it to `Auth::RECORD_LOGIN_ATTEMPT_ALL`.
It means you log all requests.

## Logging

Login attempts are recorded in the `auth_token_logins` table, according to the
configuration above.

When a failed login attempt is logged, the raw token value sent is saved in
the `identifier` column.

When a successful login attempt is logged, the token name is saved in the
`identifier` column.
