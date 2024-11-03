# HMAC SHA256 Token Authenticator

The HMAC-SHA256 authenticator supports the use of revocable API keys without using OAuth. This provides
an alternative to a token that is passed in every request and instead uses a shared secret that is used to sign
the request in a secure manner. Like authorization tokens, these are commonly used to provide third-party developers
access to your API. These keys typically have a very long expiration time, often years.

These are also suitable for use with mobile applications. In this case, the user would register/sign-in
with their email/password. The application would create a new access token for them, with a recognizable
name, like "John's iPhone 12", and return it to the mobile application, where it is stored and used
in all future requests.

!!! note

    For the purpose of this documentation, and to maintain a level of consistency with the Authorization Tokens,
    the term "Token" will be used to represent a set of API Keys (key and secretKey).

## Usage

In order to use HMAC Keys/Token the `Authorization` header will be set to the following in the request:

```
Authorization: HMAC-SHA256 <key>:<HMAC-HASH-of-request-body>
```

The code to do this will look something like this:

```php
header("Authorization: HMAC-SHA256 {$key}:" . hash_hmac('sha256', $requestBody, $secretKey));
```

Using the CodeIgniter CURLRequest class:

```php
<?php

$client = \Config\Services::curlrequest();

$key = 'a6c460151b4cabbe1c1d73e08915ce8e';
$secretKey = '56c85232f0e5b55c05015476cd132c8d';
$requestBody = '{"name":"John","email":"john@example.com"}';

// $hashValue = b22b0ec11ad61cd4488ab1a09c8a0317e896c22adcc5754ea4cfd0f903a0f8c2
$hashValue = hash_hmac('sha256', $requestBody, $secretKey);

$response = $client->setHeader('Authorization', "HMAC-SHA256 {$key}:{$hashValue}")
    ->setBody($requestBody)
    ->request('POST', 'https://example.com/api');
```

## HMAC Keys/API Authentication

Using HMAC keys requires that you either use/extend `CodeIgniter\Shield\Models\UserModel` or
use the `CodeIgniter\Shield\Authentication\Traits\HasHmacTokens` on your own user model. This trait
provides all the custom methods needed to implement HMAC keys in your application. The necessary
database table, `auth_identities`, is created in Shield's only migration class, which must be run
before first using any of the features of Shield.

## Generating HMAC Access Keys

Access keys/tokens are created through the `generateHmacToken()` method on the user. This takes a name to
give to the token as the first argument. The name is used to display it to the user, so they can
differentiate between multiple tokens.

```php
$token = $user->generateHmacToken('Work Laptop');
```

This creates the keys/tokens using a cryptographically secure random string. The keys operate as shared keys.
The '**key**' is stored as plain text in the database, the '**secretKey**' is stored encrypted. The method returns an
instance of `CodeIgniters\Shield\Authentication\Entities\AccessToken`. The field `secret` is the '**key**' the field
`rawSecretKey` is the shared '**secretKey**'. Both are required to when using this authentication method.

**The plain text version of these keys should be displayed to the user immediately, so they can copy it for
their use.** It is recommended that after that only the '**key**' field is displayed to a user. If a user loses the
'**secretKey**', they should be required to generate a new set of keys to use.

```php
$token = $user->generateHmacToken('Work Laptop');

echo 'Key: ' . $token->secret;
echo 'SecretKey: ' . $token->rawSecretKey;
```

## Revoking HMAC Keys

HMAC keys can be revoked through the `revokeHmacToken()` method. This takes the key as the only
argument. Revoking simply deletes the record from the database.

```php
$user->revokeHmacToken($key);
```

You can revoke all HMAC Keys with the `revokeAllHmacTokens()` method.

```php
$user->revokeAllHmacTokens();
```

## Expiring HMAC Keys

By default, the HMAC keys don't expire unless they meet the HMAC Keys lifetime expiration after their last used date.

HMAC keys can be set to expire through the `generateHmacToken()` method. This takes the expiration date as the $expiresAt argument. It's also possible to update an existing HMAC key using `setHmacTokenExpirationById($HmacTokenID, $expiresAt)`

`$expiresAt` Accepts DateTime string formatted as 'Y-m-d h:i:s' or [DateTime relative formats](https://www.php.net/manual/en/datetime.formats.php#datetime.formats.relative) unit symbols (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'

```php
// Expiration date = 2024-11-03 12:00:00
$token = $this->user->generateHmacToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

// Expiration date = 2024-11-15 00:00:00
$token = $user->setHmacTokenExpirationById($token->id, '2024-11-15 00:00:00');

// Or Expiration date = now() + 1 month + 15 days
$token = $user->setHmacTokenExpirationById($token->id, '1 month 15 days');
```

The following support methods are also available:

`hasHmacTokenExpired(AccessToken $HmacToken)` - Checks if the given HMAC key has expired. Returns `true` if the HMAC key has expired, `false` if not, and `null` if the expire date is null.

```php
$token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

$this->user->hasHmacTokenExpired($token); // Returns true
```

`getHmacTokenTimeToExpire(AccessToken $accessToken, string $format = "date" | "human")` - Checks if the given HMAC key has expired. Returns `true` if HMAC key has expired, `false` if not, and `null` if the expire date is not set.

```php
$token = $this->user->generateHmacToken('foo', ['foo:bar']);

$this->user->getHmacTokenTimeToExpire($token, 'date'); // Returns null

// Assuming current time is: 2024-11-04 20:00:00
$token = $this->user->generateHmacToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

$this->user->getHmacTokenTimeToExpire($token, 'date'); // 2024-11-03 12:00:00
$this->user->getHmacTokenTimeToExpire($token, 'human'); // 1 day ago

$token = $this->user->generateHmacToken('foo', ['foo:bar'], '2026-01-06 12:00:00');
$this->user->getHmacTokenTimeToExpire($token, 'human'); // in 1 year
```

You can also easily set all existing HMAC keys/tokens as expired with the `spark` command:
```
php spark shield:hmac expireAll
```
**Careful!** This command 'expires' _all_ keys for _all_ users.

## Retrieving HMAC Keys

The following methods are available to help you retrieve a user's HMAC keys:

```php
// Retrieve a set of HMAC Token/Keys by key
$token = $user->getHmacToken($key);

// Retrieve an HMAC token/keys by its database ID
$token = $user->getHmacTokenById($id);

// Retrieve all HMAC tokens as an array of AccessToken instances.
$tokens = $user->hmacTokens();
```

## HMAC Keys Scopes

Each token (set of keys) can be given one or more scopes they can be used within. These can be thought of as
permissions the token grants to the user. Scopes are provided when the token is generated and
cannot be modified afterword.

```php
$token = $user->gererateHmacToken('Work Laptop', ['posts.manage', 'forums.manage']);
```

By default, a user is granted a wildcard scope which provides access to all scopes. This is the
same as:

```php
$token = $user->gererateHmacToken('Work Laptop', ['*']);
```

During authentication, the HMAC Keys the user used is stored on the user. Once authenticated, you
can use the `hmacTokenCan()` and `hmacTokenCant()` methods on the user to determine if they have access
to the specified scope.

```php
if ($user->hmacTokenCan('posts.manage')) {
    // do something....
}

if ($user->hmacTokenCant('forums.manage')) {
    // do something....
}
```

## HMAC Secret Key Encryption

The HMAC Secret Key is stored encrypted. Before you start using HMAC, you will need to set/override the encryption key
in `$hmacEncryptionKeys` in **app/Config/AuthToken.php**. This should be set using **.env** and/or system
environment variables. Instructions on how to do that can be found in the
[Setting Your Encryption Key](https://codeigniter.com/user_guide/libraries/encryption.html#setting-your-encryption-key)
section of the CodeIgniter 4 documentation.

You will also be able to adjust the default Driver `$hmacEncryptionDefaultDriver` and the default Digest
`$hmacEncryptionDefaultDigest`, these default to `'OpenSSL'` and `'SHA512'` respectively. These can also be
overridden for an individual key by including them in the keys array.

```php
public $hmacEncryptionKeys = [
    'k1' => [
        'key' => 'hex2bin:923dfab5ddca0c7784c2c388a848a704f5e048736c1a852c862959da62ade8c7',
    ],
];

public string $hmacEncryptionCurrentKey    = 'k1';
public string $hmacEncryptionDefaultDriver = 'OpenSSL';
public string $hmacEncryptionDefaultDigest = 'SHA512';
```

When it is time to update your encryption keys you will need to add an additional key to the above
`$hmacEncryptionKeys` array. Then adjust the `$hmacEncryptionCurrentKey` to point at the new key.  After the new
encryption key is in place, run `php spark shield:hmac reencrypt` to re-encrypt all existing keys with the new
encryption key.  You will need to leave the old key in the array as it will be used read the existing 'Secret Keys'
during re-encryption.

```php
public $hmacEncryptionKeys = [
    'k1' => [
        'key' => 'hex2bin:923dfab5ddca0c7784c2c388a848a704f5e048736c1a852c862959da62ade8c7',
    ],
    'k2' => [
        'key'    => 'hex2bin:451df599363b19be1434605fff8556a0bbfc50bede1bb33793dcde4d97fce4b0',
        'digest' => 'SHA256',
    ],
];

public string $hmacEncryptionCurrentKey    = 'k2';
public string $hmacEncryptionDefaultDriver = 'OpenSSL';
public string $hmacEncryptionDefaultDigest = 'SHA512';

```

```console
php spark shield:hmac reencrypt
```

You can (and should) set these values using environment variable and/or the **.env** file. To do this you will need to set
the values as JSON strings:

```text
authtoken.hmacEncryptionKeys = '{"k1":{"key":"hex2bin:923dfab5ddca0c7784c2c388a848a704f5e048736c1a852c862959da62ade8c7"},"k2":{"key":"hex2bin:451df599363b19be1434605fff8556a0bbfc50bede1bb33793dcde4d97fce4b0"}}'
authtoken.hmacEncryptionCurrentKey = k2
```

Depending on the set length of the Secret Key and the type of encryption used, it is possible for the encrypted value to
exceed the database column character limit of 255 characters. If this happens, creation of a new HMAC identity will
throw a `RuntimeException`.

## Configuration

Configure **app/Config/AuthToken.php** for your needs.

!!! note

    Shield does not expect you use the Access Token Authenticator and HMAC Authenticator
    at the same time. Therefore, some Config items are common.

### HMAC Keys Lifetime

HMAC Keys will expire after a specified amount of time has passed since they have been used.

By default, this is set to 1 year. You can change this value by setting the `$unusedTokenLifetime`
value. This is in seconds so that you can use the
[time constants](https://codeigniter.com/user_guide/general/common_functions.html#time-constants)
that CodeIgniter provides.

```php
public $unusedTokenLifetime = YEAR;
```

### HMAC Keys Expiration vs Lifetime
Expiration and Lifetime are different concepts. The lifetime is the maximum time allowed for the HMAC Key to exist since its last use. HMAC Key expiration, on the other hand, is a set date in which the HMAC Key will cease to function.

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
