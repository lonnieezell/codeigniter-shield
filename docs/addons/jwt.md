# JWT Authentication

!!! note

    Shield now supports only JWS (Singed JWT). JWE (Encrypted JWT) is not supported.

## What is JWT?

JWT or JSON Web Token is a compact and self-contained way of securely transmitting
information between parties as a JSON object. It is commonly used for authentication
and authorization purposes in web applications.

For example, when a user logs in to a web application, the server generates a JWT
token and sends it to the client. The client then includes this token in the header
of subsequent requests to the server. The server verifies the authenticity of the
token and grants access to protected resources accordingly.

If you are not familiar with JWT, we recommend that you check out
[Introduction to JSON Web Tokens](https://jwt.io/introduction) before continuing.

## Setup

To use JWT Authentication, you need additional setup and configuration.

### Manual Setup

1. Install "firebase/php-jwt" via Composer.

    ```console
    composer require firebase/php-jwt:^6.4
    ```

2. Copy the **AuthJWT.php** from **vendor/codeigniter4/shield/src/Config/** into your project's config folder and update the namespace to `Config`. You will also need to have these classes extend the original classes. See the example below.

    ```php
    <?php

    // app/Config/AuthJWT.php

    declare(strict_types=1);

    namespace Config;

    use CodeIgniter\Shield\Config\AuthJWT as ShieldAuthJWT;

    /**
     * JWT Authenticator Configuration
     */
    class AuthJWT extends ShieldAuthJWT
    {
        // ...
    }
    ```

3. If your **app/Config/Auth.php** is not up-to-date, you also need to update it. Check **vendor/codeigniter4/shield/src/Config/Auth.php** and apply the differences.

    You need to add the following constants:
    ```php
    public const RECORD_LOGIN_ATTEMPT_NONE    = 0; // Do not record at all
    public const RECORD_LOGIN_ATTEMPT_FAILURE = 1; // Record only failures
    public const RECORD_LOGIN_ATTEMPT_ALL     = 2; // Record all login attempts
    ```

    You need to add JWT Authenticator:
    ```php
    use CodeIgniter\Shield\Authentication\Authenticators\JWT;

    // ...

    public array $authenticators = [
        'tokens'  => AccessTokens::class,
        'session' => Session::class,
        'jwt'     => JWT::class,
    ];
    ```

    If you want to use JWT Authenticator in Authentication Chain, add `jwt`:
    ```php
    public array $authenticationChain = [
        'session',
        'tokens',
        'jwt'
    ];
    ```

## Configuration

Configure **app/Config/AuthJWT.php** for your needs.

### Set the Default Claims

!!! note

    A payload contains the actual data being transmitted, such as user ID, role,
    or expiration time. Items in a payload is called *claims*.

Set the default payload items to the property `$defaultClaims`.

E.g.:
```php
public array $defaultClaims = [
    'iss' => 'https://codeigniter.com/',
];
```

The default claims will be included in all tokens issued by Shield.

### Set Secret Key

Set your secret key in the `$keys` property, or set it in your `.env` file.

E.g.:
```text
authjwt.keys.default.0.secret = 8XBFsF6HThIa7OV/bSynahEch+WbKrGcuiJVYPiwqPE=
```

It needs at least 256 bits random string. The length of the secret depends on the
algorithm we use. The default one is `HS256`, so to ensure that the hash value is
secure and not easily guessable, the secret key should be at least as long as the
hash function's output - 256 bits (32 bytes). You can get a secure random string
with the following command:

```console
php -r 'echo base64_encode(random_bytes(32));'
```

!!! note

    The secret key is used for signing and validating tokens.

### Login Attempt Logging

By default, only failed login attempts are recorded in the `auth_token_logins` table.

```php
public int $recordLoginAttempt = Auth::RECORD_LOGIN_ATTEMPT_FAILURE;
```

If you don't want any logs, set it to `Auth::RECORD_LOGIN_ATTEMPT_NONE`.

If you want to log all login attempts, set it to `Auth::RECORD_LOGIN_ATTEMPT_ALL`.
It means you log all requests.

## Issuing JWTs

To use JWT Authentication, you need a controller that issues JWTs.

Here is a sample controller. When a client posts valid credentials (email/password),
it returns a new JWT.

```php
// app/Config/Routes.php
$routes->post('auth/jwt', '\App\Controllers\Auth\LoginController::jwtLogin');
```

```php
<?php

// app/Controllers/Auth/LoginController.php

declare(strict_types=1);

namespace App\Controllers\Auth;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Authentication\JWTManager;
use CodeIgniter\Shield\Validation\ValidationRules;

class LoginController extends BaseController
{
    use ResponseTrait;

    /**
     * Authenticate Existing User and Issue JWT.
     */
    public function jwtLogin(): ResponseInterface
    {
        // Get the validation rules
        $rules = $this->getValidationRules();

        // Validate credentials
        if (! $this->validateData($this->request->getJSON(true), $rules, [], config('Auth')->DBGroup)) {
            return $this->fail(
                ['errors' => $this->validator->getErrors()],
                $this->codes['unauthorized']
            );
        }

        // Get the credentials for login
        $credentials             = $this->request->getJsonVar(shieldSetting('Auth.validFields'));
        $credentials             = array_filter($credentials);
        $credentials['password'] = $this->request->getJsonVar('password');

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // Check the credentials
        $result = $authenticator->check($credentials);

        // Credentials mismatch.
        if (! $result->isOK()) {
            // @TODO Record a failed login attempt

            return $this->failUnauthorized($result->reason());
        }

        // Credentials match.
        // @TODO Record a successful login attempt

        $user = $result->extraInfo();

        /** @var JWTManager $manager */
        $manager = service('jwtmanager');

        // Generate JWT and return to client
        $jwt = $manager->generateToken($user);

        return $this->respond([
            'access_token' => $jwt,
        ]);
    }

    /**
     * Returns the rules that should be used for validation.
     *
     * @return array<string, array<string, array<string>|string>>
     * @phpstan-return array<string, array<string, string|list<string>>>
     */
    protected function getValidationRules(): array
    {
        $rules = new ValidationRules();

        return $rules->getLoginRules();
    }
}
```

You could send a request with the existing user's credentials by curl like this:

```curl
curl --location 'http://localhost:8080/auth/jwt' \
--header 'Content-Type: application/json' \
--data-raw '{"email" : "admin@example.jp" , "password" : "passw0rd!"}'
```

When making all future requests to the API, the client should send the JWT in
the `Authorization` header as a `Bearer` token.

You could send a request with the `Authorization` header by curl like this:

```curl
curl --location --request GET 'http://localhost:8080/api/users' \
--header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTaGllbGQgVGVzdCBBcHAiLCJzdWIiOiIxIiwiaWF0IjoxNjgxODA1OTMwLCJleHAiOjE2ODE4MDk1MzB9.DGpOmRPOBe45whVtEOSt53qJTw_CpH0V8oMoI_gm2XI'
```

## Protecting Routes

The first way to specify which routes are protected is to use the `jwt` controller
filter.

For example, to ensure it protects all routes under the `/api` route group, you
would use the `$filters` setting on **app/Config/Filters.php**.

```php
public $filters = [
    'jwt' => ['before' => ['api', 'api/*']],
];
```

You can also specify the filter should run on one or more routes within the routes
file itself:

```php
$routes->group('api', ['filter' => 'jwt'], static function ($routes) {
    // ...
});

$routes->get('users', 'UserController::list', ['filter' => 'jwt']);
```

When the filter runs, it checks the `Authorization` header for a `Bearer` value
that has the JWT. It then validates the token. If the token is valid, it can
determine the correct user, which will then be available through an `auth()->user()`
call.

## Method References

### Generating Signed JWTs

#### JWT to a Specific User

JWTs are created through the `JWTManager::generateToken()` method.
This takes a User object to give to the token as the first argument.
It can also take optional additional claims array, time to live in seconds,
a key group (an array key) in the `Config\AuthJWT::$keys`, and additional header
array:

```php
public function generateToken(
    User $user,
    array $claims = [],
    ?int $ttl = null,
    $keyset = 'default',
    ?array $headers = null
): string
```

The following code generates a JWT to the user.

```php
use CodeIgniter\Shield\Authentication\JWTManager;

/** @var JWTManager $manager */
$manager = service('jwtmanager');

$user   = auth()->user();
$claims = [
    'email' => $user->email,
];
$jwt = $manager->generateToken($user, $claims);
```

It sets the `Config\AuthJWT::$defaultClaims` to the token, and adds
the `'email'` claim and the user ID in the `"sub"` (subject) claim.
It also sets `"iat"` (Issued At) and `"exp"` (Expiration Time) claims automatically
if you don't specify.

#### Arbitrary JWT

You can generate arbitrary JWT with the ``JWTManager::issue()`` method.

It takes a JWT claims array, and can take time to live in seconds, a key group
(an array key) in the `Config\AuthJWT::$keys`, and additional header array:

```php
public function issue(
    array $claims,
    ?int $ttl = null,
    $keyset = 'default',
    ?array $headers = null
): string
```

The following code generates a JWT.

```php
use CodeIgniter\Shield\Authentication\JWTManager;

/** @var JWTManager $manager */
$manager = service('jwtmanager');

$payload = [
    'user_id' => '1',
    'email'   => 'admin@example.jp',
];
$jwt = $manager->issue($payload, DAY);
```

It uses the `secret` and `alg` in the `Config\AuthJWT::$keys['default']`.

It sets the `Config\AuthJWT::$defaultClaims` to the token, and sets
`"iat"` (Issued At) and `"exp"` (Expiration Time) claims automatically even if
you don't pass them.

## Logging

Login attempts are recorded in the `auth_token_logins` table, according to the
configuration above.

When a failed login attempt is logged, the raw token value sent is saved in
the `identifier` column.

When a successful login attempt is logged, the SHA256 hash value of the token
sent is saved in the `identifier` column.
