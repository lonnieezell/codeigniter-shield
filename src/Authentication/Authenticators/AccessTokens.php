<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace CodeIgniter\Shield\Authentication\Authenticators;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\AuthenticationException;
use CodeIgniter\Shield\Authentication\AuthenticatorInterface;
use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\InvalidArgumentException;
use CodeIgniter\Shield\Models\TokenLoginModel;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;

class AccessTokens implements AuthenticatorInterface
{
    public const ID_TYPE_ACCESS_TOKEN = 'access_token';

    /**
     * The persistence engine
     */
    protected UserModel $provider;

    protected ?User $user = null;
    protected TokenLoginModel $loginModel;

    public function __construct(UserModel $provider)
    {
        $this->provider = $provider;

        $this->loginModel = model(TokenLoginModel::class);
    }

    /**
     * Attempts to authenticate a user with the given $credentials.
     * Logs the user in with a successful check.
     *
     * @throws AuthenticationException
     */
    public function attempt(array $credentials): Result
    {
        $config = config('AuthToken');

        /** @var IncomingRequest $request */
        $request = service('request');

        $ipAddress = $request->getIPAddress();
        $userAgent = (string) $request->getUserAgent();

        $result = $this->check($credentials);

        if (! $result->isOK()) {
            if ($config->recordLoginAttempt >= Auth::RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Record all failed login attempts.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_ACCESS_TOKEN,
                    $credentials['token'] ?? '',
                    false,
                    $ipAddress,
                    $userAgent
                );
            }

            return $result;
        }

        $user  = $result->extraInfo();
        $token = $user->getAccessToken($this->getBearerToken());

        if ($user->isBanned()) {
            if ($config->recordLoginAttempt >= Auth::RECORD_LOGIN_ATTEMPT_FAILURE) {
                // Record a banned login attempt.
                $this->loginModel->recordLoginAttempt(
                    self::ID_TYPE_ACCESS_TOKEN,
                    $token->name ?? '',
                    false,
                    $ipAddress,
                    $userAgent,
                    $user->id
                );
            }

            $this->user = null;

            return new Result([
                'success' => false,
                'reason'  => $user->getBanMessage() ?? lang('Auth.bannedUser'),
            ]);
        }

        $user = $user->setAccessToken($token);

        $this->login($user);

        if ($config->recordLoginAttempt === Auth::RECORD_LOGIN_ATTEMPT_ALL) {
            // Record a successful login attempt.
            $this->loginModel->recordLoginAttempt(
                self::ID_TYPE_ACCESS_TOKEN,
                $token->name ?? '',
                true,
                $ipAddress,
                $userAgent,
                $this->user->id
            );
        }

        return $result;
    }

    /**
     * Checks a user's $credentials to see if they match an
     * existing user.
     *
     * In this case, $credentials has only a single valid value: token,
     * which is the plain text token to return.
     */
    public function check(array $credentials): Result
    {
        if (! array_key_exists('token', $credentials) || empty($credentials['token'])) {
            return new Result([
                'success' => false,
                'reason'  => lang(
                    'Auth.noToken',
                    [config('AuthToken')->authenticatorHeader['tokens']]
                ),
            ]);
        }

        if (strpos($credentials['token'], 'Bearer') === 0) {
            $credentials['token'] = trim(substr($credentials['token'], 6));
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $token = $identityModel->getAccessTokenByRawToken($credentials['token']);

        if ($token === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badToken'),
            ]);
        }

        assert($token->last_used_at instanceof Time || $token->last_used_at === null);

        // Is expired ?
        if (
            $token->expires
            && $token->expires->isBefore(
                Time::now()
            )
        ) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.oldToken'),
            ]);
        }

        // Hasn't been used in a long time
        if (
            $token->last_used_at
            && $token->last_used_at->isBefore(
                Time::now()->subSeconds(config('AuthToken')->unusedTokenLifetime)
            )
        ) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.oldToken'),
            ]);
        }

        $token->last_used_at = Time::now();

        if ($token->hasChanged()) {
            $identityModel->save($token);
        }

        // Ensure the token is set as the current token
        $user = $token->user();
        $user->setAccessToken($token);

        return new Result([
            'success'   => true,
            'extraInfo' => $user,
        ]);
    }

    /**
     * Checks if the user is currently logged in.
     * Since AccessToken usage is inherently stateless,
     * it runs $this->attempt on each usage.
     */
    public function loggedIn(): bool
    {
        if ($this->user instanceof User) {
            return true;
        }

        /** @var IncomingRequest $request */
        $request = service('request');

        return $this->attempt([
            'token' => $request->getHeaderLine(
                config('AuthToken')->authenticatorHeader['tokens']
            ),
        ])->isOK();
    }

    /**
     * Logs the given user in by saving them to the class.
     */
    public function login(User $user): void
    {
        $this->user = $user;
    }

    /**
     * Logs a user in based on their ID.
     *
     * @param int|string $userId
     *
     * @throws AuthenticationException
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if (! $user instanceof User) {
            throw AuthenticationException::forInvalidUser();
        }

        $user->setAccessToken(
            $user->getAccessToken($this->getBearerToken())
        );

        $this->login($user);
    }

    /**
     * Logs the current user out.
     */
    public function logout(): void
    {
        $this->user = null;
    }

    /**
     * Returns the currently logged in user.
     */
    public function getUser(): ?User
    {
        return $this->user;
    }

    /**
     * Returns the Bearer token from the Authorization header
     */
    public function getBearerToken(): ?string
    {
        /** @var IncomingRequest $request */
        $request = service('request');

        $header = $request->getHeaderLine(config('AuthToken')->authenticatorHeader['tokens']);

        if (empty($header)) {
            return null;
        }

        return trim(substr($header, 6));   // 'Bearer'
    }

    /**
     * Updates the user's last active date.
     */
    public function recordActiveDate(): void
    {
        if (! $this->user instanceof User) {
            throw new InvalidArgumentException(
                __METHOD__ . '() requires logged in user before calling.'
            );
        }

        $this->user->last_active = Time::now();

        $this->provider->updateActiveDate($this->user);
    }
}
