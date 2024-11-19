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

use CodeIgniter\Config\Factories;
use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\Response;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Actions\ActionInterface;
use CodeIgniter\Shield\Authentication\AuthenticationException;
use CodeIgniter\Shield\Authentication\AuthenticatorInterface;
use CodeIgniter\Shield\Authentication\Passwords;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Exceptions\InvalidArgumentException;
use CodeIgniter\Shield\Exceptions\LogicException;
use CodeIgniter\Shield\Exceptions\SecurityException;
use CodeIgniter\Shield\Models\LoginModel;
use CodeIgniter\Shield\Models\RememberModel;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;
use Config\Security;
use Config\Services;
use stdClass;

class Session implements AuthenticatorInterface
{
    /**
     * @var string Special ID Type.
     *             `username` is stored in `users` table, so no `auth_identities` record.
     */
    public const ID_TYPE_USERNAME = 'username';

    // Identity types
    public const ID_TYPE_EMAIL_PASSWORD = 'email_password';
    public const ID_TYPE_MAGIC_LINK     = 'magic-link';
    public const ID_TYPE_EMAIL_2FA      = 'email_2fa';
    public const ID_TYPE_EMAIL_ACTIVATE = 'email_activate';

    // User states
    private const STATE_UNKNOWN   = 0; // Not checked yet.
    private const STATE_ANONYMOUS = 1;
    private const STATE_PENDING   = 2; // 2FA or Activation required.
    private const STATE_LOGGED_IN = 3;

    /**
     * The persistence engine
     */
    protected UserModel $provider;

    /**
     * Authenticated or authenticating (pending login) User
     */
    protected ?User $user = null;

    /**
     * The User auth state
     */
    private int $userState = self::STATE_UNKNOWN;

    /**
     * Should the user be remembered?
     */
    protected bool $shouldRemember = false;

    protected LoginModel $loginModel;
    protected RememberModel $rememberModel;
    protected UserIdentityModel $userIdentityModel;

    public function __construct(UserModel $provider)
    {
        $this->provider = $provider;

        $this->loginModel        = model(LoginModel::class);
        $this->rememberModel     = model(RememberModel::class);
        $this->userIdentityModel = model(UserIdentityModel::class);

        $this->checkSecurityConfig();
    }

    /**
     * Checks less secure Configuration.
     */
    private function checkSecurityConfig(): void
    {
        /** @var Security $securityConfig */
        $securityConfig = config('Security');

        if ($securityConfig->csrfProtection === 'cookie') {
            throw new SecurityException(
                'Config\Security::$csrfProtection is set to \'cookie\'.'
                    . ' Same-site attackers may bypass the CSRF protection.'
                    . ' Please set it to \'session\'.'
            );
        }
    }

    /**
     * Sets the $shouldRemember flag
     *
     * @return $this
     */
    public function remember(bool $shouldRemember = true): self
    {
        $this->shouldRemember = $shouldRemember;

        return $this;
    }

    /**
     * Attempts to authenticate a user with the given $credentials.
     * Logs the user in with a successful check.
     *
     * @phpstan-param array{email?: string, username?: string, password?: string} $credentials
     */
    public function attempt(array $credentials): Result
    {
        /** @var IncomingRequest $request */
        $request = service('request');

        $ipAddress = $request->getIPAddress();
        $userAgent = (string) $request->getUserAgent();

        $result = $this->check($credentials);

        // Credentials mismatch.
        if (! $result->isOK()) {
            // Always record a login attempt, whether success or not.
            $this->recordLoginAttempt($credentials, false, $ipAddress, $userAgent);

            $this->user = null;

            // Fire an event on failure so devs have the chance to
            // let them know someone attempted to login to their account
            unset($credentials['password']);
            Events::trigger('failedLogin', $credentials);

            return $result;
        }

        /** @var User $user */
        $user = $result->extraInfo();

        if ($user->isBanned()) {
            $this->user = null;

            return new Result([
                'success' => false,
                'reason'  => $user->getBanMessage() ?? lang('Auth.bannedUser'),
            ]);
        }

        $this->user = $user;

        // Update the user's last used date on their password identity.
        $user->touchIdentity($user->getEmailIdentity());

        // Set auth action from database.
        $this->setAuthAction();

        // If an action has been defined for login, start it up.
        $this->startUpAction('login', $user);

        $this->startLogin($user);

        $this->recordLoginAttempt($credentials, true, $ipAddress, $userAgent, $user->id);

        $this->issueRememberMeToken();

        if (! $this->hasAction()) {
            $this->completeLogin($user);
        }

        return $result;
    }

    /**
     * If an action has been defined, start it up.
     *
     * @param string $type 'register', 'login'
     *
     * @return bool If the action has been defined or not.
     */
    public function startUpAction(string $type, User $user): bool
    {
        $actionClass = shieldSetting('Auth.actions')[$type] ?? null;

        if ($actionClass === null) {
            return false;
        }

        /** @var ActionInterface $action */
        $action = Factories::actions($actionClass); // @phpstan-ignore-line

        // Create identity for the action.
        $action->createIdentity($user);

        $this->setAuthAction();

        return true;
    }

    /**
     * Returns an action object from the session data
     */
    public function getAction(): ?ActionInterface
    {
        /** @var class-string<ActionInterface>|null $actionClass */
        $actionClass = $this->getSessionUserKey('auth_action');

        if ($actionClass === null) {
            return null;
        }

        return Factories::actions($actionClass); // @phpstan-ignore-line
    }

    /**
     * Check token in Action
     *
     * @param string $token Token to check
     */
    public function checkAction(UserIdentity $identity, string $token): bool
    {
        $user = ($this->loggedIn() || $this->isPending()) ? $this->user : null;

        if ($user === null) {
            throw new LogicException('Cannot get the User.');
        }

        if ($token === '' || $token !== $identity->secret) {
            return false;
        }

        // On success - remove the identity
        $this->userIdentityModel->deleteIdentitiesByType($user, $identity->type);

        // Clean up our session
        $this->removeSessionUserKey('auth_action');
        $this->removeSessionUserKey('auth_action_message');

        $this->user = $user;

        $this->completeLogin($user);

        return true;
    }

    /**
     * Completes login process
     */
    public function completeLogin(User $user): void
    {
        $this->userState = self::STATE_LOGGED_IN;

        // a successful login
        Events::trigger('login', $user);
    }

    /**
     * @param int|string|null $userId
     */
    private function recordLoginAttempt(
        array $credentials,
        bool $success,
        string $ipAddress,
        string $userAgent,
        $userId = null
    ): void {
        // Determine the type of ID we're using.
        // Standard fields would be email, username,
        // but any column within config('Auth')->validFields can be used.
        $field = array_intersect(config('Auth')->validFields ?? [], array_keys($credentials));

        if (count($field) !== 1) {
            throw new InvalidArgumentException('Invalid credentials passed to recordLoginAttempt.');
        }

        $field = array_pop($field);

        if (! in_array($field, ['email', 'username'], true)) {
            $idType = $field;
        } else {
            $idType = (! isset($credentials['email']) && isset($credentials['username']))
                ? self::ID_TYPE_USERNAME
                : self::ID_TYPE_EMAIL_PASSWORD;
        }

        $this->loginModel->recordLoginAttempt(
            $idType,
            $credentials[$field],
            $success,
            $ipAddress,
            $userAgent,
            $userId
        );
    }

    /**
     * Checks a user's $credentials to see if they match an
     * existing user.
     *
     * @phpstan-param array{email?: string, username?: string, password?: string} $credentials
     */
    public function check(array $credentials): Result
    {
        // Can't validate without a password.
        if (empty($credentials['password']) || count($credentials) < 2) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        // Remove the password from credentials so we can
        // check afterword.
        $givenPassword = $credentials['password'];
        unset($credentials['password']);

        // Find the existing user
        $user = $this->provider->findByCredentials($credentials);

        if ($user === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        /** @var Passwords $passwords */
        $passwords = service('passwords');

        // Now, try matching the passwords.
        if (! $passwords->verify($givenPassword, $user->password_hash)) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.invalidPassword'),
            ]);
        }

        // Check to see if the password needs to be rehashed.
        // This would be due to the hash algorithm or hash
        // cost changing since the last time that a user
        // logged in.
        if ($passwords->needsRehash($user->password_hash)) {
            $user->password_hash = $passwords->hash($givenPassword);
            $this->provider->save($user);
        }

        return new Result([
            'success'   => true,
            'extraInfo' => $user,
        ]);
    }

    /**
     * Checks if the user is currently logged in.
     */
    public function loggedIn(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_LOGGED_IN;
    }

    /**
     * Checks User state
     */
    private function checkUserState(): void
    {
        if ($this->userState !== self::STATE_UNKNOWN) {
            // Checked already.
            return;
        }

        /** @var int|string|null $userId */
        $userId = $this->getSessionUserKey('id');

        // Has User Info in Session.
        if ($userId !== null) {
            $this->user = $this->provider->findById($userId);

            if ($this->user === null) {
                // The user is deleted.
                $this->userState = self::STATE_ANONYMOUS;

                // Remove User Info in Session.
                $this->removeSessionUserInfo();

                return;
            }

            // If having `auth_action`, it is pending.
            if ($this->getSessionUserKey('auth_action')) {
                $this->userState = self::STATE_PENDING;

                return;
            }

            $this->userState = self::STATE_LOGGED_IN;

            return;
        }

        // No User Info in Session.
        // Check remember-me token.
        if (shieldSetting('Auth.sessionConfig')['allowRemembering']) {
            if ($this->checkRememberMe()) {
                $this->setAuthAction();
            }

            return;
        }

        $this->userState = self::STATE_ANONYMOUS;
    }

    /**
     * Has Auth Action?
     *
     * @param int|string|null $userId Provide user id only when checking a
     *                                not-logged-in user
     *                                (e.g. user who tries magic-link login)
     */
    public function hasAction($userId = null): bool
    {
        // Check not-logged-in user
        if ($userId !== null) {
            $user = $this->provider->findById($userId);

            // Check identities for actions
            if ($this->getIdentitiesForAction($user) !== []) {
                // Make pending login state
                $this->user = $user;
                $this->setSessionUserKey('id', $user->id);
                $this->setAuthAction();

                return true;
            }
        }

        // Check the Session
        if ($this->getSessionUserKey('auth_action')) {
            return true;
        }

        // Check the database
        return $this->setAuthAction();
    }

    /**
     * Finds an identity for actions from database, and sets the identity
     * that is found first in the session.
     *
     * @return bool true if the action is set in the session.
     */
    private function setAuthAction(): bool
    {
        if ($this->user === null) {
            return false;
        }

        $authActions = shieldSetting('Auth.actions');

        foreach ($authActions as $actionClass) {
            if ($actionClass === null) {
                continue;
            }

            /** @var ActionInterface $action */
            $action = Factories::actions($actionClass);  // @phpstan-ignore-line

            $identity = $this->userIdentityModel->getIdentityByType($this->user, $action->getType());

            if ($identity instanceof UserIdentity) {
                $this->userState = self::STATE_PENDING;

                $this->setSessionUserKey('auth_action', $actionClass);
                $this->setSessionUserKey('auth_action_message', $identity->extra);

                return true;
            }
        }

        return false;
    }

    /**
     * Gets identities for action
     *
     * @return list<UserIdentity>
     */
    private function getIdentitiesForAction(User $user): array
    {
        return $this->userIdentityModel->getIdentitiesByTypes(
            $user,
            $this->getActionTypes()
        );
    }

    /**
     * @return list<string>
     */
    private function getActionTypes(): array
    {
        $actions = shieldSetting('Auth.actions');
        $types   = [];

        foreach ($actions as $actionClass) {
            if ($actionClass === null) {
                continue;
            }

            /** @var ActionInterface $action */
            $action  = Factories::actions($actionClass);  // @phpstan-ignore-line
            $types[] = $action->getType();
        }

        return $types;
    }

    /**
     * Checks if the user is currently in pending login state.
     * They need to do an auth action.
     */
    public function isPending(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_PENDING;
    }

    /**
     * Checks if the visitor is anonymous. The user's id is unknown.
     * They are not logged in, are not in pending login state.
     */
    public function isAnonymous(): bool
    {
        $this->checkUserState();

        return $this->userState === self::STATE_ANONYMOUS;
    }

    /**
     * Returns pending login error message
     */
    public function getPendingMessage(): string
    {
        $this->checkUserState();

        return $this->getSessionUserKey('auth_action_message') ?? '';
    }

    /**
     * @return bool true if logged in by remember-me token.
     */
    private function checkRememberMe(): bool
    {
        // Get remember-me token.
        $remember = $this->getRememberMeToken();
        if ($remember === null) {
            $this->userState = self::STATE_ANONYMOUS;

            return false;
        }

        // Check the remember-me token.
        $token = $this->checkRememberMeToken($remember);
        if ($token === false) {
            $this->userState = self::STATE_ANONYMOUS;

            return false;
        }

        $user = $this->provider->findById($token->user_id);

        if ($user === null) {
            // The user is deleted.
            $this->userState = self::STATE_ANONYMOUS;

            // Remove remember-me cookie.
            $this->removeRememberCookie();

            return false;
        }

        $this->startLogin($user);

        $this->refreshRememberMeToken($token);

        $this->userState = self::STATE_LOGGED_IN;

        return true;
    }

    private function getRememberMeToken(): ?string
    {
        /** @var IncomingRequest $request */
        $request = service('request');

        $cookieName = shieldSetting('Cookie.prefix') . shieldSetting('Auth.sessionConfig')['rememberCookieName'];

        return $request->getCookie($cookieName);
    }

    /**
     * @return false|stdClass
     */
    private function checkRememberMeToken(string $remember)
    {
        [$selector, $validator] = explode(':', $remember);

        $hashedValidator = hash('sha256', $validator);

        $token = $this->rememberModel->getRememberToken($selector);

        if ($token === null) {
            return false;
        }

        if (hash_equals($token->hashedValidator, $hashedValidator) === false) {
            return false;
        }

        return $token;
    }

    /**
     * Starts login process
     */
    public function startLogin(User $user): void
    {
        /** @var int|string|null $userId */
        $userId = $this->getSessionUserKey('id');

        // Check if already logged in.
        if ($userId !== null) {
            throw new LogicException(
                'The user has User Info in Session, so already logged in or in pending login state.'
                    . ' If a logged in user logs in again with other account, the session data of the previous'
                    . ' user will be used as the new user.'
                    . ' Fix your code to prevent users from logging in without logging out or delete the session data.'
                    . ' user_id: ' . $userId
            );
        }

        $this->user = $user;

        // Regenerate the session ID to help protect against session fixation
        if (ENVIRONMENT !== 'testing') {
            session()->regenerate(true);

            // Regenerate CSRF token even if `security.regenerate = false`.
            Services::security()->generateHash();
        }

        // Let the session know we're logged in
        $this->setSessionUserKey('id', $user->id);

        /** @var Response $response */
        $response = service('response');

        // When logged in, ensure cache control headers are in place
        $response->noCache();
    }

    /**
     * Gets User Info in Session
     */
    protected function getSessionUserInfo(): array
    {
        return session(shieldSetting('Auth.sessionConfig')['field']) ?? [];
    }

    /**
     * Removes User Info in Session
     */
    protected function removeSessionUserInfo(): void
    {
        session()->remove(shieldSetting('Auth.sessionConfig')['field']);
    }

    /**
     * Gets the key value in Session User Info
     *
     * @return int|string|null
     */
    protected function getSessionUserKey(string $key)
    {
        $sessionUserInfo = $this->getSessionUserInfo();

        return $sessionUserInfo[$key] ?? null;
    }

    /**
     * Sets the key value in Session User Info
     *
     * @param int|string|null $value
     */
    protected function setSessionUserKey(string $key, $value): void
    {
        $sessionUserInfo       = $this->getSessionUserInfo();
        $sessionUserInfo[$key] = $value;
        session()->set(shieldSetting('Auth.sessionConfig')['field'], $sessionUserInfo);
    }

    /**
     * Remove the key value in Session User Info
     */
    protected function removeSessionUserKey(string $key): void
    {
        $sessionUserInfo = $this->getSessionUserInfo();
        unset($sessionUserInfo[$key]);
        session()->set(shieldSetting('Auth.sessionConfig')['field'], $sessionUserInfo);
    }

    /**
     * Logs the given user in.
     */
    public function login(User $user): void
    {
        $this->user = $user;

        // Check identities for actions
        if ($this->getIdentitiesForAction($user) !== []) {
            throw new LogicException(
                'The user has identities for action, so cannot complete login.'
                    . ' If you want to start to login with auth action, use startLogin() instead.'
                    . ' Or delete identities for action in database.'
                    . ' user_id: ' . $user->id
            );
        }
        // Check auth_action in Session
        if ($this->getSessionUserKey('auth_action')) {
            throw new LogicException(
                'The user has auth action in session, so cannot complete login.'
                    . ' If you want to start to login with auth action, use startLogin() instead.'
                    . ' Or delete `auth_action` and `auth_action_message` in session data.'
                    . ' user_id: ' . $user->id
            );
        }

        $this->startLogin($user);

        $this->issueRememberMeToken();

        $this->completeLogin($user);
    }

    private function issueRememberMeToken(): void
    {
        if ($this->shouldRemember && shieldSetting('Auth.sessionConfig')['allowRemembering']) {
            $this->rememberUser($this->user);

            // Reset so it doesn't mess up future calls.
            $this->shouldRemember = false;
        } elseif ($this->getRememberMeToken() !== null) {
            $this->removeRememberCookie();

            // @TODO delete the token record.
        }

        // We'll give a 20% chance to need to do a purge since we
        // don't need to purge THAT often, it's just a maintenance issue.
        // to keep the table from getting out of control.
        if (random_int(1, 100) <= 20) {
            $this->rememberModel->purgeOldRememberTokens();
        }
    }

    private function removeRememberCookie(): void
    {
        /** @var Response $response */
        $response = service('response');

        // Remove remember-me cookie
        $response->deleteCookie(
            shieldSetting('Auth.sessionConfig')['rememberCookieName'],
            shieldSetting('Cookie.domain'),
            shieldSetting('Cookie.path'),
            shieldSetting('Cookie.prefix')
        );
    }

    /**
     * Logs a user in based on their ID.
     *
     * @param int|string $userId
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if (! $user instanceof User) {
            throw AuthenticationException::forInvalidUser();
        }

        $this->login($user);
    }

    /**
     * Logs the current user out.
     */
    public function logout(): void
    {
        $this->checkUserState();

        if ($this->user === null) {
            return;
        }

        // Destroy the session data - but ensure a session is still
        // available for flash messages, etc.
        /** @var \CodeIgniter\Session\Session $session */
        $session     = session();
        $sessionData = $session->get();
        if (isset($sessionData)) {
            foreach (array_keys($sessionData) as $key) {
                $session->remove($key);
            }
        }

        // Regenerate the session ID for a touch of added safety.
        $session->regenerate(true);

        // Take care of any remember-me functionality
        $this->rememberModel->purgeRememberTokens($this->user);

        // Trigger logout event
        Events::trigger('logout', $this->user);

        $this->user      = null;
        $this->userState = self::STATE_ANONYMOUS;
    }

    /**
     * Removes any remember-me tokens, if applicable.
     */
    public function forget(?User $user = null): void
    {
        $user ??= $this->user;
        if ($user === null) {
            return;
        }

        $this->rememberModel->purgeRememberTokens($user);
    }

    /**
     * Returns the current user instance.
     */
    public function getUser(): ?User
    {
        $this->checkUserState();

        if ($this->userState === self::STATE_LOGGED_IN) {
            return $this->user;
        }

        return null;
    }

    /**
     * Returns the current pending login User.
     */
    public function getPendingUser(): ?User
    {
        $this->checkUserState();

        if ($this->userState === self::STATE_PENDING) {
            return $this->user;
        }

        return null;
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

    /**
     * Generates a timing-attack safe remember-me token
     * and stores the necessary info in the db and a cookie.
     *
     * @see https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
     */
    protected function rememberUser(User $user): void
    {
        $selector  = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(20));
        $expires   = $this->calcExpires();

        $rawToken = $selector . ':' . $validator;

        // Store it in the database.
        $this->rememberModel->rememberUser(
            $user,
            $selector,
            $this->hashValidator($validator),
            $expires->format('Y-m-d H:i:s')
        );

        $this->setRememberMeCookie($rawToken);
    }

    private function calcExpires(): Time
    {
        $timestamp = Time::now()->getTimestamp() + shieldSetting('Auth.sessionConfig')['rememberLength'];

        return Time::createFromTimestamp($timestamp);
    }

    /**
     * @param non-empty-string $rawToken
     */
    private function setRememberMeCookie(string $rawToken): void
    {
        /** @var Response $response */
        $response = service('response');

        // Save it to the user's browser in a cookie.
        // Create the cookie
        $response->setCookie(
            shieldSetting('Auth.sessionConfig')['rememberCookieName'],
            $rawToken,                                             // Value
            shieldSetting('Auth.sessionConfig')['rememberLength'],      // # Seconds until it expires
            shieldSetting('Cookie.domain'),
            shieldSetting('Cookie.path'),
            shieldSetting('Cookie.prefix'),
            shieldSetting('Cookie.secure'),                          // Only send over HTTPS?
            true                                                  // Hide from Javascript?
        );
    }

    /**
     * Hash remember-me validator
     */
    private function hashValidator(string $validator): string
    {
        return hash('sha256', $validator);
    }

    private function refreshRememberMeToken(stdClass $token): void
    {
        // Update validator.
        $validator = bin2hex(random_bytes(20));

        $token->hashedValidator = $this->hashValidator($validator);
        $token->expires         = $this->calcExpires();

        $this->rememberModel->updateRememberValidator($token);

        $rawToken = $token->selector . ':' . $validator;

        $this->setRememberMeCookie($rawToken);
    }
}
