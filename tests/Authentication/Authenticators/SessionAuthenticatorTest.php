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

namespace Tests\Authentication\Authenticators;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Authentication\Authentication;
use CodeIgniter\Shield\Authentication\AuthenticationException;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\LogicException;
use CodeIgniter\Shield\Models\RememberModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;
use CodeIgniter\Test\Mock\MockEvents;
use Config\Services;
use Tests\Support\DatabaseTestCase;
use Tests\Support\FakeUser;

/**
 * @internal
 */
final class SessionAuthenticatorTest extends DatabaseTestCase
{
    use FakeUser;

    private Session $auth;

    protected function setUp(): void
    {
        parent::setUp();

        $config = new Auth();
        $auth   = new Authentication($config);
        $auth->setProvider(model(UserModel::class));

        /** @var Session $authenticator */
        $authenticator = $auth->factory('session');
        $this->auth    = $authenticator;

        $events = new MockEvents();
        Services::injectMock('events', $events);

        $this->db->table($this->tables['identities'])->truncate();
    }

    public function testLoggedInFalse(): void
    {
        $this->assertFalse($this->auth->loggedIn());
    }

    public function testLoggedInTrue(): void
    {
        $_SESSION['user']['id'] = $this->user->id;

        $this->assertTrue($this->auth->loggedIn());

        $authUser = $this->auth->getUser();
        $this->assertInstanceOf(User::class, $authUser);
        $this->assertSame($this->user->id, $authUser->id);
    }

    public function testLoggedInAsDeletedUserWithSessionData(): void
    {
        $_SESSION['user']['id'] = $this->user->id;

        // Delete the user.
        $users = model(UserModel::class);
        $users->delete($this->user->id);

        $loggedIn = $this->auth->loggedIn();

        $this->assertFalse($loggedIn);
        $this->assertNull(session()->get('user'));
    }

    public function testLoggedInWithRememberCookie(): void
    {
        unset($_SESSION['user']);
        // Set Cookie.prefix
        $cookiePrefix = 'prefix_';
        shieldSetting('Cookie.prefix', $cookiePrefix);

        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        // Insert remember-me token.
        /** @var RememberModel $rememberModel */
        $rememberModel = model(RememberModel::class);
        $selector      = 'selector';
        $validator     = 'validator';
        $expires       = date('Y-m-d H:i:s', time() + shieldSetting('Auth.sessionConfig')['rememberLength']);
        $rememberModel->rememberUser($this->user, $selector, hash('sha256', $validator), $expires);

        // Set Cookie value for remember-me.
        $token                = $selector . ':' . $validator;
        $cookieName           = $cookiePrefix . shieldSetting('Auth.sessionConfig')['rememberCookieName'];
        $_COOKIE[$cookieName] = $token;

        $this->assertTrue($this->auth->loggedIn());

        $authUser = $this->auth->getUser();

        $this->assertInstanceOf(User::class, $authUser);
        $this->assertSame($this->user->id, $authUser->id);

        // Forget Cookie.prefix
        shieldSetting()->forget('Cookie.prefix');
    }

    public function testLoggedInAsDeletedUserWithRememberCookie(): void
    {
        unset($_SESSION['user']);

        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        // Insert remember-me token.
        /** @var RememberModel $rememberModel */
        $rememberModel = model(RememberModel::class);
        $selector      = 'selector';
        $validator     = 'validator';
        $expires       = date('Y-m-d H:i:s', time() + shieldSetting('Auth.sessionConfig')['rememberLength']);
        $rememberModel->rememberUser($this->user, $selector, hash('sha256', $validator), $expires);

        // Set Cookie value for remember-me.
        $token               = $selector . ':' . $validator;
        $_COOKIE['remember'] = $token;

        // Delete the user.
        $users = model(UserModel::class);
        $users->delete($this->user->id);

        $loggedIn = $this->auth->loggedIn();

        $this->assertFalse($loggedIn);
    }

    public function testLoginNoRemember(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        $this->auth->login($this->user);

        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        $this->dontSeeInDatabase($this->tables['remember_tokens'], [
            'user_id' => $this->user->id,
        ]);
    }

    public function testLoginWithRemember(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        $this->auth->remember()->login($this->user);

        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        $this->seeInDatabase($this->tables['remember_tokens'], [
            'user_id' => $this->user->id,
        ]);

        // Cookie should have been set
        $response = service('response');
        $this->assertNotNull($response->getCookie('remember'));
    }

    public function testLogout(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);
        $this->auth->remember()->login($this->user);

        $this->seeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $this->auth->logout();

        $this->assertArrayNotHasKey('user', $_SESSION);
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testLogoutOnlyLogoutCalled(): void
    {
        $_SESSION['user']['id'] = $this->user->id;

        $this->auth->logout();

        $this->assertArrayNotHasKey('user', $_SESSION);
    }

    public function testLoginByIdBadUser(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage(lang('Auth.invalidUser'));

        $this->auth->loginById(123);
    }

    public function testLoginById(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        $this->auth->loginById($this->user->id);

        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testLoginByIdRemember(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);

        $this->auth->remember()->loginById($this->user->id);

        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        $this->seeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testForgetCurrentUser(): void
    {
        $this->user->createEmailIdentity(['email' => 'foo@example.com', 'password' => 'secret']);
        $this->auth->remember()->loginById($this->user->id);
        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        $this->seeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $this->auth->forget();

        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testForgetAnotherUser(): void
    {
        fake(RememberModel::class, ['user_id' => $this->user->id]);

        $this->seeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $this->auth->forget($this->user);

        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testCheckNoPassword(): void
    {
        $result = $this->auth->check([
            'email' => 'johnsmith@example.com',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertFalse($result->isOK());
        $this->assertSame(lang('Auth.badAttempt'), $result->reason());
    }

    public function testCheckCannotFindUser(): void
    {
        $result = $this->auth->check([
            'email'    => 'johnsmith@example.com',
            'password' => 'secret',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertFalse($result->isOK());
        $this->assertSame(lang('Auth.badAttempt'), $result->reason());
    }

    public function testCheckBadPassword(): void
    {
        $this->user->createEmailIdentity([
            'email'    => 'foo@example.com',
            'password' => 'secret123',
        ]);

        $result = $this->auth->check([
            'email'    => $this->user->email,
            'password' => 'secret',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertFalse($result->isOK());
        $this->assertSame(lang('Auth.invalidPassword'), $result->reason());
    }

    public function testCheckSuccess(): void
    {
        $this->user->createEmailIdentity([
            'email'    => 'foo@example.com',
            'password' => 'secret123',
        ]);

        $result = $this->auth->check([
            'email'    => $this->user->email,
            'password' => 'secret123',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertTrue($result->isOK());

        $foundUser = $result->extraInfo();
        $this->assertSame($this->user->id, $foundUser->id);
    }

    public function testAttemptCannotFindUser(): void
    {
        $result = $this->auth->attempt([
            'email'    => 'johnsmith@example.com',
            'password' => 'secret',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertFalse($result->isOK());
        $this->assertSame(lang('Auth.badAttempt'), $result->reason());

        // A login attempt should have always been recorded
        $this->seeInDatabase($this->tables['logins'], [
            'identifier' => 'johnsmith@example.com',
            'success'    => 0,
        ]);
    }

    public function testAttemptSuccess(): void
    {
        $this->user->createEmailIdentity([
            'email'    => 'foo@example.com',
            'password' => 'secret123',
        ]);

        $this->assertArrayNotHasKey('user', $_SESSION);

        $result = $this->auth->attempt([
            'email'    => $this->user->email,
            'password' => 'secret123',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertTrue($result->isOK());

        $foundUser = $result->extraInfo();
        $this->assertSame($this->user->id, $foundUser->id);

        $this->assertArrayHasKey('id', $_SESSION['user']);
        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        // A login attempt should have been recorded
        $this->seeInDatabase($this->tables['logins'], [
            'identifier' => $this->user->email,
            'success'    => 1,
        ]);
    }

    public function testAttemptUserHavingSessionDataAttemptsAgain(): void
    {
        $_SESSION['user']['id'] = '999';

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'The user has User Info in Session, so already logged in or in pending login state.'
        );

        $this->user->createEmailIdentity([
            'email'    => 'foo@example.com',
            'password' => 'secret123',
        ]);

        $this->auth->attempt([
            'email'    => $this->user->email,
            'password' => 'secret123',
        ]);
    }

    public function testAttemptCaseInsensitive(): void
    {
        $this->user->createEmailIdentity([
            'email'    => 'FOO@example.com',
            'password' => 'secret123',
        ]);

        $this->assertArrayNotHasKey('user', $_SESSION);

        $result = $this->auth->attempt([
            'email'    => 'foo@example.COM',
            'password' => 'secret123',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertTrue($result->isOK());

        $foundUser = $result->extraInfo();
        $this->assertSame($this->user->id, $foundUser->id);

        $this->assertArrayHasKey('id', $_SESSION['user']);
        $this->assertSame($this->user->id, $_SESSION['user']['id']);

        // A login attempt should have been recorded
        $this->seeInDatabase($this->tables['logins'], [
            'identifier' => 'foo@example.COM',
            'success'    => 1,
        ]);
    }

    public function testAttemptUsernameOnly(): void
    {
        // Update our auth config to use the username as a valid field for login.
        // It is commented out by default.
        $config              = config('Auth');
        $config->validFields = ['email', 'username'];
        Factories::injectMock('config', 'Auth', $config);

        /** @var User $user */
        $user = fake(UserModel::class, ['username' => 'foorog']);
        $user->createEmailIdentity([
            'email'    => 'FOO@example.com',
            'password' => 'secret123',
        ]);

        $this->assertArrayNotHasKey('user', $_SESSION);

        $result = $this->auth->attempt([
            'username' => 'fooROG',
            'password' => 'secret123',
        ]);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertTrue($result->isOK());

        $foundUser = $result->extraInfo();
        $this->assertSame($user->id, $foundUser->id);

        $this->assertArrayHasKey('id', $_SESSION['user']);
        $this->assertSame($user->id, $_SESSION['user']['id']);

        // A login attempt should have been recorded
        $this->seeInDatabase($this->tables['logins'], [
            'identifier' => 'fooROG',
            'success'    => 1,
        ]);
    }

    /**
     * Test that any field within the user table can be used as the
     * login identifier.
     *
     * @see https://github.com/codeigniter4/shield/issues/334
     */
    public function testAttemptCustomField(): void
    {
        // We don't need email, but do need a password set....
        $this->user->createEmailIdentity([
            'email'    => $this->db->getPlatform() === 'OCI8' ? ' ' : '',
            'password' => 'secret123',
        ]);

        // We don't have any custom fields in the User model, so we'll
        // just use the status field to represent an employoee ID
        model(UserModel::class)->set('status', '12345')->update($this->user->id);

        // Update our auth config to use the status field as a valid field for login
        $config              = config('Auth');
        $config->validFields = ['email', 'status'];
        Factories::injectMock('config', 'Auth', $config);

        // Should block it
        $result = $this->auth->attempt(['status' => 'abcde', 'password' => 'secret123']);

        $this->assertFalse($result->isOK());

        $result = $this->auth->attempt(['status' => '12345', 'password' => 'secret123']);

        $this->assertTrue($result->isOK());

        $this->seeInDatabase($this->tables['logins'], [
            'id_type'    => 'status',
            'identifier' => '12345',
            'success'    => 1,
        ]);
    }
}
