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

namespace Tests\Controllers;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Authentication\Actions\EmailActivator;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Authentication\Passwords\ValidationRules;
use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\FeatureTestTrait;
use Config\Services;
use Tests\Support\DatabaseTestCase;
use Tests\Support\FakeUser;

/**
 * @internal
 */
final class RegisterTest extends DatabaseTestCase
{
    use FeatureTestTrait;
    use FakeUser;

    protected function setUp(): void
    {
        Services::reset(true);

        parent::setUp();

        // Add auth routes
        $routes = service('routes');
        auth()->routes($routes);
        Services::injectMock('routes', $routes);

        // Ensure password validation rule is present
        $config             = config('Validation');
        $config->ruleSets[] = ValidationRules::class;
        $config->ruleSets   = array_reverse($config->ruleSets);
        Factories::injectMock('config', 'Validation', $config);
    }

    public function testRegisterActionSuccess(): void
    {
        $result = $this->withSession()->post('/register', [
            'username'         => 'JohnDoe',
            'email'            => 'john.doe@example.com',
            'password'         => 'secret things might happen here',
            'password_confirm' => 'secret things might happen here',
        ]);

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionMissing('error');
        $result->assertSessionMissing('errors');

        $this->assertSame(site_url(), $result->getRedirectUrl());

        // User saved to DB
        $this->seeInDatabase($this->tables['users'], [
            'username' => 'JohnDoe',
        ]);

        // User has email/password identity
        /** @var User $user */
        $user = model(UserModel::class)->where('username', 'JohnDoe')->first();

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => Session::ID_TYPE_EMAIL_PASSWORD,
            'secret'  => 'john.doe@example.com',
        ]);

        // User added to default group
        $this->assertTrue($user->inGroup(config('AuthGroups')->defaultGroup));
        $this->assertFalse($user->inGroup('admin'));

        $this->assertTrue($user->active);
    }

    public function testRegisterActionSuccessWithNoEmailLogin(): void
    {
        /** @var Auth $config */
        $config = config('Auth');
        // Use `username` for login
        $config->validFields = ['username'];

        $this->testRegisterActionSuccess();
    }

    public function testRegisterTooLongPasswordDefault(): void
    {
        $result = $this->withSession()->post('/register', [
            'username'         => 'JohnDoe',
            'email'            => 'john.doe@example.com',
            'password'         => str_repeat('a', 73),
            'password_confirm' => str_repeat('a', 73),
        ]);

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionMissing('error');
        $result->assertSessionHas(
            'errors',
            ['password' => 'Password cannot exceed 72 bytes in length.']
        );
    }

    public function testRegisterTooLongPasswordArgon2id(): void
    {
        /** @var Auth $config */
        $config                = config('Auth');
        $config->hashAlgorithm = PASSWORD_ARGON2ID;

        $result = $this->withSession()->post('/register', [
            'username'         => 'JohnDoe',
            'email'            => 'john.doe@example.com',
            'password'         => str_repeat('a', 256),
            'password_confirm' => str_repeat('a', 256),
        ]);

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionMissing('error');
        $result->assertSessionHas(
            'errors',
            ['password' => 'The Password field cannot exceed 255 characters in length.']
        );
    }

    public function testRegisterDisplaysForm(): void
    {
        $result = $this->withSession()->get('/register');

        $result->assertStatus(200);
        $result->assertSee(lang('Auth.register'));
    }

    public function testRegisterRedirectsIfNotAllowed(): void
    {
        $config                    = config('Auth');
        $config->allowRegistration = false;
        Factories::injectMock('config', 'Auth', $config);

        $result = $this->withSession()->get('/register');

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionHas('error');
    }

    public function testRegisterActionRedirectsIfNotAllowed(): void
    {
        $config                    = config('Auth');
        $config->allowRegistration = false;
        Factories::injectMock('config', 'Auth', $config);

        $result = $this->withSession()->post('/register');

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionHas('error');
    }

    public function testRegisterActionInvalidData(): void
    {
        $result = $this->withSession()->post('/register');

        $result->assertStatus(302);
        $this->assertCount(4, session('errors'));
    }

    public function testRegisterRedirectsToActionIfDefined(): void
    {
        // Ensure our action is defined
        $config                      = config('Auth');
        $config->actions['register'] = EmailActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        $result = $this->post('/register', [
            'email'            => 'foo@example.com',
            'username'         => 'foo',
            'password'         => 'abkdhflkjsdflkjasd;lkjf',
            'password_confirm' => 'abkdhflkjsdflkjasd;lkjf',
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');

        // Should NOT have activated the user
        $this->seeInDatabase($this->tables['users'], [
            'username' => 'foo',
            'active'   => 0,
        ]);
    }

    public function testRegisteredButNotActivatedAndLogin(): void
    {
        // Ensure our action is defined
        $config                      = config('Auth');
        $config->actions['register'] = EmailActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        $result = $this->post('/register', [
            'email'            => 'foo@example.com',
            'username'         => 'foo',
            'password'         => 'abkdhflkjsdflkjasd;lkjf',
            'password_confirm' => 'abkdhflkjsdflkjasd;lkjf',
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');

        // Not activated yet, but login again.
        $result = $this->withSession()->get('/login');

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');
    }

    public function testRegisteredButNotActivatedAndRegisterAgain(): void
    {
        // Ensure our action is defined
        $config                      = config('Auth');
        $config->actions['register'] = EmailActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        $password = 'abkdhflkjsdflkjasd;lkjf';

        $result = $this->post('/register', [
            'email'            => 'foo@example.com',
            'username'         => 'foo',
            'password'         => $password,
            'password_confirm' => $password,
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');

        // Not activated yet, but register again.
        $result = $this->withSession()->get('/register');

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');
    }

    public function testRegisteredAndSessionExpiredAndLogin(): void
    {
        // Ensure our action is defined
        $config                      = config('Auth');
        $config->actions['register'] = EmailActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        $result = $this->post('/register', [
            'email'            => 'foo@example.com',
            'username'         => 'foo',
            'password'         => 'abkdhflkjsdflkjasd;lkjf',
            'password_confirm' => 'abkdhflkjsdflkjasd;lkjf',
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');

        // Not activated yet, and do not set Session (= the session is expired) and login again.
        $result = $this->post('/login', [
            'email'    => 'foo@example.com',
            'password' => 'abkdhflkjsdflkjasd;lkjf',
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');
    }

    public function testRegisterRedirectsIfLoggedIn(): void
    {
        // log them in
        session()->set('user', ['id' => $this->user->id]);

        $result = $this->withSession()->get('/register');

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertRedirectTo(config('Auth')->registerRedirect());
    }

    public function testRegisterActionRedirectsIfLoggedIn(): void
    {
        // log them in
        session()->set('user', ['id' => $this->user->id]);

        $result = $this->withSession()->post('/register', [
            'username'         => 'JohnDoe',
            'email'            => 'john.doe@example.com',
            'password'         => 'secret things might happen here',
            'password_confirm' => 'secret things might happen here',
        ]);

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertRedirectTo(config('Auth')->registerRedirect());
    }

    public function testRegisterActionWithBadEmailValue(): void
    {
        $result = $this->withSession()->post('/register', [
            'username'         => 'JohnDoe',
            'email'            => 'john.doe',
            'password'         => '123456789aa',
            'password_confirm' => '123456789aa',
        ]);

        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSessionMissing('error');
        $result->assertSessionHas(
            'errors',
            ['email' => 'The Email Address field must contain a valid email address.']
        );
    }

    public function testRegisterActionRedirectsIfTokenNotMatch(): void
    {
        // Ensure our action is defined
        $config                      = config('Auth');
        $config->actions['register'] = EmailActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        // Already registered but not yet activated and logged in.
        $result = $this->post('/register', [
            'email'            => 'foo@example.com',
            'username'         => 'foo',
            'password'         => 'abkdhflkjsdflkjasd;lkjf',
            'password_confirm' => 'abkdhflkjsdflkjasd;lkjf',
        ]);

        // Should have been redirected to the action's page.
        $result->assertRedirectTo('/auth/a/show');

        // Attempted to send an invalid token.
        $result = $this->withSession()->post('/auth/a/verify', [
            'token' => 'invalid-token',
        ]);

        // Should have been redirected to the previous page.
        $result->assertStatus(302);
        $result->assertRedirect();
        $result->assertSee(lang('Auth.invalidActivateToken'));
    }

    protected function setupConfig(): void
    {
        $config             = config('Validation');
        $config->ruleSets[] = ValidationRules::class;
        Factories::injectMock('config', 'Validation', $config);
    }
}
