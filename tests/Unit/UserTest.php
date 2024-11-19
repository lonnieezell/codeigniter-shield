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

namespace Tests\Unit;

use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\Login;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\LoginModel;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Tests\Support\DatabaseTestCase;
use Tests\Support\FakeUser;

/**
 * @internal
 */
final class UserTest extends DatabaseTestCase
{
    use FakeUser;

    protected $namespace;
    protected $refresh = true;

    public function testGetIdentitiesNone(): void
    {
        // when none, returns empty array
        $this->assertEmpty($this->user->identities);
    }

    public function testGetIdentitiesSome(): void
    {
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'password']);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'access_token']);

        $identities = $this->user->identities;

        $this->assertCount(2, $identities);
    }

    public function testGetIdentitiesByType(): void
    {
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'password']);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'access_token']);

        $identities = $this->user->getIdentities('access_token');

        $this->assertCount(1, $identities);
        $this->assertInstanceOf(UserIdentity::class, $identities[0]);
        $this->assertSame('access_token', $identities[0]->type);
        $this->assertEmpty($this->user->getIdentities('foo'));
    }

    public function testModelFindAllWithIdentities(): void
    {
        fake(UserModel::class);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'password']);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'access_token']);

        // Grab the user again, using the model's identity helper
        model(UserModel::class)->withIdentities()->findAll();

        $identities = $this->user->identities;

        $this->assertCount(2, $identities);
    }

    public function testModelFindAllWithIdentitiesUserNotExists(): void
    {
        $users = model(UserModel::class)->where('active', 0)->withIdentities()->findAll();

        $this->assertSame([], $users);
    }

    public function testModelFindByIdWithIdentities(): void
    {
        fake(UserModel::class);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'password']);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'access_token']);

        // Grab the user again, using the model's identity helper
        $user = model(UserModel::class)->withIdentities()->findById(1);

        $this->assertCount(2, $user->identities);
    }

    public function testModelFindAllWithIdentitiesWhereInQuery(): void
    {
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'password']);
        fake(UserIdentityModel::class, ['user_id' => $this->user->id, 'type' => 'access_token']);

        // Grab the user again, using the model's identity helper
        $users = model(UserModel::class)->withIdentities()->findAll();

        $identities = [];

        foreach ($users as $user) {
            if ($user->id !== $this->user->id) {
                continue;
            }

            $identities = $user->identities;

            // Check the last query and see if a proper type of query was used
            $query = (string) model(UserModel::class)->getLastQuery();
            $this->assertMatchesRegularExpression(
                '/WHERE\s+.*\s+IN\s+\([^)]+\)/i',
                $query,
                'Identities were not obtained with the single query (missing "WHERE ... IN" condition)'
            );
        }

        $this->assertCount(2, $identities);
    }

    public function testModelFindByIdWithIdentitiesUserNotExists(): void
    {
        $user = model(UserModel::class)->where('active', 0)->withIdentities()->findById(1);

        $this->assertNull($user);
    }

    public function testLastLogin(): void
    {
        fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => Session::ID_TYPE_EMAIL_PASSWORD, 'secret' => 'foo@example.com']
        );

        // No logins found.
        $this->assertNull($this->user->lastLogin());

        fake(
            LoginModel::class,
            ['id_type' => 'email', 'identifier' => $this->user->email, 'user_id' => $this->user->id]
        );
        $login2 = fake(
            LoginModel::class,
            ['id_type' => 'email', 'identifier' => $this->user->email, 'user_id' => $this->user->id]
        );
        fake(
            LoginModel::class,
            [
                'id_type'    => 'email',
                'identifier' => $this->user->email,
                'user_id'    => $this->user->id,
                'success'    => false,
            ]
        );

        $last = $this->user->lastLogin();

        $this->assertInstanceOf(Login::class, $last); // @phpstan-ignore-line
        $this->assertSame($login2->id, $last->id);
        $this->assertInstanceOf(Time::class, $last->date);
    }

    public function testPreviousLogin(): void
    {
        fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => Session::ID_TYPE_EMAIL_PASSWORD, 'secret' => 'foo@example.com']
        );

        // No logins found.
        $this->assertNull($this->user->previousLogin());

        $login1 = fake(
            LoginModel::class,
            ['id_type' => 'email', 'identifier' => $this->user->email, 'user_id' => $this->user->id]
        );

        // The very most login is skipped.
        $this->assertNull($this->user->previousLogin());

        fake(
            LoginModel::class,
            ['id_type' => 'email', 'identifier' => $this->user->email, 'user_id' => $this->user->id]
        );
        fake(
            LoginModel::class,
            [
                'id_type'    => 'email',
                'identifier' => $this->user->email,
                'user_id'    => $this->user->id,
                'success'    => false,
            ]
        );

        $previous = $this->user->previousLogin();

        $this->assertInstanceOf(Login::class, $previous); // @phpstan-ignore-line
        $this->assertSame($login1->id, $previous->id);
        $this->assertInstanceOf(Time::class, $previous->date);
    }

    /**
     * @see https://github.com/codeigniter4/shield/issues/103
     */
    public function testUpdateEmail(): void
    {
        // Update user's email
        $this->user->email  = 'foo@bar.com';
        $this->user->active = false;

        $users = model(UserModel::class);
        $users->save($this->user);

        /** @var User $user */
        $user = $users->find($this->user->id);

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'secret'  => 'foo@bar.com',
        ]);
        $this->assertSame('foo@bar.com', $user->email);
    }

    /**
     * @see https://github.com/codeigniter4/shield/issues/103
     */
    public function testUpdatePassword(): void
    {
        // Update user's email
        $this->user->email    = 'foo@bar.com';
        $this->user->password = 'foobar';
        $this->user->active   = false;

        $users = model(UserModel::class);
        $users->save($this->user);

        $user = $users->find($this->user->id);

        $this->assertTrue(service('passwords')->verify('foobar', $user->password_hash));
    }

    /**
     * @see https://github.com/codeigniter4/shield/issues/103
     */
    public function testUpdatePasswordHash(): void
    {
        // Update user's email
        $hash                      = service('passwords')->hash('foobar');
        $this->user->email         = 'foo@bar.com';
        $this->user->password_hash = $hash;
        $this->user->active        = false;

        $users = model(UserModel::class);
        $users->save($this->user);

        /** @var User $user */
        $user = $users->find($this->user->id);

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'secret'  => 'foo@bar.com',
            'secret2' => $hash,
        ]);
    }

    public function testCreateEmailIdentity(): void
    {
        $identity = $this->user->getEmailIdentity();
        $this->assertNull($identity);

        $this->user->createEmailIdentity([
            'email'    => 'foo@example.com',
            'password' => 'passbar',
        ]);

        $identity = $this->user->getEmailIdentity();
        $this->assertSame('foo@example.com', $identity->secret);
    }

    public function testSaveEmailIdentity(): void
    {
        $hash                      = service('passwords')->hash('passbar');
        $this->user->email         = 'foo@example.com';
        $this->user->password_hash = $hash;

        $this->user->saveEmailIdentity();

        $identity = $this->user->getEmailIdentity();
        $this->assertSame('foo@example.com', $identity->secret);
    }

    public function testActivate(): void
    {
        $this->user->active = false;
        model(UserModel::class)->save($this->user);

        $this->seeInDatabase($this->tables['users'], [
            'id'     => $this->user->id,
            'active' => 0,
        ]);

        $this->user->activate();

        // Refresh user
        $this->user = model(UserModel::class)->find($this->user->id);

        $this->assertTrue($this->user->active);
        $this->seeInDatabase($this->tables['users'], [
            'id'     => $this->user->id,
            'active' => 1,
        ]);
    }

    public function testDeactivate(): void
    {
        $this->user->active = true;
        model(UserModel::class)->save($this->user);

        $this->seeInDatabase($this->tables['users'], [
            'id'     => $this->user->id,
            'active' => 1,
        ]);

        $this->user->deactivate();

        // Refresh user
        $this->user = model(UserModel::class)->find($this->user->id);

        $this->assertFalse($this->user->active);
        $this->seeInDatabase($this->tables['users'], [
            'id'     => $this->user->id,
            'active' => 0,
        ]);
    }

    public function testIsActivatedSuccessWhenNotRequired(): void
    {
        $this->user->active = false;
        model(UserModel::class)->save($this->user);

        shieldSetting('Auth.actions', ['register' => null]);

        $this->assertTrue($this->user->isActivated());
    }

    public function testIsActivatedWhenRequired(): void
    {
        shieldSetting('Auth.actions', ['register' => '\CodeIgniter\Shield\Authentication\Actions\EmailActivator']);
        $user = $this->user;

        $user->deactivate();
        /** @var User $user */
        $user = model(UserModel::class)->find($user->id);

        $this->assertFalse($user->isActivated());

        $user->activate();
        /** @var User $user */
        $user = model(UserModel::class)->find($user->id);

        $this->assertTrue($user->isActivated());
    }

    public function testIsNotActivated(): void
    {
        shieldSetting('Auth.actions', ['register' => '\CodeIgniter\Shield\Authentication\Actions\EmailActivator']);
        $user = $this->user;

        $user->active = false;
        model(UserModel::class)->save($user);

        /** @var User $user */
        $user = model(UserModel::class)->find($user->id);

        $this->assertFalse($user->isActivated());
    }
}
