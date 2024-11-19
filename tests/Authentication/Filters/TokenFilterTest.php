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

namespace Tests\Authentication\Filters;

use CodeIgniter\Shield\Entities\AccessToken;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Filters\TokenAuth;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\DatabaseTestTrait;

/**
 * @internal
 */
final class TokenFilterTest extends AbstractFilterTestCase
{
    use DatabaseTestTrait;

    protected string $alias     = 'tokenAuth';
    protected string $classname = TokenAuth::class;

    public function testFilterNotAuthorized(): void
    {
        $result = $this->call('get', 'protected-route');

        $result->assertStatus(401);

        $result = $this->get('open-route');
        $result->assertStatus(200);
        $result->assertSee('Open');
    }

    public function testFilterSuccess(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateAccessToken('foo');

        $result = $this->withHeaders(['Authorization' => 'Bearer ' . $token->raw_token])
            ->get('protected-route');

        $result->assertStatus(200);
        $result->assertSee('Protected');

        $this->assertSame($user->id, auth('tokens')->id());
        $this->assertSame($user->id, auth('tokens')->user()->id);

        // User should have the current token set.
        $this->assertInstanceOf(AccessToken::class, auth('tokens')->user()->currentAccessToken());
        $this->assertSame($token->id, auth('tokens')->user()->currentAccessToken()->id);
    }

    public function testRecordActiveDate(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateAccessToken('foo');

        $this->withHeaders(['Authorization' => 'Bearer ' . $token->raw_token])
            ->get('protected-route');

        // Last Active should be greater than 'updated_at' column
        $this->assertGreaterThan(auth('tokens')->user()->updated_at, auth('tokens')->user()->last_active);
    }

    public function testFiltersProtectsWithScopes(): void
    {
        /** @var User $user1 */
        $user1  = fake(UserModel::class);
        $token1 = $user1->generateAccessToken('foo', ['users-read']);
        /** @var User $user2 */
        $user2  = fake(UserModel::class);
        $token2 = $user2->generateAccessToken('foo', ['users-write']);

        // User 1 should be able to access the route
        $this->withHeaders(['Authorization' => 'Bearer ' . $token1->raw_token])
            ->get('protected-user-route');

        // Last Active should be greater than 'updated_at' column
        $this->assertGreaterThan(auth('tokens')->user()->updated_at, auth('tokens')->user()->last_active);

        // User 2 should NOT be able to access the route
        $result = $this->withHeaders(['Authorization' => 'Bearer ' . $token2->raw_token])
            ->get('protected-user-route');

        $result->assertStatus(401);
    }

    public function testBlocksInactiveUsers(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class, ['active' => false]);
        $token = $user->generateAccessToken('foo');

        // Activation only required with email activation
        shieldSetting('Auth.actions', ['register' => null]);

        $result = $this->withHeaders(['Authorization' => 'Bearer ' . $token->raw_token])
            ->get('protected-route');

        $result->assertStatus(200);
        $result->assertSee('Protected');

        // Now require user activation and try again
        shieldSetting('Auth.actions', ['register' => '\CodeIgniter\Shield\Authentication\Actions\EmailActivator']);

        $result = $this->withHeaders(['Authorization' => 'Bearer ' . $token->raw_token])
            ->get('protected-route');

        $result->assertStatus(403);

        shieldSetting('Auth.actions', ['register' => null]);
    }
}
