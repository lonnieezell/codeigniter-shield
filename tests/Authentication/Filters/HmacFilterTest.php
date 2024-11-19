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
use CodeIgniter\Shield\Filters\HmacAuth;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\DatabaseTestTrait;

/**
 * @internal
 */
final class HmacFilterTest extends AbstractFilterTestCase
{
    use DatabaseTestTrait;

    // Filter alias and classname
    protected string $alias     = 'hmacAuth';
    protected string $classname = HmacAuth::class;

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
        $token = $user->generateHmacToken('foo');

        $rawToken = $this->generateRawHeaderToken($token->secret, $token->rawSecretKey, '');
        $result   = $this->withHeaders(['Authorization' => 'HMAC-SHA256  ' . $rawToken])
            ->get('protected-route');

        $result->assertStatus(200);
        $result->assertSee('Protected');

        $this->assertSame($user->id, auth('hmac')->id());
        $this->assertSame($user->id, auth('hmac')->user()->id);

        // User should have the current token set.
        $this->assertInstanceOf(AccessToken::class, auth('hmac')->user()->currentHmacToken());
        $this->assertSame($token->id, auth('hmac')->user()->currentHmacToken()->id);
    }

    public function testFilterInvalidSignature(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateHmacToken('foo');

        $result = $this->withHeaders(['Authorization' => 'HMAC-SHA256  ' . $this->generateRawHeaderToken($token->secret, $token->rawSecretKey, 'bar')])
            ->get('protected-route');

        $result->assertStatus(401);
    }

    public function testRecordActiveDate(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateHmacToken('foo');

        $this->withHeaders(['Authorization' => 'HMAC-SHA256 ' . $this->generateRawHeaderToken($token->secret, $token->rawSecretKey, '')])
            ->get('protected-route');

        // Last Active should be greater than 'updated_at' column
        $this->assertGreaterThan(auth('hmac')->user()->updated_at, auth('hmac')->user()->last_active);
    }

    public function testFiltersProtectsWithScopes(): void
    {
        /** @var User $user1 */
        $user1  = fake(UserModel::class);
        $token1 = $user1->generateHmacToken('foo', ['users-read']);
        /** @var User $user2 */
        $user2  = fake(UserModel::class);
        $token2 = $user2->generateHmacToken('foo', ['users-write']);

        // User 1 should be able to access the route
        $result1 = $this->withHeaders(['Authorization' => 'HMAC-SHA256 ' . $this->generateRawHeaderToken($token1->secret, $token1->rawSecretKey, '')])
            ->get('protected-user-route');

        $result1->assertStatus(200);
        // Last Active should be greater than 'updated_at' column
        $this->assertGreaterThan(auth('hmac')->user()->updated_at, auth('hmac')->user()->last_active);

        // User 2 should NOT be able to access the route
        $result2 = $this->withHeaders(['Authorization' => 'HMAC-SHA256 ' . $this->generateRawHeaderToken($token2->secret, $token2->rawSecretKey, '')])
            ->get('protected-user-route');

        $result2->assertStatus(401);
    }

    public function testBlocksInactiveUsers(): void
    {
        /** @var User $user */
        $user  = fake(UserModel::class, ['active' => false]);
        $token = $user->generateHmacToken('foo');

        // Activation only required with email activation
        shieldSetting('Auth.actions', ['register' => null]);

        $result = $this->withHeaders(['Authorization' => 'HMAC-SHA256 ' . $this->generateRawHeaderToken($token->secret, $token->rawSecretKey, '')])
            ->get('protected-route');

        $result->assertStatus(200);
        $result->assertSee('Protected');

        // Now require user activation and try again
        shieldSetting('Auth.actions', ['register' => '\CodeIgniter\Shield\Authentication\Actions\EmailActivator']);

        $result = $this->withHeaders(['Authorization' => 'HMAC-SHA256 ' . $this->generateRawHeaderToken($token->secret, $token->rawSecretKey, '')])
            ->get('protected-route');

        $result->assertStatus(403);

        shieldSetting('Auth.actions', ['register' => null]);
    }

    protected function generateRawHeaderToken(string $secret, string $secretKey, string $body): string
    {
        return $secret . ':' . hash_hmac('sha256', $body, $secretKey);
    }
}
