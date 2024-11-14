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

namespace Tests\Authentication;

use CodeIgniter\Shield\Entities\AccessToken;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use DateInterval;
use DateTime;
use Tests\Support\DatabaseTestCase;

/**
 * @internal
 */
final class HasAccessTokensTest extends DatabaseTestCase
{
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = fake(UserModel::class);
        $this->db->table($this->tables['identities'])->truncate();
    }

    public function testGenerateToken(): void
    {
        $token = $this->user->generateAccessToken('foo');

        $this->assertInstanceOf(AccessToken::class, $token);
        $this->assertSame('foo', $token->name);
        $this->assertNull($token->expires);

        // When newly created, should have the raw, plain-text token as well
        // so it can be shown to users.
        $this->assertNotNull($token->raw_token);
        $this->assertSame($token->secret, hash('sha256', $token->raw_token));

        // All scopes are assigned by default via wildcard
        $this->assertSame(['*'], $token->scopes);
    }

    public function testAccessTokens(): void
    {
        // Should return empty array when none exist
        $this->assertSame([], $this->user->accessTokens());

        // Give the user a couple of access tokens
        $token1 = fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => 'access_token', 'secret' => 'secretToken1']
        );
        $token2 = fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => 'access_token', 'secret' => 'secretToken2']
        );

        /** @var list<AccessToken> $tokens */
        $tokens = $this->user->accessTokens();

        $this->assertCount(2, $tokens);
        $this->assertSame($token1->id, $tokens[0]->id);
        $this->assertSame($token2->id, $tokens[1]->id);
    }

    public function testGetAccessToken(): void
    {
        // Should return null when not found
        $this->assertNull($this->user->getAccessToken('foo'));

        $token = $this->user->generateAccessToken('foo');

        $found = $this->user->getAccessToken($token->raw_token);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
    }

    public function testGetAccessTokenById(): void
    {
        // Should return null when not found
        $this->assertNull($this->user->getAccessTokenById(123));

        $token = $this->user->generateAccessToken('foo');
        $found = $this->user->getAccessTokenById($token->id);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
    }

    public function testRevokeAccessToken(): void
    {
        $token = $this->user->generateAccessToken('foo');

        $this->assertCount(1, $this->user->accessTokens());

        $this->user->revokeAccessToken($token->raw_token);

        $this->assertCount(0, $this->user->accessTokens());
    }

    public function testRevokeAccessTokenBySecret(): void
    {
        $token = $this->user->generateAccessToken('foo');

        $this->assertCount(1, $this->user->accessTokens());

        $this->user->revokeAccessTokenBySecret($token->secret);

        $this->assertCount(0, $this->user->accessTokens());
    }

    public function testRevokeAllAccessTokens(): void
    {
        $this->user->generateAccessToken('foo');
        $this->user->generateAccessToken('foo');

        $this->assertCount(2, $this->user->accessTokens());

        $this->user->revokeAllAccessTokens();

        $this->assertCount(0, $this->user->accessTokens());
    }

    public function testTokenCanNoTokenSet(): void
    {
        $this->assertFalse($this->user->tokenCan('foo'));
    }

    public function testTokenCanBasics(): void
    {
        $token = $this->user->generateAccessToken('foo', ['foo:bar']);
        $this->user->setAccessToken($token);

        $this->assertTrue($this->user->tokenCan('foo:bar'));
        $this->assertFalse($this->user->tokenCan('foo:baz'));
    }

    public function testTokenCantNoTokenSet(): void
    {
        $this->assertTrue($this->user->tokenCant('foo'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testGenerateTokenWithExpiration(): void
    {
        $token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');
        $this->user->setAccessToken($token);

        $this->assertSame('2024-11-03 12:00:00', $this->user->getAccessTokenTimeToExpire($this->user->currentAccessToken(), 'date'));

        $token = $this->user->generateAccessToken('foo', ['foo:bar'], '1 month 1 year');
        $this->user->setAccessToken($token);

        $expireDate = new DateTime();
        $expireDate->add(DateInterval::createFromDateString('1 month + 1 year'));
        $this->assertSame($expireDate->format('Y-m-d h:i:s'), $this->user->getAccessTokenTimeToExpire($this->user->currentAccessToken(), 'date'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testSetTokenExpirationById(): void
    {
        $token = $this->user->generateAccessToken('foo', ['foo:bar']);

        $this->user->setAccessToken($token);

        $this->assertNull($this->user->currentAccessToken()->expires);

        // true = updated row
        $this->assertTrue($this->user->setAccessTokenExpirationById($token->id, '2024-11-03 12:00:00'));

        $this->assertSame('2024-11-03 12:00:00', $this->user->getAccessTokenTimeToExpire($this->user->currentAccessToken(), 'date'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testIsTokenExpired(): void
    {
        $token = $this->user->generateAccessToken('foo', ['foo:bar'], '2024-11-03 12:00:00');
        $this->user->setAccessToken($token);

        $this->assertTrue($this->user->hasAccessTokenExpired($this->user->currentAccessToken()));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testTokenTimeToExpired(): void
    {
        $token = $this->user->generateAccessToken('foo', ['foo:bar'], '1 year');
        $this->user->setAccessToken($token);

        $this->assertSame('in 1 year', $this->user->getAccessTokenTimeToExpire($this->user->currentAccessToken(), 'human'));
    }
}
