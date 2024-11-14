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
final class HasHmacTokensTest extends DatabaseTestCase
{
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = fake(UserModel::class);
        $this->db->table($this->tables['identities'])->truncate();
    }

    public function testGenerateHmacToken(): void
    {
        $token = $this->user->generateHmacToken('foo');

        $this->assertSame('foo', $token->name);
        $this->assertNull($token->expires);

        $this->assertIsString($token->secret);
        $this->assertIsString($token->secret2);
        $this->assertIsString($token->rawSecretKey);

        // All scopes are assigned by default via wildcard
        $this->assertSame(['*'], $token->scopes);
    }

    public function testHmacTokens(): void
    {
        // Should return empty array when none exist
        $this->assertSame([], $this->user->accessTokens());

        // Give the user a couple of access tokens
        $token1 = fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => 'hmac_sha256', 'secret' => 'key1', 'secret2' => 'd862cd9ddc23e960ca6d45a3e0b64c7509f0c0ef0e5f7b64be8910a6a714c89b83fab95251bbf17f6c84b42c26cf460a28ea969591dc64b1f5c4b323f47615d2e8cbe4c62118001d3274e0f25850b0ac2617bc43119af22c99a1a83072002267177da01f9f37225435e1914be004f4d35a49869b737ed10ab232c1ed1048bb9']
        );

        $token2 = fake(
            UserIdentityModel::class,
            ['user_id' => $this->user->id, 'type' => 'hmac_sha256', 'secret' => 'key2', 'secret2' => 'd862cd9ddc23e960ca6d45a3e0b64c7509f0c0ef0e5f7b64be8910a6a714c89b83fab95251bbf17f6c84b42c26cf460a28ea969591dc64b1f5c4b323f47615d2e8cbe4c62118001d3274e0f25850b0ac2617bc43119af22c99a1a83072002267177da01f9f37225435e1914be004f4d35a49869b737ed10ab232c1ed1048bb9']
        );

        $tokens = $this->user->hmacTokens();

        $this->assertCount(2, $tokens);
        $this->assertSame($token1->id, $tokens[0]->id);
        $this->assertSame($token1->secret, $tokens[0]->secret); // Key
        $this->assertSame($token1->secret2, $tokens[0]->secret2); // Secret Key
        $this->assertSame($token2->id, $tokens[1]->id);
        $this->assertSame($token2->secret, $tokens[1]->secret);
        $this->assertSame($token2->secret2, $tokens[1]->secret2);
    }

    public function testGetHmacToken(): void
    {
        // Should return null when not found
        $this->assertNull($this->user->getHmacToken('foo'));

        $token = $this->user->generateHmacToken('foo');

        $found = $this->user->getHmacToken($token->secret);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
        $this->assertSame($token->secret, $found->secret); // Key
        $this->assertSame($token->secret2, $found->secret2); // Secret Key
    }

    public function testGetHmacTokenById(): void
    {
        // Should return null when not found
        $this->assertNull($this->user->getHmacTokenById(123));

        $token = $this->user->generateHmacToken('foo');
        $found = $this->user->getHmacTokenById($token->id);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
        $this->assertSame($token->secret, $found->secret); // Key
        $this->assertSame($token->secret2, $found->secret2); // Secret Key
    }

    public function testRevokeHmacToken(): void
    {
        $token = $this->user->generateHmacToken('foo');

        $this->assertCount(1, $this->user->hmacTokens());

        $this->user->revokeHmacToken($token->secret);

        $this->assertCount(0, $this->user->hmacTokens());
    }

    public function testRevokeAllHmacTokens(): void
    {
        $this->user->generateHmacToken('foo');
        $this->user->generateHmacToken('foo');

        $this->assertCount(2, $this->user->hmacTokens());

        $this->user->revokeAllHmacTokens();

        $this->assertCount(0, $this->user->hmacTokens());
    }

    public function testHmacTokenCanNoTokenSet(): void
    {
        $this->assertFalse($this->user->hmacTokenCan('foo'));
    }

    public function testHmacTokenCanBasics(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar']);
        $this->user->setHmacToken($token);

        $this->assertTrue($this->user->hmacTokenCan('foo:bar'));
        $this->assertFalse($this->user->hmacTokenCan('foo:baz'));
    }

    public function testHmacTokenCantNoTokenSet(): void
    {
        $this->assertTrue($this->user->hmacTokenCant('foo'));
    }

    public function testHmacTokenCant(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar']);
        $this->user->setHmacToken($token);

        $this->assertFalse($this->user->hmacTokenCant('foo:bar'));
        $this->assertTrue($this->user->hmacTokenCant('foo:baz'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testGenerateTokenWithExpiration(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

        $this->assertSame('2024-11-03 12:00:00', $this->user->getHmacTokenTimeToExpire($token, 'date'));

        $token = $this->user->generateHmacToken('foo', ['foo:bar'], '1 month 1 year');

        $expireDate = new DateTime();
        $expireDate->add(DateInterval::createFromDateString('1 month 1 year'));

        $this->assertSame($expireDate->format('Y-m-d h:i:s'), $this->user->getHmacTokenTimeToExpire($token, 'date'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testSetTokenExpirationById(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar']);

        $this->assertNull($token->expires);

        // true = updated row
        $this->assertTrue($this->user->setHmacTokenExpirationById($token->id, '2024-11-03 12:00:00'));

        $found = $this->user->getHmacTokenById($token->id);
        $this->assertSame('2024-11-03 12:00:00', $this->user->getHmacTokenTimeToExpire($found, 'date'));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testIsHmacTokenExpired(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar'], '2024-11-03 12:00:00');

        $this->assertTrue($this->user->hasHmacTokenExpired($token));
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testHmacTokenTimeToExpired(): void
    {
        $token = $this->user->generateHmacToken('foo', ['foo:bar'], '1 year');

        $this->assertSame('in 1 year', $this->user->getHmacTokenTimeToExpire($token, 'human'));
    }
}
