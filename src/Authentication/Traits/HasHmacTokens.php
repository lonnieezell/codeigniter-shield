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

namespace CodeIgniter\Shield\Authentication\Traits;

use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Authenticators\HmacSha256;
use CodeIgniter\Shield\Entities\AccessToken;
use CodeIgniter\Shield\Models\UserIdentityModel;
use InvalidArgumentException;
use ReflectionException;

/**
 * Trait HasHmacTokens
 *
 * Provides functionality needed to generate, revoke,
 * and retrieve Personal Access Tokens.
 *
 * Intended to be used with User entities.
 */
trait HasHmacTokens
{
    /**
     * The current access token for the user.
     */
    private ?AccessToken $currentHmacToken = null;

    /**
     * Generates a new personal HMAC token for this user.
     *
     * @param string       $name      Token name
     * @param list<string> $scopes    Permissions the token grants
     * @param string       $expiresAt Sets token expiration date. Accepts DateTime string formatted as 'Y-m-d h:i:s' or DateTime relative formats (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'
     *
     * @throws InvalidArgumentException
     * @throws ReflectionException
     */
    public function generateHmacToken(string $name, array $scopes = ['*'], ?string $expiresAt = null): AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->generateHmacToken($this, $name, $scopes, $expiresAt);
    }

    /**
     * Delete any HMAC tokens for the given key.
     */
    public function revokeHmacToken(string $key): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeHmacToken($this, $key);
    }

    /**
     * Revokes all HMAC tokens for this user.
     */
    public function revokeAllHmacTokens(): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAllHmacTokens($this);
    }

    /**
     * Retrieves all personal HMAC tokens for this user.
     *
     * @return list<AccessToken>
     */
    public function hmacTokens(): array
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAllHmacTokens($this);
    }

    /**
     * Given an HMAC Key, it will locate it within the system.
     */
    public function getHmacToken(?string $key): ?AccessToken
    {
        if (! isset($key) || $key === '') {
            return null;
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getHmacToken($this, $key);
    }

    /**
     * Given the ID, returns the given access token.
     */
    public function getHmacTokenById(int $id): ?AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getHmacTokenById($id, $this);
    }

    /**
     * Determines whether the user's token grants permissions to $scope.
     * First checks against $this->activeToken, which is set during
     * authentication. If it hasn't been set, returns false.
     */
    public function hmacTokenCan(string $scope): bool
    {
        if (! $this->currentHmacToken() instanceof AccessToken) {
            return false;
        }

        return $this->currentHmacToken()->can($scope);
    }

    /**
     * Determines whether the user's token does NOT grant permissions to $scope.
     * First checks against $this->activeToken, which is set during
     * authentication. If it hasn't been set, returns true.
     */
    public function hmacTokenCant(string $scope): bool
    {
        if (! $this->currentHmacToken() instanceof AccessToken) {
            return true;
        }

        return $this->currentHmacToken()->cant($scope);
    }

    /**
     * Returns the current HMAC token for the user.
     */
    public function currentHmacToken(): ?AccessToken
    {
        return $this->currentHmacToken;
    }

    /**
     * Sets the current active token for this user.
     *
     * @return $this
     */
    public function setHmacToken(?AccessToken $accessToken): self
    {
        $this->currentHmacToken = $accessToken;

        return $this;
    }

    /**
     * Checks if the provided Access Token has expired.
     *
     * @return false|true|null Returns true if Access Token has expired, false if not, and null if the expire field is null
     */
    public function hasHmacTokenExpired(?AccessToken $accessToken): bool|null
    {
        if (null === $accessToken->expires) {
            return null;
        }

        return $accessToken->expires->isBefore(Time::now());
    }

    /**
     * Returns formatted date to expiration for provided Hmac Key/Token.
     *
     * @param AcessToken $accessToken AccessToken
     * @param string     $format      The return format - "date" or "human".  Date is 'Y-m-d h:i:s', human is 'in 2 weeks'
     *
     * @return false|true|null Returns true if Access Token has expired, false if not and null if the expire field is null
     *
     * @throws InvalidArgumentException
     */
    public function getHmacTokenTimeToExpire(?AccessToken $accessToken, string $format = 'date'): string|null
    {
        if (null === $accessToken->expires) {
            return null;
        }

        switch ($format) {
            case 'date':
                return $accessToken->expires->toLocalizedString();

            case 'human':
                return $accessToken->expires->humanize();

            default:
                throw new InvalidArgumentException('getHmacTokenTimeToExpire(): $format argument is invalid. Expects string with "date" or "human".');
        }
    }

    /**
     * Sets an expiration for Hmac Key/Token by ID.
     *
     * @param int    $id        AccessTokens ID
     * @param string $expiresAt Expiration date. Accepts DateTime string formatted as 'Y-m-d h:i:s' or DateTime relative formats (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'
     *
     * @return false|true|null Returns true if token is updated, false if not.
     */
    public function setHmacTokenExpirationById(int $id, string $expiresAt): bool
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);
        $result        = $identityModel->setIdentityExpirationById($id, $this, $expiresAt, HmacSha256::ID_TYPE_HMAC_TOKEN);

        if ($result) {
            // refresh currentAccessToken with updated data
            $this->currentAccessToken = $identityModel->getHmacTokenById($id, $this);
        }

        return $result;
    }
}
