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
use CodeIgniter\Shield\Authentication\Authenticators\AccessTokens;
use CodeIgniter\Shield\Entities\AccessToken;
use CodeIgniter\Shield\Models\UserIdentityModel;
use InvalidArgumentException;

/**
 * Trait HasAccessTokens
 *
 * Provides functionality needed to generate, revoke,
 * and retrieve Personal Access Tokens.
 *
 * Intended to be used with User entities.
 */
trait HasAccessTokens
{
    /**
     * The current access token for the user.
     */
    private ?AccessToken $currentAccessToken = null;

    /**
     * Generates a new personal access token for this user.
     *
     * @param string       $name      Token name
     * @param list<string> $scopes    Permissions the token grants
     * @param string       $expiresAt Sets token expiration date. Accepts DateTime string formatted as 'Y-m-d h:i:s' or DateTime relative formats (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'
     *
     * @throws InvalidArgumentException
     */
    public function generateAccessToken(string $name, array $scopes = ['*'], ?string $expiresAt = null): AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->generateAccessToken($this, $name, $scopes, $expiresAt);
    }

    /**
     * Delete any access tokens for the given raw token.
     */
    public function revokeAccessToken(string $rawToken): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAccessToken($this, $rawToken);
    }

    /**
     * Delete any access tokens for the given secret token.
     */
    public function revokeAccessTokenBySecret(string $secretToken): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAccessTokenBySecret($this, $secretToken);
    }

    /**
     * Revokes all access tokens for this user.
     */
    public function revokeAllAccessTokens(): void
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        $identityModel->revokeAllAccessTokens($this);
    }

    /**
     * Retrieves all personal access tokens for this user.
     *
     * @return list<AccessToken>
     */
    public function accessTokens(): array
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAllAccessTokens($this);
    }

    /**
     * Given a raw token, will hash it and attempt to
     * locate it within the system.
     */
    public function getAccessToken(?string $rawToken): ?AccessToken
    {
        if ($rawToken === null || $rawToken === '') {
            return null;
        }

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAccessToken($this, $rawToken);
    }

    /**
     * Given the ID, returns the given access token.
     */
    public function getAccessTokenById(int $id): ?AccessToken
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getAccessTokenById($id, $this);
    }

    /**
     * Determines whether the user's token grants permissions to $scope.
     * First checks against $this->activeToken, which is set during
     * authentication. If it hasn't been set, returns false.
     */
    public function tokenCan(string $scope): bool
    {
        if (! $this->currentAccessToken() instanceof AccessToken) {
            return false;
        }

        return $this->currentAccessToken()->can($scope);
    }

    /**
     * Determines whether the user's token does NOT grant permissions to $scope.
     * First checks against $this->activeToken, which is set during
     * authentication. If it hasn't been set, returns true.
     */
    public function tokenCant(string $scope): bool
    {
        if (! $this->currentAccessToken() instanceof AccessToken) {
            return true;
        }

        return $this->currentAccessToken()->cant($scope);
    }

    /**
     * Returns the current access token for the user.
     */
    public function currentAccessToken(): ?AccessToken
    {
        return $this->currentAccessToken;
    }

    /**
     * Sets the current active token for this user.
     *
     * @return $this
     */
    public function setAccessToken(?AccessToken $accessToken): self
    {
        $this->currentAccessToken = $accessToken;

        return $this;
    }

    /**
     * Checks if the provided Access Token has expired.
     *
     * @return bool|null Returns true if Access Token has expired, false if not, and null if the expire field is null
     */
    public function hasAccessTokenExpired(?AccessToken $accessToken): bool|null
    {
        return $accessToken->expires !== null ? $accessToken->expires->isBefore(Time::now()) : null;
    }

    /**
     * Returns formatted date to expiration for provided AccessToken
     *
     * @param AccessToken $accessToken AccessToken
     * @param string      $format      The return format - "date" or "human".  Date is 'Y-m-d h:i:s', human is 'in 2 weeks'
     *
     * @return string|null Returns a formatted expiration date or null if the expire field is not set.
     *
     * @throws InvalidArgumentException
     */
    public function getAccessTokenTimeToExpire(?AccessToken $accessToken, string $format = 'date'): string|null
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
                throw new InvalidArgumentException('getAccessTokenTimeToExpire(): $format argument is invalid. Expects string with "date" or "human".');
        }
    }

    /**
     * Sets an expiration for Access Tokens by ID.
     *
     * @param int    $id        AccessTokens ID
     * @param string $expiresAt Expiration date. Accepts DateTime string formatted as 'Y-m-d h:i:s' or DateTime relative formats (1 day, 2 weeks, 6 months, 1 year) to be added to DateTime 'now'
     *
     * @return bool Returns true if expiration date is set or updated.
     */
    public function setAccessTokenExpirationById(int $id, string $expiresAt): bool
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);
        $result        = $identityModel->setIdentityExpirationById($id, $this, $expiresAt, AccessTokens::ID_TYPE_ACCESS_TOKEN);

        if ($result) {
            // refresh currentAccessToken with updated data
            $this->currentAccessToken = $identityModel->getAccessTokenById($id, $this);
        }

        return $result;
    }
}
