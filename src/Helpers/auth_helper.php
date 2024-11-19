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

use CodeIgniter\Shield\Auth;
use CodeIgniter\Shield\Config\Auth as AuthConfig;

if (! function_exists('auth')) {
    /**
     * Provides convenient access to the main Auth class
     * for CodeIgniter Shield.
     *
     * @param string|null $alias Authenticator alias
     */
    function auth(?string $alias = null): Auth
    {
        /** @var Auth $auth */
        $auth = service('auth');

        return $auth->setAuthenticator($alias);
    }
}

if (! function_exists('user_id')) {
    /**
     * Returns the ID for the current logged-in user.
     *
     * @return int|string|null
     */
    function user_id()
    {
        /** @var Auth $auth */
        $auth = service('auth');

        return $auth->id();
    }
}

if (! function_exists('shieldSetting')) {
    /**
     * Provides a wrapper function for settings module.
     *
     * @param mixed $value
     *
     * @return array|bool|float|int|object|string|void|null
     * @phpstan-return ($value is null ? array|bool|float|int|object|string|null : void)
     */
    function shieldSetting(?string $key = null, $value = null)
    {
        /** @var AuthConfig $config */
        $config = config('Auth');
        if($config->useSettings) {
            return setting($key, $value);
        }

        // Getting the value?
        if (!empty($key) && count(func_get_args()) === 1) {
            $parts = explode('.', $key);
            if (count($parts) === 1) {
                throw new InvalidArgumentException('$key must contain both the class and field name, i.e. Foo.bar');
            }
            return config($parts[0])?->{$parts[1]} ?? null;
        }

        throw new InvalidArgumentException('Settings library is not being used for shield');
    }
}
