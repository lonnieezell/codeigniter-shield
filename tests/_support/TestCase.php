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

namespace Tests\Support;

use CodeIgniter\Config\Factories;
use CodeIgniter\Settings\Settings;
use CodeIgniter\Test\CIUnitTestCase;
use Config\Services;

/**
 * @internal
 */
abstract class TestCase extends CIUnitTestCase
{
    protected function setUp(): void
    {
        $this->resetServices();

        parent::setUp();

        // Use Array Settings Handler
        $configSettings           = config('Settings');
        $configSettings->handlers = ['array'];
        $settings                 = new Settings($configSettings);
        Services::injectMock('settings', $settings);

        // Load helpers that should be autoloaded
        helper(['auth', 'setting']);

        // Ensure from email is available anywhere during Tests
        shieldSetting('Email.fromEmail', 'foo@example.com');
        shieldSetting('Email.fromName', 'John Smith');

        // Clear any actions
        $config          = config('Auth');
        $config->actions = ['login' => null, 'register' => null];
        Factories::injectMock('config', 'Auth', $config);

        // Set Config\Security::$csrfProtection to 'session'
        $config                 = config('Security');
        $config->csrfProtection = 'session';
        Factories::injectMock('config', 'Security', $config);
    }
}
