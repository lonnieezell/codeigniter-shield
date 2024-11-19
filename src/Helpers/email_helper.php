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

use CodeIgniter\Email\Email;

if (! function_exists('emailer')) {
    /**
     * Provides convenient access to the CodeIgniter Email class.
     *
     * @param array<string, mixed> $overrides Email preferences to override.
     *
     * @internal
     */
    function emailer(array $overrides = []): Email
    {
        $config = [
            'userAgent'     => shieldSetting('Email.userAgent'),
            'protocol'      => shieldSetting('Email.protocol'),
            'mailPath'      => shieldSetting('Email.mailPath'),
            'SMTPHost'      => shieldSetting('Email.SMTPHost'),
            'SMTPUser'      => shieldSetting('Email.SMTPUser'),
            'SMTPPass'      => shieldSetting('Email.SMTPPass'),
            'SMTPPort'      => shieldSetting('Email.SMTPPort'),
            'SMTPTimeout'   => shieldSetting('Email.SMTPTimeout'),
            'SMTPKeepAlive' => shieldSetting('Email.SMTPKeepAlive'),
            'SMTPCrypto'    => shieldSetting('Email.SMTPCrypto'),
            'wordWrap'      => shieldSetting('Email.wordWrap'),
            'wrapChars'     => shieldSetting('Email.wrapChars'),
            'mailType'      => shieldSetting('Email.mailType'),
            'charset'       => shieldSetting('Email.charset'),
            'validate'      => shieldSetting('Email.validate'),
            'priority'      => shieldSetting('Email.priority'),
            'CRLF'          => shieldSetting('Email.CRLF'),
            'newline'       => shieldSetting('Email.newline'),
            'BCCBatchMode'  => shieldSetting('Email.BCCBatchMode'),
            'BCCBatchSize'  => shieldSetting('Email.BCCBatchSize'),
            'DSN'           => shieldSetting('Email.DSN'),
        ];

        if ($overrides !== []) {
            $config = array_merge($config, $overrides);
        }

        /** @var Email $email */
        $email = service('email');

        return $email->initialize($config);
    }
}
