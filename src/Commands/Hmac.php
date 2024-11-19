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

namespace CodeIgniter\Shield\Commands;

use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\HMAC\HmacEncrypter;
use CodeIgniter\Shield\Commands\Exceptions\BadInputException;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use CodeIgniter\Shield\Models\UserIdentityModel;
use Exception;
use ReflectionException;

class Hmac extends BaseCommand
{
    /**
     * The Command's name
     *
     * @var string
     */
    protected $name = 'shield:hmac';

    /**
     * the Command's short description
     *
     * @var string
     */
    protected $description = 'Encrypt/Decrypt secretKey for HMAC tokens.';

    /**
     * the Command's usage
     *
     * @var string
     */
    protected $usage = <<<'EOL'
        shield:hmac <action>
            shield:hmac reencrypt
            shield:hmac encrypt
            shield:hmac decrypt
            shield:hmac invalidateAll

            The reencrypt command should be used when rotating the encryption keys.
            The encrypt command should only be run on existing raw secret keys (extremely rare).
            The invalidateAll command should only be run if you need to invalidate ALL HMAC Tokens  (for everyone).
        EOL;

    /**
     * the Command's Arguments
     *
     * @var array<string, string>
     */
    protected $arguments = [
        'action' => <<<'EOL'
                reencrypt: Re-encrypts all HMAC Secret Keys on encryption key rotation
                encrypt: Encrypt all raw HMAC Secret Keys
                decrypt: Decrypt all encrypted HMAC Secret Keys
                invalidateAll: Invalidates all HMAC Keys/Tokens (for everyone)
            EOL,
    ];

    /**
     * HMAC Encrypter Object
     */
    private HmacEncrypter $encrypter;

    /**
     * the Command's Options
     *
     * @var array<string, string>
     */
    protected $options = [];

    /**
     * Run Encryption Methods
     */
    public function run(array $params): int
    {
        $action = $params[0] ?? null;

        $this->encrypter = new HmacEncrypter();

        try {
            switch ($action) {
                case 'encrypt':
                    $this->encrypt();
                    break;

                case 'decrypt':
                    $this->decrypt();
                    break;

                case 'reencrypt':
                    $this->reEncrypt();
                    break;

                case 'expireAll':
                    $this->expireAll();
                    break;

                default:
                    throw new BadInputException('Unrecognized Command');
            }
        } catch (Exception $e) {
            $this->write($e->getMessage(), 'red');

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }

    /**
     * Encrypt all Raw HMAC Secret Keys
     *
     * @throws ReflectionException
     */
    public function encrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // For saving.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if ($encrypter->isEncrypted($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', already encrypted, skipped.');

                    return;
                }

                try {
                    $identity->secret2 = $encrypter->encrypt($identity->secret2);
                    $uIdModelSub->save($identity);

                    $that->write('id: ' . $identity->id . ', encrypted.');
                } catch (RuntimeException $e) {
                    $that->error('id: ' . $identity->id . ', ' . $e->getMessage());
                }
            }
        );
    }

    /**
     * Decrypt all encrypted HMAC Secret Keys
     *
     * @throws ReflectionException
     */
    public function decrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // For saving.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if (! $encrypter->isEncrypted($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', not encrypted, skipped.');

                    return;
                }

                $identity->secret2 = $encrypter->decrypt($identity->secret2);
                $uIdModelSub->save($identity);

                $that->write('id: ' . $identity->id . ', decrypted.');
            }
        );
    }

    /**
     * Re-encrypt all encrypted HMAC Secret Keys from existing/deprecated
     * encryption key to new encryption key.
     *
     * @throws ReflectionException
     */
    public function reEncrypt(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel(); // For saving.
        $encrypter   = $this->encrypter;

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $encrypter, $that): void {
                if ($encrypter->isEncryptedWithCurrentKey($identity->secret2)) {
                    $that->write('id: ' . $identity->id . ', already encrypted with current key, skipped.');

                    return;
                }

                $identity->secret2 = $encrypter->decrypt($identity->secret2);
                $identity->secret2 = $encrypter->encrypt($identity->secret2);
                $uIdModelSub->save($identity);

                $that->write('id: ' . $identity->id . ', Re-encrypted.');
            }
        );
    }

    /**
     * Invalidates all HMAC Keys/Tokens for every user.
     */
    public function expireAll(): void
    {
        $uIdModel    = new UserIdentityModel();
        $uIdModelSub = new UserIdentityModel();

        $that = $this;

        $uIdModel->where('type', 'hmac_sha256')->orderBy('id')->chunk(
            100,
            static function ($identity) use ($uIdModelSub, $that): void {
                $timeNow = Time::now(); // Current date/time

                if (null !== $identity->expires && $identity->expires->isBefore($timeNow)) {
                    $that->write('Hmac Key/Token ID: ' . $identity->id . ', already expired, skipped.');

                    return;
                }

                $identity->expires = $timeNow->format('Y-m-d h:i:s');
                $uIdModelSub->save($identity);

                $that->write('Hmac Key/Token ID: ' . $identity->id . ', set as expired.');
            }
        );
    }
}
