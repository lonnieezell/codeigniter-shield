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

namespace Tests\Commands;

use CodeIgniter\Shield\Authentication\HMAC\HmacEncrypter;
use CodeIgniter\Shield\Commands\Hmac;
use CodeIgniter\Shield\Config\AuthToken;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Test\MockInputOutput;
use Tests\Support\DatabaseTestCase;

/**
 * @internal
 */
final class HmacTest extends DatabaseTestCase
{
    private ?MockInputOutput $io = null;

    public function testEncrypt(): void
    {
        $idModel = new UserIdentityModel();

        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateHmacToken('foo');

        $rawSecretKey   = $token->rawSecretKey;
        $token->secret2 = $rawSecretKey;

        $idModel->save($token);
        $tokenCheck = $idModel->find($token->id);

        $this->assertSame($rawSecretKey, $tokenCheck->secret2);

        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac encrypt'));

        $tokenCheck = $idModel->find($token->id);

        $encrypter    = new HmacEncrypter();
        $decryptedKey = $encrypter->decrypt($tokenCheck->secret2);

        $this->assertSame($rawSecretKey, $decryptedKey);

        // verify that encryption can only happen once
        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac encrypt'));

        $resultsString = trim($this->io->getOutputs());
        $this->assertSame('id: 1, already encrypted, skipped.', $resultsString);
    }

    public function testDecrypt(): void
    {
        $idModel = new UserIdentityModel();

        /** @var User $user */
        $user  = fake(UserModel::class);
        $token = $user->generateHmacToken('foo');

        $rawSecretKey = $token->rawSecretKey;

        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac decrypt'));

        $token->secret2 = $rawSecretKey;

        $idModel->save($token);
        $tokenCheck = $idModel->find($token->id);

        $this->assertSame($rawSecretKey, $tokenCheck->secret2);

        // verify that decryption does not run on fields already decrypted
        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac decrypt'));

        $resultsString = trim($this->io->getOutputs());
        $this->assertSame('id: 1, not encrypted, skipped.', $resultsString);
    }

    public function testReEncrypt(): void
    {
        $idModel = new UserIdentityModel();

        // generate first token
        /** @var User $user */
        $user   = fake(UserModel::class);
        $token1 = $user->generateHmacToken('foo');

        // update config, rotate keys
        /** @var AuthToken $config */
        $config = config('AuthToken');

        $config->hmacEncryptionCurrentKey = 'k2';

        // new key generated with updated encryption
        $token2 = $user->generateHmacToken('bar');

        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac reencrypt'));

        $resultsString = $this->io->getOutputs();
        $results       = explode("\n", trim($resultsString));

        // verify that only 1 key needed to be re-encrypted
        $this->assertCount(2, $results);
        $this->assertSame('id: 1, Re-encrypted.', trim($results[0]));
        $this->assertSame('id: 2, already encrypted with current key, skipped.', trim($results[1]));

        $encrypter = new HmacEncrypter();

        $tokenCheck1        = $idModel->find($token1->id);
        $descryptSecretKey1 = $encrypter->decrypt($tokenCheck1->secret2);
        $this->assertSame($token1->rawSecretKey, $descryptSecretKey1);

        $tokenCheck2        = $idModel->find($token2->id);
        $descryptSecretKey2 = $encrypter->decrypt($tokenCheck2->secret2);
        $this->assertSame($token2->rawSecretKey, $descryptSecretKey2);
    }

    public function testBadCommand(): void
    {
        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac badcommand'));

        $resultsString = $this->stripRedColorCode(trim($this->io->getOutputs()));

        $this->assertSame('Unrecognized Command', $resultsString);
    }

    /**
     * See https://github.com/codeigniter4/shield/issues/926
     */
    public function testExpireAll(): void
    {
        /** @var User $user */
        $user = fake(UserModel::class);
        $user->generateHmacToken('foo', expiresAt: '2024-10-01 12:20:00');
        $user->generateHmacToken('bar');

        $this->setMockIo([]);
        $this->assertNotFalse(command('shield:hmac expireAll'));

        $resultsString = $this->io->getOutputs();
        $results       = explode("\n", trim($resultsString));

        $this->assertCount(2, $results);
        $this->assertSame('Hmac Key/Token ID: 1, already expired, skipped.', trim($results[0]));
        $this->assertSame('Hmac Key/Token ID: 2, set as expired.', trim($results[1]));
    }

    /**
     * Set MockInputOutput and user inputs.
     *
     * @param list<string> $inputs User inputs
     */
    private function setMockIo(array $inputs): void
    {
        $this->io = new MockInputOutput();
        $this->io->setInputs($inputs);
        Hmac::setInputOutput($this->io);
    }

    /**
     * Strip color from output code
     */
    private function stripRedColorCode(string $output): string
    {
        $output = str_replace(["\033[0;31m", "\033[0m"], '', $output);

        if (is_windows()) {
            $output = str_replace("\r\n", "\n", $output);
        }

        return $output;
    }
}
