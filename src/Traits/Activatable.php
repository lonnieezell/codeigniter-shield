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

namespace CodeIgniter\Shield\Traits;

trait Activatable
{
    /**
     * Returns true if the user has been activated
     * and activation is required after registration.
     */
    public function isActivated(): bool
    {
        // If activation is not required, then we're always active.
        return ! $this->shouldActivate() || $this->active;
    }

    /**
     * Returns true if the user has not been activated.
     */
    public function isNotActivated(): bool
    {
        return ! $this->isActivated();
    }

    /**
     * Activates the user.
     */
    public function activate(): void
    {
        $users = auth()->getProvider();

        $users->update($this->id, ['active' => 1]);
    }

    /**
     * Deactivates the user.
     */
    public function deactivate(): void
    {
        $users = auth()->getProvider();

        $users->update($this->id, ['active' => 0]);
    }

    /**
     * Does the Auth actions require activation?
     * Check for the generic 'Activator' class name to allow
     * for custom implementations, provided they follow the naming convention.
     */
    private function shouldActivate(): bool
    {
        return strpos(shieldSetting('Auth.actions')['register'] ?? '', 'Activator') !== false;
    }
}
