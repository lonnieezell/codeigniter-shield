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

namespace CodeIgniter\Shield\Entities;

use CodeIgniter\Entity\Entity;

/**
 * Represents a single User Group
 * and provides utility functions.
 */
class Group extends Entity
{
    protected ?array $permissions = null;

    /**
     * Returns the permissions for this group.
     */
    public function permissions(): array
    {
        $this->populatePermissions();

        return $this->permissions;
    }

    /**
     * Overrides and saves all permissions in the class
     * with the permissions array that is passed in.
     */
    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;

        $matrix = shieldSetting('AuthGroups.matrix');

        $matrix[$this->alias] = $permissions;

        shieldSetting('AuthGroups.matrix', $matrix);
    }

    /**
     * Adds a single permission to this group and saves it.
     */
    public function addPermission(string $permission): void
    {
        $this->populatePermissions();

        array_unshift($this->permissions, $permission);

        $this->setPermissions($this->permissions);
    }

    /**
     * Removes a single permission from this group and saves it.
     */
    public function removePermission(string $permission): void
    {
        $this->populatePermissions();

        unset($this->permissions[array_search($permission, $this->permissions, true)]);

        $this->setPermissions($this->permissions);
    }

    /**
     * Determines if the group has the given permission
     */
    public function can(string $permission): bool
    {
        $this->populatePermissions();

        // Check exact match
        if ($this->permissions !== null && $this->permissions !== [] && in_array($permission, $this->permissions, true)) {
            return true;
        }

        // Check wildcard match
        $check = substr($permission, 0, strpos($permission, '.')) . '.*';

        return $this->permissions !== null && $this->permissions !== [] && in_array($check, $this->permissions, true);
    }

    /**
     * Loads our permissions for this group.
     */
    private function populatePermissions(): void
    {
        if ($this->permissions !== null) {
            return;
        }

        $this->permissions = shieldSetting('AuthGroups.matrix')[$this->alias] ?? [];
    }
}
