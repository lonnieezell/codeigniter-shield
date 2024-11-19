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

namespace CodeIgniter\Shield\Authorization;

use CodeIgniter\Shield\Entities\Group;
use CodeIgniter\Shield\Exceptions\RuntimeException;

/**
 * Provides utility feature for working with
 * groups, adding permissions, etc.
 */
class Groups
{
    /**
     * Grabs a group info from settings.
     */
    public function info(string $group): ?Group
    {
        $info = shieldSetting('AuthGroups.groups')[strtolower($group)] ?? null;

        if (empty($info)) {
            return null;
        }

        $info['alias'] = $group;

        return new Group($info);
    }

    /**
     * Saves or creates the group.
     */
    public function save(Group $group): void
    {
        if (empty($group->title)) {
            throw new RuntimeException(lang('Auth.missingTitle'));
        }

        $groups = shieldSetting('AuthGroups.groups');

        $alias = $group->alias;

        if (empty($alias)) {
            $alias = strtolower(url_title($group->title));
        }

        $groups[$alias] = [
            'title'       => $group->title,
            'description' => $group->description,
        ];

        // Save it
        shieldSetting('AuthGroups.groups', $groups);
    }
}
