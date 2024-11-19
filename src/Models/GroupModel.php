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

namespace CodeIgniter\Shield\Models;

use CodeIgniter\Shield\Entities\User;

class GroupModel extends BaseModel
{
    protected $primaryKey     = 'id';
    protected $returnType     = 'array';
    protected $useSoftDeletes = false;
    protected $allowedFields  = [
        'user_id',
        'group',
        'created_at',
    ];
    protected $useTimestamps      = false;
    protected $validationRules    = [];
    protected $validationMessages = [];
    protected $skipValidation     = false;

    protected function initialize(): void
    {
        parent::initialize();

        $this->table = $this->tables['groups_users'];
    }

    public function getForUser(User $user): array
    {
        $rows = $this->builder()
            ->select('group')
            ->where('user_id', $user->id)
            ->get()
            ->getResultArray();

        return array_column($rows, 'group');
    }

    /**
     * @param int|string $userId
     */
    public function deleteAll($userId): void
    {
        $return = $this->builder()
            ->where('user_id', $userId)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * @param int|string $userId
     * @param mixed      $cache
     */
    public function deleteNotIn($userId, $cache): void
    {
        $return = $this->builder()
            ->where('user_id', $userId)
            ->whereNotIn('group', $cache)
            ->delete();

        $this->checkQueryReturn($return);
    }

    /**
     * @param non-empty-string $group Group name
     */
    public function isValidGroup(string $group): bool
    {
        $allowedGroups = array_keys(shieldSetting('AuthGroups.groups'));

        return in_array($group, $allowedGroups, true);
    }
}
