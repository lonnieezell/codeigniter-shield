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

namespace Tests\Authorization;

use CodeIgniter\Shield\Authorization\Groups;
use CodeIgniter\Test\DatabaseTestTrait;
use Tests\Support\TestCase;

/**
 * @internal
 */
final class GroupTest extends TestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;
    protected $namespace;
    protected $groups;

    protected function setUp(): void
    {
        parent::setUp();

        $this->groups = new Groups();
    }

    public function testPermissions(): void
    {
        $group = $this->groups->info('admin');

        $permissions = $group->permissions();

        $this->assertIsArray($permissions);
        $this->assertContains('users.create', $permissions);
    }

    public function testSavePermissions(): void
    {
        $group = $this->groups->info('admin');

        $permissions = $group->permissions();
        unset($permissions[array_search('users.create', $permissions, true)]);

        $group->setPermissions($permissions);
        $permissions = $group->permissions();

        $this->assertNotContains('users.create', $permissions);
    }

    public function testAddPermission(): void
    {
        $group = $this->groups->info('admin');

        $group->addPermission('foo.bar');

        $permissions = $group->permissions();
        $this->assertContains('foo.bar', $permissions);
    }

    public function testRemovePermission(): void
    {
        $group = $this->groups->info('admin');

        $group->removePermission('users.edit');

        $permissions = $group->permissions();
        $this->assertNotContains('users.edit', $permissions);
    }

    public function testCan(): void
    {
        $group1 = $this->groups->info('superadmin');
        $group2 = $this->groups->info('admin');

        $this->assertTrue($group1->can('users.*'));
        $this->assertTrue($group2->can('users.edit'));
        $this->assertFalse($group2->can('foo.bar'));
    }
    
    public function testCanNestedPerms(): void
    {
        $group = $this->groups->info('user');
        $group->addPermission('foo.bar.*');
        $group->addPermission('foo.biz.buz.*');
        $this->assertTrue($group->can('foo.bar'));
        $this->assertTrue($group->can('foo.bar.baz'));
        $this->assertTrue($group->can('foo.bar.buz'));        
        $this->assertTrue($group->can('foo.bar.*'));
        $this->assertTrue($group->can('foo.biz.buz'));
        $this->assertFalse($group->can('foo.biz.*'));
        $this->assertTrue($group->can('foo.biz.buz.bar'));
        $this->assertFalse($group->can('foo.biz.bar.buz'));        
    }    
}
