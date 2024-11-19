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
use CodeIgniter\Shield\Entities\Group;
use CodeIgniter\Test\DatabaseTestTrait;
use RuntimeException;
use Tests\Support\TestCase;

/**
 * @internal
 */
final class GroupsTest extends TestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;
    protected $namespace;

    /**
     * @var Groups
     */
    protected $groups;

    protected function setUp(): void
    {
        parent::setUp();

        $this->groups = new Groups();
    }

    public function testGroupInfoBadName(): void
    {
        $this->assertNull($this->groups->info('foo'));
    }

    public function testGroupInfo(): void
    {
        $group = $this->groups->info('admin');

        $this->assertInstanceOf(Group::class, $group);
        $this->assertSame('Admin', $group->title);
        $this->assertSame(shieldSetting('AuthGroups.groups')['admin']['description'], $group->description);
        $this->assertSame('admin', $group->alias);
    }

    public function testSaveGroupCreatesNew(): void
    {
        $group = new Group([
            'alias'       => 'foo',
            'title'       => 'Foo Dog',
            'description' => 'Foo Dog was here',
        ]);

        $this->groups->save($group);

        $this->assertInstanceOf(Group::class, $this->groups->info('foo'));
    }

    public function testSaveGroupCreatesNewMakesAlias(): void
    {
        $group = new Group([
            'title'       => 'Foo Dog',
            'description' => 'Foo Dog was here',
        ]);

        $this->groups->save($group);

        $this->assertInstanceOf(Group::class, $this->groups->info('foo-dog'));
    }

    public function testSaveGroupThrowsOnMissingTitle(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(lang('Auth.missingTitle'));

        $group = new Group([
            'description' => 'Foo Dog was here',
        ]);

        $this->groups->save($group);
    }
}
