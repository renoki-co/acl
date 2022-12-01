<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;
use RenokiCo\Acl\Concerns\HasArn;
use RenokiCo\Acl\Concerns\HasPolicies;
use RenokiCo\Acl\Contracts\Arnable;
use RenokiCo\Acl\Contracts\RuledByPolicies;

class PolicyTest extends TestCase
{
    public function test_policy_allow_on_a_general_arn_instance()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:List',
                'Resource' => [
                    'arn:php:default:local:team-1:vps',
                ],
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Describe',
                'Resource' => [
                    'arn:php:default:local:team-1:vps/vps-xxx',
                ],
            ],
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-2'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertFalse($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx', 'team-2')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));
    }

    public function test_deny_arn_instance()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Describe',
                'Resource' => [
                    'arn:php:default:local:team-1:vps/*',
                ],
            ],
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Describe',
                'Resource' => [
                    'arn:php:default:local:team-1:vps/vps-xxx',
                ],
            ],
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-2'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-2'],
        ]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));
    }

    public function test_allow_arn_instance_for_resource_arn()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:List',
                'Resource' => [
                    'arn:php:default:local:team-1:vps',
                ],
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Describe',
                'Resource' => [
                    'arn:php:default:local:team-1:vps/vps-xxx',
                ],
            ],
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($user->isAllowedTo('vps:List', VpsWithTeam::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new VpsWithTeam('vps-xxx')));

        $this->assertFalse($user->isAllowedTo('vps:List', new VpsWithTeam('vps-xxx')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', VpsWithTeam::class));
    }
}

class User implements RuledByPolicies
{
    use HasPolicies;

    public function __construct(
        public string $id,
        public string $teamId = 'team-1',
    ) {
        //
    }

    public function resolveArnAccountId()
    {
        return $this->teamId;
    }
}

class VpsWithTeam implements Arnable
{
    use HasArn;

    public function __construct(
        public string $id = 'vps-xxx',
        public string $teamId = 'team-1',
    ) {
        //
    }

    public function arnResourceAccountId()
    {
        return $this->teamId;
    }

    public function arnResourceId()
    {
        return $this->id;
    }

    public static function arnResourceType()
    {
        return 'vps';
    }
}
