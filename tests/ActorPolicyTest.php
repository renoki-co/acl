<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;
use RenokiCo\Acl\Exceptions\WildcardNotPermittedException;
use RenokiCo\Acl\Statement;
use RenokiCo\Acl\Test\Fixtures\User;
use RenokiCo\Acl\Test\Fixtures\Vps;

class ActorPolicyTest extends TestCase
{
    public function test_actor_policy_wildcards_are_not_permitted()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: '*',
                resource: '*'
            ),
        ]);

        $user = new User('user-1', team: 'team-1');
        $user->loadPolicies($policy);

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('*', '*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('vps:*', '*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('*', 'arn:*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('vps:*', 'arn:*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('vps:*', 'arn:*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('vps:Read', 'arn:*');
        $this->expectException('');

        $this->expectException(WildcardNotPermittedException::class);
        $user->isAllowedTo('vps:*', new Vps('vps-000', team: 'team-1'));
        $this->expectException('');
    }

    public function test_actor_policy_allow_wildcard_on_wildcard_resources_is_restricted_to_its_account_only()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: '*',
                resource: '*'
            ),
        ]);

        $user = new User('user-1', team: 'team-1');
        $user->loadPolicies($policy);

        $this->assertTrue($user->isAllowedTo('vps:Read', new Vps('vps-000', team: 'team-1')));
        $this->assertTrue($user->isAllowedTo('vps:Read', new Vps('vps-000', team: 'team-1')));
        $this->assertTrue($user->isAllowedTo('vps:List', Vps::class));
        $this->assertTrue($user->isAllowedTo('vps:List', Vps::class));

        $this->assertFalse($user->isAllowedTo('vps:Read', 'arn:php:default:local:team-2:vps/vps-111'));
        $this->assertFalse($user->isAllowedTo('vps:Read', 'arn:php:default:local:team-2:vps/vps-111'));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:default:local:team-2:vps'));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:default:local:team-2:vps'));
    }

    public function test_actor_policy_allow_wildcard_on_partial_wildcard_resources_is_restricted_to_its_account_only()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: '*',
                resource: [
                    'arn:php:default:local:*:*',
                    'arn:php:default:local:*:*/*',
                ],
            ),
        ]);

        $user = new User('user-1', team: 'team-1');
        $user->loadPolicies($policy);

        $this->assertTrue($user->isAllowedTo('vps:Read', new Vps('vps-000', team: 'team-1')));
        $this->assertTrue($user->isAllowedTo('vps:List', Vps::class));

        $this->assertFalse($user->isAllowedTo('vps:Read', 'arn:php:default:local:team-2:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:default:local:team-2:vps'));
    }

    public function test_actor_policy_allow_specific_actions_on_specific_arns()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: 'vps:List',
                resource: [
                    'arn:php:default:local:team-1:vps',
                ],
            ),
            Statement::make(
                action: 'vps:Describe',
                resource: [
                    'arn:php:default:local:team-1:vps/vps-000',
                ],
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:List', Vps::class));
        $this->assertTrue($user->isAllowedTo('vps:Describe', new Vps('vps-000', team: 'team-1')));

        $this->assertFalse($user->isAllowedTo('vps:List', new Vps('vps-000', team: 'team-1')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', Vps::class));
    }

    public function test_actor_policy_allow_specific_actions_on_wildcard_resources()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: [
                    'vps:List',
                    'vps:Describe',
                ],
                resource: '*',
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:Describe', new Vps('vps-000', team: 'team-1')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', new Vps('vps-111', team: 'team-2')));

        $this->assertTrue($user->isAllowedTo('vps:List', Vps::class));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:default:local:team-2:vps'));
    }

    public function test_actor_policy_denies_specific_resource_from_wildcard_allow()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: 'vps:Describe',
                resource: [
                    'arn:php:default:local:team-1:vps/*',
                ],
            ),
            Statement::make(
                effect: 'Deny',
                action: 'vps:Describe',
                resource: [
                    'arn:php:default:local:team-1:vps/vps-000',
                ],
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', new Vps('vps-000', team: 'team-1')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', new Vps('vps-000', team: 'team-2')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', Vps::class));

        $this->assertTrue($user->isAllowedTo('vps:Describe', new Vps('vps-111', team: 'team-1')));
        $this->assertFalse($user->isAllowedTo('vps:Describe', new Vps('vps-111', team: 'team-2')));
    }

    public function test_actor_policy_denies_specific_action_on_every_resource()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                effect: 'Deny',
                action: 'vps:Describe',
                resource: '*',
            ),
            Statement::make(
                effect: 'Allow',
                action: 'vps:List',
                resource: '*',
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:List', 'arn:php:local:local:team-1:vps'));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:local:local:team-2:vps'));

        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:local:local:team-1:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:local:local:team-1:vps/vps-111'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:local:local:team-2:vps/vps-000'));
    }

    public function test_actor_policy_denies_all_actions_on_a_single_resource_even_when_other_allows_exist()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                effect: 'Deny',
                action: '*',
                resource: 'arn:php:default:local:*:vps/vps-000',
            ),
            Statement::make(
                effect: 'Allow',
                action: 'vps:Describe',
                resource: [
                    'arn:php:default:local:*:vps/vps-000',
                    'arn:php:default:local:*:vps/vps-111',
                ],
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-1:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-2:vps/vps-000'));
        $this->assertTrue($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-1:vps/vps-111'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-2:vps/vps-111'));

        $this->assertFalse($user->isAllowedTo('vps:Delete', 'arn:php:default:local:team-1:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:Delete', 'arn:php:default:local:team-2:vps/vps-000'));
    }

    public function test_actor_policy_denies_specific_action_on_all_resources_even_when_other_allows_exist()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                effect: 'Deny',
                action: 'vps:Shutdown',
                resource: 'arn:php:default:local:*:vps/*',
            ),
            Statement::make(
                effect: 'Allow',
                action: 'vps:*',
                resource: [
                    'arn:php:default:local:*:vps',
                    'arn:php:default:local:*:vps/*',
                ],
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);

        $this->assertTrue($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-1:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-2:vps/vps-000'));

        $this->assertTrue($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-1:vps/vps-111'));
        $this->assertTrue($user->isAllowedTo('vps:List', 'arn:php:default:local:team-1:vps'));
        $this->assertFalse($user->isAllowedTo('vps:Describe', 'arn:php:default:local:team-2:vps/vps-111'));
        $this->assertFalse($user->isAllowedTo('vps:List', 'arn:php:default:local:team-2:vps'));

        $this->assertFalse($user->isAllowedTo('vps:Shutdown', 'arn:php:default:local:team-1:vps/vps-000'));
        $this->assertFalse($user->isAllowedTo('vps:Shutdown', 'arn:php:default:local:team-2:vps/vps-000'));
    }

    public function add()
    {
        $policy = Acl::createPolicy([
            Statement::make(
                action: [
                    'vps:List',
                    'vps:Describe',
                ],
                resource: '*',
            ),
        ]);

        $user = new User('user-1');
        $user->loadPolicies([$policy]);
    }
}
