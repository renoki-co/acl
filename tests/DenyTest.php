<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;

class DenyTest extends TestCase
{
    public function test_deny_policy_on_every_resource_without_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Describe',
                'Resource' => '*',
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:List',
                'Resource' => '*',
            ],
        ]);

        $this->assertTrue($policy->allows('vps:List', 'arn:php:service1:local:000:vps'));
        $this->assertTrue($policy->allows('vps:List', 'arn:php:service1:local:111:vps'));

        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_deny_policy_on_every_resource_restricted_to_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Describe',
                'Resource' => '*',
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:List',
                'Resource' => '*',
            ],
        ]);

        $policy->setRootAccount('000');

        $this->assertTrue($policy->allows('vps:List', 'arn:php:service1:local:000:vps'));
        $this->assertFalse($policy->allows('vps:List', 'arn:php:service1:local:111:vps'));

        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_deny_policy_on_every_action_restricted_to_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Deny',
                'Action' => '*',
                'Resource' => 'arn:php:service1:local:000:vps/vps-000',
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Describe',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                    'arn:php:service1:local:000:vps/vps-111',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:111:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:111:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Describe', 'arn:php:service1:local:000:vps/vps-111'));

        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:111:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Describe', 'arn:php:service1:local:111:vps/vps-111'));
    }

    public function test_allow_policy_on_everything_restricted_by_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => '*',
                'Resource' => '*',
            ],
        ]);

        $policy->setRootAccount('000');

        $accounts = ['000', '111'];

        $this->assertTrue($policy->allows('*', '*'));

        foreach ($accounts as $account) {
            $accountMatchesRoot = $account === '000';

            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:*', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:*', "arn:php:service1:local:{$account}:vps/vps-000"));

            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-333"));

            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-333"));

            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertEquals($accountMatchesRoot, $policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-333"));
        }
    }

    public function test_explicit_deny_on_specific_resources_blocks_access_to_individual_resources_only()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_explicit_deny_on_wildcard_resources_blocks_access_to_those_resources_when_allows_cover_specific_resources()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                ],
            ],
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Shutdown',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:111:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_explicit_deny_on_wildcard_resources_blocks_access_to_those_resources_when_allows_cover_wildcard_resources()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Shutdown',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:111:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_explicit_deny_on_wildcard_actions_blocks_access_to_those_actions_when_allows_cover_wildcard_resources()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:*',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
            [
                'Effect' => 'Deny',
                'Action' => 'vps:Shutdown',
                'Resource' => [
                    'arn:php:service1:local:000:vps/*',
                ],
            ],
        ]);

        $this->assertTrue($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:111:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:111:vps/vps-000'));
    }
}
