<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;

class AllowTest extends TestCase
{
    public function test_allow_policy_on_everything_without_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => '*',
                'Resource' => '*',
            ],
        ]);

        $accounts = ['000', '111'];

        $this->assertTrue($policy->allows('*', '*'));

        foreach ($accounts as $account) {
            $this->assertTrue($policy->allows('vps:*', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertTrue($policy->allows('vps:*', "arn:php:service1:local:{$account}:vps/vps-000"));

            $this->assertTrue($policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertTrue($policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertTrue($policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertTrue($policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertTrue($policy->allows('vps:Read', "arn:php:service1:local:{$account}:vps/vps-333"));

            $this->assertTrue($policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertTrue($policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertTrue($policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertTrue($policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertTrue($policy->allows('vps:Delete', "arn:php:service1:local:{$account}:vps/vps-333"));

            $this->assertTrue($policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/*"));
            $this->assertTrue($policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-000"));
            $this->assertTrue($policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-111"));
            $this->assertTrue($policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-222"));
            $this->assertTrue($policy->allows('vps:Shutdown', "arn:php:service1:local:{$account}:vps/vps-333"));
        }
    }

    public function test_allow_policy_on_everything_restricted_by_root_id()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => '*',
                'Resource' => '*',
            ],
        ], rootAccountId: '000');

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

    public function test_allow_policy_on_all_actions_on_specific_resource()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => '*',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertTrue($policy->allows('*', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:111:vps/vps-000'));
    }

    public function test_allow_policy_on_all_actions_on_all_resources()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
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
    }

    public function test_individual_actions_on_specific_resources_pass_through()
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
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-111',
                ],
            ],
            [
                'Effect' => 'Allow',
                'Action' => 'vps:Read',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-222',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-333'));
    }

    public function test_wildcard_actions_on_specific_resources_pass_through()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:*',
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                    'arn:php:service1:local:000:vps/vps-111',
                    'arn:php:service1:local:000:vps/vps-222',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-333'));
    }

    public function test_multiple_specific_actions_on_specific_resources_pass_through()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => [
                    'vps:Read',
                    'vps:Shutdown',
                ],
                'Resource' => [
                    'arn:php:service1:local:000:vps/vps-000',
                    'arn:php:service1:local:000:vps/vps-111',
                    'arn:php:service1:local:000:vps/vps-222',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));

        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-333'));
    }

    public function test_individual_actions_on_wildcard_resources_pass_through()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => [
                    'vps:Read',
                    'vps:Shutdown',
                ],
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
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertFalse($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-333'));
    }

    public function test_wildcard_actions_on_wildcard_resources_pass_through()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => [
                    'vps:*',
                ],
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
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertTrue($policy->allows('vps:Read', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertTrue($policy->allows('vps:Delete', 'arn:php:service1:local:000:vps/vps-333'));

        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/*'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-222'));
        $this->assertTrue($policy->allows('vps:Shutdown', 'arn:php:service1:local:000:vps/vps-333'));
    }

    public function test_checks_on_no_specific_resource()
    {
        $policy = Acl::createPolicy([
            [
                'Effect' => 'Allow',
                'Action' => 'vps:List',
                'Resource' => [
                    'arn:php:service1:local:000:vps',
                ],
            ],
        ]);

        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:*', 'arn:php:service1:local:000:vps'));

        $this->assertFalse($policy->allows('vps:List', 'arn:php:service1:local:000:vps/*'));
        $this->assertFalse($policy->allows('vps:List', 'arn:php:service1:local:000:vps/vps-000'));
        $this->assertFalse($policy->allows('vps:List', 'arn:php:service1:local:000:vps/vps-111'));
        $this->assertFalse($policy->allows('vps:List', 'arn:php:service1:local:111:vps'));

        $this->assertTrue($policy->allows('vps:List', 'arn:php:service1:local:000:vps'));
    }
}
