<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;

class DenyTest extends TestCase
{
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
