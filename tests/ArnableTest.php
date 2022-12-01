<?php

namespace RenokiCo\Acl\Test;

use RenokiCo\Acl\Acl;
use RenokiCo\Acl\Concerns\HasArn;
use RenokiCo\Acl\Contracts\Arnable;

class ArnableTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        Acl::provideAccountIdInArns(function () {
            return request()->team
                ? request()->team['id']
                : null;
        });

        Acl::provideRegionInArns(function () {
            return 'local';
        });

        request()->merge([
            'team' => null,
            'user' => null,
        ]);
    }

    public function test_allow_on_a_general_arn_instance()
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

        $this->assertFalse($policy->allows('vps:List', Vps::class));
        $this->assertTrue($policy->allows('vps:Describe', new Vps('vps-xxx')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($policy->allows('vps:List', Vps::class));
        $this->assertTrue($policy->allows('vps:Describe', new Vps('vps-xxx')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-2'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($policy->allows('vps:List', Vps::class));
        $this->assertTrue($policy->allows('vps:Describe', new Vps('vps-xxx')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-2'],
        ]);

        $this->assertFalse($policy->allows('vps:List', Vps::class));
        $this->assertFalse($policy->allows('vps:Describe', new Vps('vps-xxx', 'team-2')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));
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

        $this->assertFalse($policy->allows('vps:Describe', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertFalse($policy->allows('vps:Describe', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-2'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertFalse($policy->allows('vps:Describe', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-2'],
        ]);

        $this->assertFalse($policy->allows('vps:Describe', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));
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

        $this->assertFalse($policy->allows('vps:List', Vps::class));
        $this->assertTrue($policy->allows('vps:Describe', new Vps('vps-xxx')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertTrue($policy->allows('vps:List', Vps::class));
        $this->assertTrue($policy->allows('vps:Describe', new Vps('vps-xxx')));

        $this->assertFalse($policy->allows('vps:List', new Vps('vps-xxx')));
        $this->assertFalse($policy->allows('vps:Describe', Vps::class));
    }

    public function test_arn_resource_generates_valid_arns()
    {
        $this->assertEquals('arn:php:default:local::vps', Vps::resourceIdAgnosticArn());

        request()->merge([
            'user' => ['id' => 'user-1'],
            'team' => ['id' => 'team-1'],
        ]);

        $this->assertEquals('arn:php:default:local:team-1:vps', Vps::resourceIdAgnosticArn());

        $vps = new Vps('vps-1', 'team-1');

        $this->assertEquals('arn:php:default:local:team-1:vps/vps-1', $vps->toArn());
    }
}

class Vps implements Arnable
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
}
