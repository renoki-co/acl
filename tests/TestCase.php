<?php

namespace RenokiCo\Acl\Test;

use Orchestra\Testbench\TestCase as Orchestra;
use RenokiCo\Acl\Policy;

abstract class TestCase extends Orchestra
{
    public function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            //
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        $app['config']->set('app.key', 'wslxrEFGWY6GfGhvN9L3wH3KSRJQQpBD');
    }

    protected function testPoliciesSerialization(array $policies)
    {
        foreach ($policies as $policy) {
            /** @var Policy $policy */
            $importedPolicy = Policy::fromArray($policy->toArray());

            $this->assertSame(
                serialize($policy),
                serialize($importedPolicy)
            );
        }
    }
}
