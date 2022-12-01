<?php

namespace RenokiCo\Acl\Test;

use Orchestra\Testbench\TestCase as Orchestra;
use RenokiCo\Acl\Acl;

abstract class TestCase extends Orchestra
{
    public function setUp(): void
    {
        parent::setUp();

        Acl::provideAccountIdInArns(null);
        Acl::provideRegionInArns(null);
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
}
