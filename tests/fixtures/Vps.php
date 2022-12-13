<?php

namespace RenokiCo\Acl\Test\Fixtures;

use RenokiCo\Acl\Concerns\HasArn;
use RenokiCo\Acl\Contracts\Arnable;

class Vps implements Arnable
{
    use HasArn;

    public function __construct(
        public string $id = 'vps-000',
        public string $team = 'team-1',
    ) {
        //
    }

    public function arnResourceAccountId()
    {
        return $this->team;
    }

    public function arnResourceId()
    {
        return $this->id;
    }
}
