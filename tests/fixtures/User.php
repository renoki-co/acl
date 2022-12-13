<?php

namespace RenokiCo\Acl\Test\Fixtures;

use RenokiCo\Acl\Concerns\HasPolicies;
use RenokiCo\Acl\Contracts\RuledByPolicies;

class User implements RuledByPolicies
{
    use HasPolicies;

    public function __construct(
        public string $id,
        public string $team = 'team-1',
        public string $region = 'local',
    ) {
        //
    }

    public function resolveArnAccountId()
    {
        return $this->team;
    }

    public function resolveArnRegion()
    {
        return $this->region;
    }
}
