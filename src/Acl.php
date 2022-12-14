<?php

namespace RenokiCo\Acl;

class Acl
{
    /**
     * Create a policy from statements.
     *
     * @param  array  $statement
     * @return Policy
     */
    public static function createPolicy(
        array $statement = [],
    ) {
        return new Policy($statement);
    }
}
