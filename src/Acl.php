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
    public static function createPolicy(array $statement = [])
    {
        return new Policy($statement);
    }

    /**
     * Import an existing JSON into a new Policy object.
     *
     * @param  string  $json
     * @return Policy
     */
    public function createPolicyFromJson(string $json)
    {
        return static::createPolicy(json_decode($json, true));
    }
}
