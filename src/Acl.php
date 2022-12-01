<?php

namespace RenokiCo\Acl;

use Closure;

class Acl
{
    /**
     * The list of callbacks that can be used for
     * Resource-agnostic ARN generations.
     *
     * The values returned might range from current
     * session-related data, like the authenticated user to
     * the current selected region.
     *
     * @var array<int, \Closure|null>
     */
    public static $arnPartsGeneratorCallbacks = [];

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

    /**
     * Get the generation callback for a specific part of an ARN.
     *
     * @param  string  $part
     * @return \Closure|null
     */
    public static function getArnGenerationCallback(string $part)
    {
        return static::$arnPartsGeneratorCallbacks[$part] ?? null;
    }

    /**
     * Provide an account ID in Resource-agnostic ARNs.
     *
     * When ARNable instances are passed as classes, the static
     * function needs an identifier for the current account or team,
     * so it can look after creation or listing actions, for example.
     *
     * Most of the time, it's the current authenticated user
     * or the current selected team/organization.
     *
     * @param  \Closure|null  $callback
     * @return void
     */
    public static function provideAccountIdInArns(?Closure $callback)
    {
        static::$arnPartsGeneratorCallbacks['accountId'] = $callback;
    }

    /**
     * Provide a region in Resource-agnostic ARNs.
     *
     * When ARNable instances are passed as classes, the static
     * function needs an identifier for the current region so
     * it can look after creation or listing actions in a
     * specific region, for example.
     *
     * Most of the time, it's the current selected region, or
     * if you got an API, the current selected region to perform
     * an API call on.
     *
     * @param  \Closure|null  $callback
     * @return void
     */
    public static function provideRegionInArns(?Closure $callback)
    {
        static::$arnPartsGeneratorCallbacks['region'] = $callback;
    }
}
