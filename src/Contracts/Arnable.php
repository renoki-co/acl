<?php

namespace RenokiCo\Acl\Contracts;

interface Arnable
{
    /**
     * This function returns the real ARN of the resource.
     *
     * If an user comes to check if it has access to a specific
     * action on this resource, it will try to match this returned
     * value with their policies.
     *
     * @return string
     */
    public function toArn(): string;

    /**
     * The Account ID this resource belongs to. It can be
     * an user ID, a team ID, etc.
     *
     * @return string|int
     */
    public function arnResourceAccountId();

    /**
     * The unique ID of this resource.
     *
     * @return string|int
     */
    public function arnResourceId();
}
