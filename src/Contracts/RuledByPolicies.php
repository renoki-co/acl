<?php

namespace RenokiCo\Acl\Contracts;

interface RuledByPolicies
{
    /**
     * Resolve the account ID of the current actor.
     * This value will be used in ARNs for ARNable static instances,
     * to see if the current actor can perform ID-agnostic resource actions.
     *
     * @return null|string|int
     */
    public function resolveArnAccountId();
}
