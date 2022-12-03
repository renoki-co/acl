<?php

namespace RenokiCo\Acl\Concerns;

use RenokiCo\Acl\Contracts\Arnable;
use RenokiCo\Acl\Exceptions\WildcardNotPermittedException;

trait HasPolicies
{
    /**
     * The policies that belong to this actor.
     *
     * @var array<int, \RenokiCo\Acl\Policy>
     */
    public $arnPolicies = [];

    /**
     * Load policies for this entity.
     *
     * @param  \RenokiCo\Acl\Policy  $policies
     * @return $this
     */
    public function loadPolicies(...$policies)
    {
        /** @var \RenokiCo\Acl\Contracts\RuledByPolicies $this */

        // Having an array passed, extract the first item.
        if (
            is_array($policies)
            && is_array($policies[0])
            && count($policies) === 1
        ) {
            $policies = $policies[0];
        }

        $this->arnPolicies = $policies;

        foreach ($this->arnPolicies as &$policy) {
            $policy->setRootAccount($this->resolveArnAccountId());
        }

        return $this;
    }

    /**
     * Check if this actor is able to perform a specific action.
     *
     * @param  string  $action
     * @param  string|Arnable  $arn
     * @return bool
     *
     * @throws WildcardNotPermittedException
     */
    public function isAllowedTo(string $action, string|Arnable $arn): bool
    {
        if ($arn instanceof Arnable) {
            $arn = $arn->toArn();
        } elseif (is_string($arn) && class_exists($arn)) {
            $arn = $arn::resourceIdAgnosticArn($this);
        }

        if (str_contains($action, '*') || str_contains($arn, '*')) {
            throw new WildcardNotPermittedException(sprintf(
                'Checking %s on %s is not permitted. Wildcards are not allowed.',
                $action,
                $arn,
            ));
        }

        $atLeastOneAllowedWasHit = false;

        foreach ($this->arnPolicies as $policy) {
            if ($policy->explicitlyDenies($action, $arn)) {
                return false;
            }

            if ($policy->allows($action, $arn)) {
                $atLeastOneAllowedWasHit = true;
            }
        }

        return $atLeastOneAllowedWasHit;
    }
}
