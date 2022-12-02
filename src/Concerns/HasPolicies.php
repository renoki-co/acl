<?php

namespace RenokiCo\Acl\Concerns;

use RenokiCo\Acl\Contracts\Arnable;

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
     * @param  array<int, \RenokiCo\Acl\Policy>  $policies
     * @return $this
     */
    public function loadPolicies(array $policies)
    {
        $this->arnPolicies = $policies;

        foreach ($this->arnPolicies as &$policy) {
            $policy->actingAs($this);
        }

        return $this;
    }

    /**
     * Check if this actor is able to perform a specific action.
     * If there is any explicit deny that's matching the given action
     * and ARN, it will return false.
     *
     * @param  string  $action
     * @param  string|Arnable  $arn
     * @return bool
     */
    public function isAllowedTo(string $action, string|Arnable $arn): bool
    {
        $allowsWithoutAnyExplicitDeny = false;

        foreach ($this->arnPolicies as $policy) {
            if ($policy->explicitlyDenies($action, $arn)) {
                return false;
            }

            if ($policy->allows($action, $arn)) {
                $allowsWithoutAnyExplicitDeny = true;
                continue;
            }
        }

        return $allowsWithoutAnyExplicitDeny;
    }
}
