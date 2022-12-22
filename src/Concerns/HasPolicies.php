<?php

namespace RenokiCo\Acl\Concerns;

use Illuminate\Support\Arr;
use RenokiCo\Acl\Arn;
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


    /**
     * @throws WildcardNotPermittedException
     */
    public function getQuery(string $action, string|Arnable $arn = null): array
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

        $resource = Arn::fromString($arn);

        $effects = [];

        foreach ($this->arnPolicies as $policy) {
            foreach ($policy->statement as $statement) {
                if(!$statement->passesAction($action)) {
                    continue;
                }

                foreach ($statement->resource as $resourcePattern) {
                    $arn = Arn::fromString($resourcePattern);

                    if($resource->partition !== $arn->partition && $arn->partition !== '*') {
                        continue;
                    }

                    if($resource->service !== $arn->service && $arn->service !== '*') {
                        continue;
                    }

                    if($resource->region !== $arn->region && $arn->region !== '*') {
                        continue;
                    }

                    if($resource->accountId !== $arn->accountId && $arn->accountId !== '*') {
                        continue;
                    }

                    if($resource->resourceType !== $arn->resourceType && $arn->resourceType !== '*') {
                        continue;
                    }

                    if($arn->resourceId == null) {
                        continue;
                    }

                    $effects[$statement->effect === 'Allow' ? 'allow' : 'deny'][] = $arn->resourceId;
                }
            }
        }

        $deny = collect($effects['deny'] ?? [])->unique();
        $allow = collect($effects['allow'] ?? [])->unique();

        if($deny->contains('*')) {
            return [
                'only' => [],
            ];
        } elseif($allow->contains('*')) {
            return [
                'except' => $deny->toArray(),
            ];
        } else {
            return [
                'only' => $allow->diff($deny)->values()->toArray(),
            ];
        }
    }
}
