<?php

namespace RenokiCo\Acl;

use RenokiCo\Acl\Concerns\HasRootAccountId;
use RenokiCo\Acl\Contracts\Arnable;

class Policy
{
    use HasRootAccountId;

    /**
     * Initialize the policy.
     *
     * @param  array<int, \RenokiCo\Acl\Statement>  $statement
     * @param  null|string|int  $rootAccountId
     * @return void
     */
    public function __construct(
        public array $statement = [],
        $rootAccountId = null,
    ) {
        $this->setRootAccount($rootAccountId);
    }

    /**
     * Check if the ARN (or ARNable instance) can
     * perform a specific action.
     *
     * @param  string  $action
     * @param  string|\RenokiCo\Acl\Contracts\Arnable  $arn
     * @return bool
     */
    public function allows(string $actionToCheck, string $arnToCheck): bool
    {
        foreach ($this->statement as $statement) {
            $statement->setRootAccount($this->rootAccountId);

            if ($statement->explicitlyDenies($actionToCheck, $arnToCheck)) {
                return false;
            }

            if ($statement->passes($actionToCheck, $arnToCheck)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the resource ARN (or the ARNable resource)
     * is explicitly denied to perform a specific action.
     *
     * @param  string  $action
     * @param  string|\RenokiCo\Acl\Contracts\Arnable  $arn
     * @return bool
     */
    public function explicitlyDenies(string $action, string|Arnable $arn): bool
    {
        foreach ($this->statement as $statement) {
            if ($statement->explicitlyDenies($action, $arn)) {
                return true;
            }
        }

        return false;
    }
}
