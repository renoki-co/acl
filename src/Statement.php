<?php

namespace RenokiCo\Acl;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use RenokiCo\Acl\Concerns\HasRootAccountId;

class Statement
{
    use HasRootAccountId;

    /**
     * Create a new statement.
     *
     * @param  string  $effect
     * @param  string|array  $action
     * @param  string|array  $resource
     * @param  string|int|null  $rootAccountId
     * @return Statement
     */
    public static function make(
        string $effect = 'Allow',
        string|array $action = [],
        string|array $resource = [],
        $rootAccountId = null,
    ) {
        return new Statement(
            $effect,
            $action,
            $resource,
            $rootAccountId,
        );
    }

    /**
     * Create a new statement instance.
     *
     * @param  string  $effect
     * @param  string|array  $action
     * @param  string|array  $resource
     * @param  string|int|null  $rootAccountId
     * @return void
     */
    public function __construct(
        public string $effect = 'Allow',
        public string|array $action = [],
        public string|array $resource = [],
        $rootAccountId = null,
    ) {
        $this->action = Arr::wrap($action);
        $this->resource = Arr::wrap($resource);

        $this->setRootAccount($rootAccountId);
    }

    /**
     * Check if the passed action & ARN are passing
     * the current statement's policy. This does not check
     * for explicit denies.
     *
     * @param  string  $actionToCheck
     * @param  string  $arnToCheck
     * @return bool
     */
    public function passes(string $actionToCheck, string $arnToCheck)
    {
        return $this->passesAction($actionToCheck) && $this->passesArn($arnToCheck);
    }

    /**
     * Check if the passed action & ARN are passing
     * the current statement's policy denial.
     *
     * @param  string  $actionToCheck
     * @param  string  $arnToCheck
     * @return bool
     */
    public function explicitlyDenies(string $actionToCheck, string $arnToCheck)
    {
        return $this->explicitlyDeniesAction($actionToCheck) && $this->explicitlyDeniesArn($arnToCheck);
    }

    /**
     * Check if the action matches this statement declaration.
     * This is not checking for allow/deny, but rather direct match.
     *
     * @param  string  $actionToCheck
     * @return bool
     */
    public function passesAction(string $actionToCheck)
    {
        foreach ($this->action as $actionPattern) {
            if ($actionPattern === '*' || $actionPattern === $actionToCheck) {
                return true;
            }

            if (Str::is($actionPattern, $actionToCheck)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the ARN matches this statement ARN.
     * This is not checking for allow/deny, but rather direct match.
     *
     * @param  string  $arnToCheck
     * @return bool
     */
    public function passesArn(string $arnToCheck)
    {
        foreach ($this->resource as $resourcePattern) {
            if ($resourcePattern === $arnToCheck) {
                return true;
            }

            $arn = Arn::fromString($resourcePattern);

            if ($this->rootAccountId) {
                $arn->accountId = $this->rootAccountId;
            }

            if (Str::is($arn->toString(), $arnToCheck)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the action matches this statement's deny declaration.
     * If the statement is Allow, it returns false.
     *
     * @param  string  $actionToCheck
     * @return bool
     */
    public function explicitlyDeniesAction(string $actionToCheck)
    {
        if ($this->effect === 'Allow') {
            return false;
        }

        foreach ($this->action as $actionPattern) {
            if (Str::is($actionPattern, $actionToCheck)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the ARN matches this statement's deny ARN.
     * If the statement is Allow, it returns false.
     *
     * @param  string  $arnToCheck
     * @return bool
     */
    public function explicitlyDeniesArn(string $arnToCheck)
    {
        if ($this->effect === 'Allow') {
            return false;
        }

        foreach ($this->resource as $resourcePattern) {
            if ($resourcePattern === $arnToCheck) {
                return true;
            }

            $arn = Arn::fromString($resourcePattern);

            if ($this->rootAccountId) {
                $arn->accountId = $this->rootAccountId;
            }

            if (Str::is($arn->toString(), $arnToCheck)) {
                return true;
            }
        }

        return false;
    }
}
