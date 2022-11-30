<?php

namespace RenokiCo\Acl;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use RenokiCo\Acl\Contracts\Arnable;

class Policy
{
    /**
     * Initialize the policy.
     *
     * @param  array  $statement
     * @return void
     */
    public function __construct(
        protected array $statement = [],
    ) {
        //
    }

    /**
     * Check if the ARN (or ARNable instance) can
     * perform a specific action.
     *
     * @param  string  $action
     * @param  string|\RenokiCo\Acl\Contracts\Arnable  $arn
     * @return bool
     */
    public function allows(string $action, string|Arnable $arn): bool
    {
        // Check if any explicit deny (besides the default deny all) exists.
        if ($this->explicitlyDenies($action, $arn)) {
            return false;
        }

        foreach ($this->statement as $statement) {
            if ($statement['Effect'] === 'Deny') {
                continue;
            }

            // If someone is trustable enough, bypass and allow * on *
            if (
                Arr::wrap($statement['Resource']) === ['*']
                && Arr::wrap($statement['Action']) === ['*']
            ) {
                return true;
            }

            // If all resources are allowed, check only for the actions.
            if (Arr::wrap($statement['Resource']) === ['*']) {
                foreach (Arr::wrap($statement['Action']) as $statementAction) {
                    if ($this->actionMatches($action, $statementAction)) {
                        return true;
                    }
                }

                return false;
            }

            // If all actions are allowed, check only for the matching ARN.
            if (Arr::wrap($statement['Action']) === ['*']) {
                foreach (Arr::wrap($statement['Resource']) as $statementArn) {
                    if ($this->arnMatches($arn, $statementArn)) {
                        return true;
                    }
                }

                return false;
            }

            // Make combinations between Action (ec2:DescribeInstance, vpc:Describe)
            // and Resource (arn:...:ec2:my-instance, vpc:vpc-123, etc.)
            $combinations = collect(Arr::wrap($statement['Action']))
                ->crossJoin(Arr::wrap($statement['Resource']))
                ->toArray();

            foreach ($combinations as [$statementAction, $statementArn]) {
                if (
                    $this->actionMatches($action, $statementAction)
                    && $this->arnMatches($arn, $statementArn)
                ) {
                    return true;
                }
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
            if ($statement['Effect'] === 'Allow') {
                continue;
            }

            // Checking denies for all resources means we have to look for any deniable action.
            if (Arr::wrap($statement['Resource']) === ['*']) {
                foreach (Arr::wrap($statement['Action']) as $statementAction) {
                    if ($this->actionMatches($action, $statementAction)) {
                        return true;
                    }
                }

                return false;
            }

            // Checking denies for all actions means we have to look for any deniable resource.
            if (Arr::wrap($statement['Action']) === ['*']) {
                foreach (Arr::wrap($statement['Resource']) as $statementArn) {
                    if ($this->arnMatches($arn, $statementArn)) {
                        return true;
                    }
                }

                return false;
            }

            // Make combinations between Action (ec2:DescribeInstance, vpc:Describe)
            // and Resource (arn:...:ec2:my-instance, vpc:vpc-123, etc.) and seek
            // for any deniable activity.
            $combinations = collect(Arr::wrap($statement['Action']))
                ->crossJoin(Arr::wrap($statement['Resource']))
                ->toArray();

            foreach ($combinations as [$statementAction, $statementArn]) {
                if (
                    $this->actionMatches($action, $statementAction)
                    && $this->arnMatches($arn, $statementArn)
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if the resource ARN matches the given statement ARN.
     *
     * @param  string|\RenokiCo\Acl\Contracts\Arnable  $resourceArn
     * @param  string  $statementArn
     * @return bool
     */
    public function arnMatches(string|Arnable $resourceArn, string $statementArn): bool
    {
        if ($resourceArn instanceof Arnable) {
            $resourceArn = $resourceArn->toPolicyArn()?->getArn();
        }

        // Matching exact ARNs can save time.
        if ($resourceArn === $statementArn) {
            return true;
        }

        $blocksFromArn = explode(':', $resourceArn);
        $blocksFromStatementArn = explode(':', $statementArn);

        $blocks = collect($blocksFromArn)
            ->combine($blocksFromStatementArn)
            ->toArray();

        // We compare each block individually and make sure the patterns match.
        foreach ($blocks as $blockFromResource => $blockFromStatement) {
            if ($blockFromStatement === $blockFromResource) {
                continue;
            }

            // This happens when someone calls ->allows('vpc:SomeAction', 'arn:aws:...:vpc/*')
            // and their policy has only specified resources (i.e arn:aws:...:vpc/vpc-123)
            if (
                ! str_contains($blockFromStatement, '*')
                && ! str_contains($blockFromStatement, '*')
            ) {
                return false;
            }

            // If no exceptions are present, the resource block should match the pattern block.
            if (! Str::is(pattern: $blockFromStatement, value: $blockFromResource)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the given action matches in the given value from a statement.
     *
     * @param  string  $action
     * @param  string  $statementAction
     * @return bool
     */
    public function actionMatches(string $action, string $statementAction): bool
    {
        // Matching exact actions can save time.
        if ($action === $statementAction) {
            return true;
        }

        $blocksFromAction = explode(':', $action);
        $blocksFromStatement = explode(':', $statementAction);

        $blocks = collect($blocksFromAction)
            ->combine($blocksFromStatement)
            ->toArray();

        // We compare each block individually and make sure the patterns match.
        foreach ($blocks as $blockFromAction => $blockFromStatement) {
            if ($blockFromStatement === $blockFromAction) {
                continue;
            }

            // This happens when someone calls ->allows('vpc:*', 'arn:aws:...:vpc/vpc-123')
            // and their policy has only specified actions (i.e vpc:Delete)
            if (
                ! str_contains($blockFromStatement, '*')
                && ! str_contains($blockFromStatement, '*')
            ) {
                return false;
            }

            // If no exceptions are present, the resource block should match the pattern block.
            if (! Str::is(pattern: $blockFromStatement, value: $blockFromAction)) {
                continue;
            }
        }

        return true;
    }
}