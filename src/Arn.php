<?php

namespace RenokiCo\Acl;

class Arn
{
    /**
     * Create a new instance of an ARN from a given string.
     *
     * @param  string  $arn
     * @return Arn
     */
    public static function fromString(string $arn)
    {
        if ($arn === '*') {
            return static::fromString('arn:*:*:*:*:*');
        }

        return new static(...array_values(
            static::splitArn($arn),
        ));
    }

    /**
     * Build the ARN based on the given pieces.
     *
     * @param  string|int|null  $partition
     * @param  string|int|null  $service
     * @param  string|int|null  $region
     * @param  string|int|null  $accountId
     * @param  string|int|null  $resourceType
     * @param  string|int|null  $resourceId
     * @return void
     */
    public function __construct(
        public string|int|null $partition = 'php',
        public string|int|null $service = 'default',
        public string|int|null $region = 'local',
        public string|int|null $accountId = '0',
        public string|int|null $resourceType = null,
        public string|int|null $resourceId = null,
    ) {
        //
    }

    /**
     * Get the resource ARN, without any
     * specific ID attached to it.
     *
     * @return string
     */
    public function getResourceArn(): string
    {
        return join(':', [
            'arn',
            $this->partition,
            $this->service,
            $this->region,
            $this->accountId,
            $this->resourceType,
        ]);
    }

    /**
     * Get the full ARN for the specific resource, in case
     * it applies. Not having a Resource ID will return
     * the Resource ARN by default.
     *
     * @return string
     */
    public function toString(): string
    {
        $arn = $this->getResourceArn();

        if (! in_array($this->resourceId, ['', null])) {
            $arn .= "/{$this->resourceId}";
        }

        return $arn;
    }

    /**
     * Split the given ARN into key-value pairs.
     *
     * @param  string  $arn
     * @return array
     */
    public static function splitArn(string $arn)
    {
        preg_match(static::pattern(), $arn, $matches);

        return collect($matches)
            ->filter(fn ($v, $k) => is_string($k))
            ->toArray();
    }

    /**
     * The pattern used to detect the ARN parts.
     *
     * @return string
     */
    public static function pattern()
    {
        return '/^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountId>[^:\n]*):(?P<ResourceType>[^:\/\n]*)[:\/]?(?P<ResourceId>.*)$/';
    }

    /**
     * Alias for ->toString().
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }
}
