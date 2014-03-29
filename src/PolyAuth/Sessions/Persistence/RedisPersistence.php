<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\Redis;
use Stash\Pool;
use PolyAuth\Options;

/**
 * This does not currently work. Need to fix the stupid adapter.
 */
class RedisPersistence extends AbstractPersistence{

    public function __construct(Redis $driver = null, Pool $cache = null, Options $options = null){

        $options = ($options) ? $options : new Options;
        $driver = ($driver) ? $driver : new Redis(
            array(
                'servers' => array(
                    $options['session_redis_server'], 
                    $options['session_redis_port'],
                )
            )
        );
        $cache = ($cache) ? $cache : new Pool();
        $cache->setDriver($driver);
        $this->cache = $cache;
        $this->namespace = $options['session_namespace'];

    }

}