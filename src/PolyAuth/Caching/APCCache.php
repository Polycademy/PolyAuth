<?php

namespace PolyAuth\Caching;

use Stash\Driver\Apc;
use Stash\Pool;
use PolyAuth\Options;

class APCCache{

	protected $cache;
	protected $namespace;

	public function __construct(Pool $cache = null, Apc $driver = null, Options $options = null){
	
		$options = ($options) ? $options : new Options;
		if(!empty($options['cache_ttl'])){
			$driver = ($driver) ? $driver : new Apc(array('ttl' => $options['cache_ttl'], 'namespace' => 'PolyAuth'));
		}else{
			$driver = ($driver) ? $driver : new Apc(array('namespace' => 'PolyAuth'));
		}
		$cache = ($cache) ? $cache : new Pool;
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = 'PolyAuth/';
	
	}
	
	/**
	 * Gets an item in the cache.
	 */
	public function get($key, $invalidation = false){
	
		$item = $this->cache->getItem($this->namespace . $key);
		if($invalidation){
			return $item->get($invalidation);
		}else{
			return $item->get();
		}
	
	}
	
	/**
	 * Sets the item in the cache. Expiration is optional, and can be time in seconds, a datetime object or negative.
	 */
	public function set($key, $value, $expiration = false){
	
		$item = $this->cache->getItem($this->namespace . $key);
		if($expiration){
			return $item->set($value, $expiration);
		}else{
			return $item->set($value);
		}
	
	}
	
	/**
	 * This will check if a particular item exists. This is better than checking for null.
	 */
	public function exists($key){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->isMiss();
	
	}
	
	/**
	 * Locks an item in the cache to prevent cache stampede. Works with invalidation parameter in $this->get
	 */
	public function lock($key){
	
		$item = $this->cache->getItem($this->namespace . $key);
		return $item->lock();
	
	}
	
	/**
	 * Clears the cache based on the key. If the key is not given, it will clear all of PolyAuth's cache.
	 */
	public function clear($key = false){
	
		if($key){
			$item = $this->cache->getItem($this->namespace . $key);
		}else{
			$item = $this->cache->getItem($this->namespace);
		}
		return $item->clear();
	
	}
	
	/**
	 * Purge all the stale data from the cache. Do this as part of maintenance.
	 */
	public function purge(){
	
		return $this->cache->purge();
	
	}
	
	/**
	 * Empty the entire cache, will also empty cache outside of PolyAuth if you are also using Stash.
	 */
	public function flush(){
	
		return $this->cache->flush();
	
	}

}