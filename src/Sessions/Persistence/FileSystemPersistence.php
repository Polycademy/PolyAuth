<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\FileSystem;
use Stash\Pool;
use PolyAuth\Options;

class FileSystemPersistence extends AbstractPersistence{

	public function __construct(FileSystem $driver = null, Pool $cache = null, Options $options = null){
	
		$options = ($options) ? $options : new Options;
		if(!empty($options['session_save_path'])){
			$driver = ($driver) ? $driver : new FileSystem(array('path' => $options['session_save_path']));
		}else{
			//the reason we put it in its own directory is because some of the caching functions (such as purge) may conflict with files that are not part the stash library, such as for example session files that are placed there by native session drivers
			$driver = ($driver) ? $driver : new FileSystem(array('path' => session_save_path()));
		}
		$cache = ($cache) ? $cache : new Pool;
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = $options['session_namespace'];
	
	}

	public function garbage_collection($probability){

		if((mt_rand(0, 10000)/100) <= $probability){
			$this->purge();
		}

	}

}