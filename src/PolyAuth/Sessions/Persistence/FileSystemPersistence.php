<?php

namespace PolyAuth\Sessions\Persistence;

use Stash\Driver\FileSystem;
use Stash\Pool;
use PolyAuth\Options;

class FileSystemPersistence extends PersistenceAbstract{

	//needs to accept the encrypt mechanism! then it will encrypt information
	public function __construct(FileSystem $driver = null, Pool $cache = null, Options $options = null){
	
		$options = ($options) ? $options : new Options;
		if(!empty($options['session_save_path'])){
			$driver = ($driver) ? $driver : new FileSystem(array('path' => $options['session_save_path']));
		}else{
			$driver = ($driver) ? $driver : new FileSystem(array('path' => session_save_path()));
		}
		$cache = ($cache) ? $cache : new Pool;
		$cache->setDriver($driver);
		$this->cache = $cache;
		$this->namespace = 'PolyAuth/FileSystem/Sessions/';
	
	}

}