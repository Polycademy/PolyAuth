<?php

namespace PolyAuth\Storage;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;
use PolyAuth\Storage\StorageInterface;

use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Subject\SubjectInterface;
use RBAC\DataStore\PDOMySQLAdapter;

/**
 * MySQL PDO Adapter for PolyAuth
 * The Rbac mysql adapter will be composited with this adapter, allowing it satisfy bother interfaces
 * The Oauth library will remain using memory storage, however this will take the memory and store into mysql
 */
class MySQLAdapter implements StorageInterface{

	protected $db;
	protected $options;
	protected $logger;
	protected $rbac_storage;

	public function __construct(PDO $db, Options $options, LoggerInterface = null){

		$this->db = $db;
		$this->options = $options;
		$this->logger = $logger;
		$this->rbac_storage = new PDOMySQLAdapter($db, $logger);

	}

	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){

		$this->logger = $logger;
		$this->rbac_storage = new PDOMySQLADapter($this->db, $logger);
	
	}

	//////////////////////
	// RBAC COMPOSITING //
	//////////////////////

	public function getDBConn(){
		return $this->rbac_storage->getDBConn();
	};

	public function permissionSave(Permission $permission){
		return $this->rbac_storage->permissionSave($permission);
	};

	public function permissionFetchById($permission_id){
		return $this->rbac_storage->permissionFetchById($permission_id);
	};

	public function permissionFetch(){
		return $this->rbac_storage->permissionFetch();
	};

	public function permissionDelete(Permission $permission){
		return $this->rbac_storage->permissionDelete($permission);
	};

	public function roleSave(Role $role){
		return $this->rbac_storage->roleSave($role);
	};

	public function rolePermissionAdd(Role $role, Permission $permission){
		return $this->rbac_storage->rolePermissionAdd($role, $permission);
	};

	public function roleDelete(Role $role){
		return $this->rbac_storage->roleDelete($role);
	};

	public function roleFetch(){
		return $this->rbac_storage->roleFetch();
	};

	public function roleFetchByName($role_name){
		return $this->rbac_storage->roleFetchByName($role_name);
	};

	public function roleFetchById($role_ids){
		return $this->rbac_storage->roleFetchById($role_ids);
	};

	public function roleFetchSubjectRoles(SubjectInterface $subject){
		return $this->rbac_storage->roleFetchSubjectRoles($subject);
	};

	public function roleAddSubjectId(Role $role, $subject_id){
		return $this->rbac_storage->roleAddSubjectId($role, $subject_id);
	};

	public function permissionFetchByRole(Role $role){
		return $this->rbac_storage->permissionFetchByRole($role);
	};

}