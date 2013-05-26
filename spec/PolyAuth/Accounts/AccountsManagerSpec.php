<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;

use PolyAuth\Options;
use PolyAuth\Language;

class AccountsManagerSpec extends ObjectBehavior{

	public $prophet;
	public $user;

	function let(
		PDOStatement $sth, 
		Options $options_object, 
		Language $language_object
	){
	
		//setting up the prophet
		$this->prophet = new Prophet;
		
		//setup user fixture
		$this->user = $this->setup_user_fixture();
		
		//setting up mocks, some of them will be from prophecy, others will be depedency injected
		$mocks = array();
		$mocks += $this->setup_db_mocks($sth);
		$mocks += $this->setup_options_language_mocks($options_object, $language_object);
		$mocks += $this->setup_logger_mocks();
		$mocks += $this->setup_rbac_mocks();
		$mocks += $this->setup_password_complexity_mocks();
		$mocks += $this->setup_random_mocks();
		$mocks += $this->setup_emailer_mocks();
		$mocks += $this->setup_login_attempts_mocks();
		
		$this->beConstructedWith(
			$mocks['db'],
			$mocks['options'], 
			$mocks['language'], 
			$mocks['logger'], 
			$mocks['rbac'],
			$mocks['password_complexity'],
			$mocks['random'],
			$mocks['emailer'],
			$mocks['login_attempts']
		);
	
	}
	
	function setup_user_fixture(){
	
		$user_data = [
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'activationCode'	=> 'abcd1234',
			'forgottenCode'		=> '1234567',
			'active'			=> 0,
			'passwordChange'	=> 0,
			'banned'			=> 0,
		];
		$user = $this->prophet->prophesize('PolyAuth\UserAccount');
		$user->set_user_data(Argument::any())->will(function($args) use (&$user_data){
			$data = $args[0];
			$type = gettype($data);
			if($type != 'object' AND $type != 'array'){
				return false;
			}
			if($type == 'object'){
				$data = get_object_vars($data);
			}
			$user_data = array_merge($user_data, $data);
		});
		$user->get_user_data()->will(function() use (&$user_data){
			return $user_data;
		});
		$user->offsetGet(Argument::any())->will(function($args) use (&$user_data){
			$key = $args[0];
			return $user_data[$key];
		});
		$user->offsetSet(Argument::cetera())->will(function($args) use (&$user_data){
			if(is_null($args[0])){
				$user_data[] = $args[1];
			} else {
				$user_data[$args[0]] = $args[1];
			}
		});
		$user->offsetExists(Argument::any())->will(function($args) use (&$user_data){
			return isset($user_data[$args[0]]);
		});
		$user->offsetUnset(Argument::any())->will(function($args) use (&$user_data){
			$key = $args[0];
			unset($user_data[$key]);
		});
		$this->user = $user->reveal();
	
	}
	
	function setup_db_mocks(PDOStatement $sth){
		
		//STH is not a prophecy object because it must be able to be overwritten
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(false);
		$sth->fetchAll(PDO::FETCH_COLUMN, 0)->willReturn(array(
			'id',
			'ipAddress',
			'username',
			'password',
			'passwordChange',
			'email',
			'activationCode',
			'forgottenCode',
			'forgottenDate',
			'autoCode',
			'createdOn',
			'lastLogin',
			'active',
			'extraRandomField',
			'anotherRandomField',
		));
		
		//PDO
		$db = $this->prophet->prophesize('PDO');
		$db->prepare(Argument::any())->willReturn($sth);
		$db->lastInsertId()->willReturn(1);
		$db->getAttribute(PDO::ATTR_DRIVER_NAME)->willReturn('mysql');
		
		return [
			'db'	=> $db, 
			'sth'	=> $sth,
		];
	
	}
	
	function setup_options_language_mocks(Options $options_object, Language $language_object){
	
		//OPTIONS
		$options = $this->prophet->prophesize('PolyAuth\Options');
		$options_array = $options_object->options;
		$options->offsetGet(Argument::any())->will(function($args) use (&$options_array){
			$key = $args[0];
			return $options[$key];
		});
		$options->offsetSet(Argument::cetera())->will(function($args) use (&$options_array){
			if(is_null($args[0])){
				$options[] = $args[1];
			} else {
				$options[$args[0]] = $args[1];
			}
		});
		
		//LANGUAGE
		$language = $this->prophet->prophesize('PolyAuth\Language');
		$language_array = $language_object->lang;
		$language->offsetGet(Argument::any())->will(function($args) use (&$language_array){
			$key = $args[0];
			return $language_array[$key];
		});
		$language->offsetSet(Argument::cetera())->will(function($args) use (&$language_array){
			if(is_null($args[0])){
				$language_array[] = $args[1];
			} else {
				$language_array[$args[0]] = $args[1];
			}
		});
		
		return [
			'options'	=> $options->reveal(), 
			'language'	=> $language->reveal(),
		];
		
	}
	
	function setup_logger_mocks(){
	
		$logger = $this->prophet->prophesize();
		$logger->willExtend('stdClass');
		$logger->willImplement('Psr\Log\LoggerInterface');
		$logger->error(Argument::type('string'), Argument::type('array'))->willReturn(true);
		return [
			'logger'	=> $logger->reveal(),
		];
	
	}
	
	function setup_rbac_mocks(){
		
		$role_set = $this->prophet->prophesize('RBAC\Role\RoleSet');
		$role_set->addRole(Argument::type('RBAC\Role\Role'))->willReturn(true);
		$role_set->has_permission('Permission Name')->willReturn(true);
		$role_set = $role_set->reveal();
	
		$rbac = $this->prophet->prophesize('PolyAuth\Accounts\Rbac');
		$rbac->load_subject_roles(Argument::type('PolyAuth\UserAccount'))->will(
			function($args) use ($role_set){
				$args[0]->loadRoleSet($role_set);
			}
		);
		
		return [
			'rbac'	=> $rbac->reveal(),
		];
	
	}
	
	function setup_password_complexity_mocks(){
	
		$password_complexity = $this->prophet->prophesize('PolyAuth\Security\PasswordComplexity');
		$password_complexity->complex_enough(Argument::type('string'))->willReturn(true);
		return [
			'password_complexity'	=> $password_complexity->reveal(),
		];
	
	}
	
	function setup_random_mocks(){
	
		$random = $this->prophet->prophesize('PolyAuth\Security\Random');
		$random->generate(40)->willReturn('1234dsf4846dcvx4v45984839ghhghfjhgj5gfh6');
		$random->generate(32, true)->willReturn('1243b48%*&#$bi40*@(&^b465o^RFSDG*&09fdg1');
		return [
			'random'	=> $random->reveal(),
		];
	
	}
	
	function setup_emailer_mocks(){
	
		$emailer = $this->prophet->prophesize('PolyAuth\Emailer');
		$emailer->send_activation(Argument::any())->willReturn(true);
		$emailer->send_forgotten_identity(Argument::any())->willReturn(true);
		$emailer->send_forgotten_password(Argument::any())->willReturn(true);
		return [
			'emailer'	=> $emailer->reveal(),
		];
	
	}
	
	function setup_login_attempts_mocks(){
	
		$login_attempts = $this->prophet->prophesize('PolyAuth\Sessions\LoginAttempts');
		$login_attempts->clear(Argument::cetera())->willReturn(true);
		return [
			'login_attempts'	=> $login_attempts->reveal(),
		];
		
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\AccountsManager');
	
	}
	
	function it_implements_logger_interface(){
	
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	
	}
	
}
