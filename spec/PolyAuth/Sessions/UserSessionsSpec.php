<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;

use Aura\Session\Manager as SessionManager;
use Aura\Session\Segment as SessionSegment;

use PolyAuth\Options;
use PolyAuth\Language;

use PolyAuth\Accounts\AccountsManager;
use PolyAuth\Accounts\Rbac;

use PolyAuth\Cookies;
use PolyAuth\Sessions\LoginAttempts;

use PolyAuth\Exceptions\UserExceptions\UserPasswordChangeException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserExceptions\UserBannedException;
use PolyAuth\Exceptions\UserExceptions\UserInactiveException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\ValidationExceptions\LoginValidationException;
use PolyAuth\Exceptions\ValidationExceptions\SessionValidationException;

class UserSessionsSpec extends ObjectBehavior{

	public $prophet;

	function let(
		PDO $db, 
		PDOStatement $sth,
		Options $options, 
		Language $language, 
		AccountsManager $accounts_manager, 
		Rbac $rbac,
		SessionManager $session_manager, 
		SessionSegment $session_segment,
		Cookies $cookies,
		LoginAttempts $login_attempts
	){
	
		$this->prophet = new Prophet;
		
		define('SID', 'abcd1234');
		
		$mocks = [];
		$mocks += $this->setup_auth_strategy_mocks();
		$mocks += $this->setup_db_mocks($db, $sth);
		$mocks += $this->setup_options_and_language_mocks($options, $language);
		$mocks += $this->setup_logger_mocks();
		$mocks += $this->setup_accounts_manager_mocks($accounts_manager);
		$mocks += $this->setup_rbac_mocks($rbac);
		$mocks += $this->setup_session_manager_mocks($session_manager);
		$mocks += $this->setup_cookies_mocks($cookies);
		$mocks += $this->setup_login_attempts_mocks($login_attempts);
		
		$this->beConstructedWith(
			$mocks['auth'],
			$mocks['db'],
			$mocks['options'],
			$mocks['language'],
			$mocks['logger'],
			$mocks['accounts_manager'],
			$mocks['rbac'],
			$mocks['session_manager'],
			$mocks['cookies'],
			$mocks['login_attempts']
		);
	
	}
	
	function setup_auth_strategy_mocks(){
	
		$auth_strategy = $this->prophet->prophesize();
		$auth_strategy->willExtend('stdClass');
		$auth_strategy->willImplement('PolyAuth\AuthStrategies\AuthStrategyInterface');
		
		$auth_strategy->autologin()->willReturn(1);
		$auth_strategy->set_autologin(Argument::any())->willReturn(true);
		$auth_strategy->login_hook(Argument::any())->will(
			function($args){ 
				return $args[0];
			}
		);
		$auth_strategy->logout_hook()->willReturn(true);
		
		$auth_strategy = $auth_strategy->reveal();
		
		return [
			'auth' => $auth_strategy,
		];
	
	}
	
	function setup_db_mocks(PDO $db, PDOStatement $sth){
	
		//STH
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(true);
		
		//PDO
		$db->prepare(Argument::any())->willReturn($sth);
		
		return [
			'db'	=> $db, 
		];
	
	}
	
	function setup_options_and_language_mocks(Options $options, Language $language){
	
		//OPTIONS
		$options_array = $options->options;
		$options = $this->prophet->prophesize('PolyAuth\Options');
		$options->offsetGet(Argument::any())->will(function($args) use (&$options_array){
			$key = $args[0];
			return $options_array[$key];
		});
		$options->offsetSet(Argument::cetera())->will(function($args) use (&$options_array){
			if(is_null($args[0])){
				$options_array[] = $args[1];
			} else {
				$options_array[$args[0]] = $args[1];
			}
		});
		$options->offsetExists(Argument::any())->will(function($args) use (&$options_array){
			return isset($options_array[$args[0]]);
		});
		$options = $options->reveal();
		
		//LANGUAGE
		$language_array = $language->lang;
		$language = $this->prophet->prophesize('PolyAuth\Language');
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
		$language->offsetExists(Argument::any())->will(function($args) use (&$language_array){
			return isset($language_array[$args[0]]);
		});
		$language = $language->reveal();
		
		return [
			'options'	=> $options, 
			'language'	=> $language,
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
	
	function setup_accounts_manager_mocks(AccountsManager $accounts_manager){
	
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
		
		$user = $user->reveal();
	
		$accounts_manager->get_user(Argument::any())->willReturn($user);
		
		return [
			'accounts_manager' => $accounts_manager,
		];
	
	}
	
	function setup_rbac_mocks(Rbac $rbac){
	
		//dummy permission
		$permission = $this->prophet->prophesize('RBAC\Permission');
		$permission->permission_id = 1;
		$permission->name = 'Permission Name';
		$permission->description = 'A dummy permission';
		$permission = $permission->reveal();
		
		//dummy role
		$role = $this->prophet->prophesize('RBAC\Role\Role');
		$role->role_id = 1;
		$role->name = 'members';
		$role->description = 'A dummy role';
		$role->hasPermission(Argument::type('RBAC\Permission'))->willReturn(true);
		$role->getPermissions()->willReturn(array($permission));
		$role->addPermission(Argument::any())->willReturn(true);
		$role = $role->reveal();
		
		//will return an array of roles, in this it will just eb one role
		$rbac->get_roles(Argument::type('array'))->willReturn(array($role));
		
		return [
			'rbac'	=> $rbac,
		];
	
	}
	
	function setup_session_manager_mocks(SessionManager $session_manager){
	
		$session_segment = $this->prophet->prophesize('stdClass');
		$session_segment->user_id = 1;
		$session_segment->anonymous = false;
		$session_segment->timeout = time();
		$session_segment = $session_segment->reveal();
	
		$session_manager->newSegment(Argument::any())->willReturn($session_segment);
		$session_manager->isStarted()->willReturn(false);
		$session_manager->commit()->willReturn(true);
		$session_manager->start()->willReturn(true);
		$session_manager->getName()->willReturn('PHPSESSID');
		$session_manager->destroy()->willReturn(true);
		$session_manager->clear()->willReturn(true);
		$session_manager->regenerateId()->willReturn(true);
		
		return [
			'session_manager' => $session_manager,
		];
	
	}
	
	function setup_cookies_mocks(Cookies $cookies){
	
		$cookies->delete_cookie(Argument::any())->willReturn(true);
		
		return [
			'cookies'	=> $cookies,
		];
	
	}
	
	function setup_login_attempts_mocks(LoginAttempts $login_attempts){
	
		
		$login_attempts->locked_out(Argument::any())->willReturn(false);
		$login_attempts->clear(Argument::cetera())->willReturn(true);
		$login_attempts->increment(Argument::any())->willReturn(true);
		
		return [
			'login_attempts'	=> $login_attempts,
		];
		
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Sessions\UserSessions');
		
	}
	
	// function it_should_autologin_on_cookie_strategy(){}
	
	// function it_should_login_on_cookie_strategy(){}
	
	// function it_should_autologin_on_http_strategy(){}
	
	// function it_should_login_on_http_strategy(){}
		
	// function it_should_increment_login_attempts_at_each_login(){}
	
	// function it_should_be_able_to_modify_client_session_data(){}

}