<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;

use Aura\Session\Manager as SessionManager;
use Aura\Session\SegmentFactory;
use Aura\Session\CsrfTokenFactory;
use Aura\Session\Randval;
use Aura\Session\Phpfunc;

use PolyAuth\Options;
use PolyAuth\Language;

use PolyAuth\AuthStrategies\AuthStrategyInterface;

use PolyAuth\UserAccount;
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
		AuthStrategyInterface $strategy, 
		PDO $db, 
		PDOStatement $sth,
		Options $options, 
		Language $language, 
		AccountsManager $accounts_manager, 
		Rbac $rbac,
		SessionManager $session_manager, 
		Cookies $cookies,
		LoginAttempts $login_attempts
	){
	
		$this->prophet = new Prophet;
		
		$mocks = [];
		$mocks += $this->setup_auth_strategy_mocks($strategy);
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
			$mocks['accounts_manager'],
			$mocks['rbac'],
			$mocks['session_manager'],
			$mocks['cookies'],
			$mocks['login_attempts']
		);
	
	}
	
	function setup_auth_strategy_mocks(AuthStrategyInterface $strategy){
	
		//continue...
	
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
	
		//continue...
	
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
		
		$role_set = $this->prophet->prophesize('RBAC\Role\RoleSet');
		$role_set->addRole(Argument::type('RBAC\Role\Role'))->willReturn(true);
		$role_set->has_permission('Permission Name')->willReturn(true);
		$role_set = $role_set->reveal();
		
		$rbac->load_subject_roles(Argument::type('PolyAuth\UserAccount'))->will(
			function($args) use ($role_set){
				$user = $args[0];
				$user->loadRoleSet($role_set);
				return $user;
			}
		);
		$rbac->register_user_roles(Argument::type('PolyAuth\UserAccount'), array('members'))->will(
			function($args) use ($role){
				$user = $args[0];
				//take the dummy role and add it to the rolset
				$role = $role;
				$role_set = $user->getRoleSet();
				$role_set->addRole($role);
				$user->loadRoleSet($role_set);
				return $user;
			}
		);
		
		return [
			'rbac'	=> $rbac,
		];
	
	}
	
	function setup_session_manager_mocks(SessionManager $session_manager){
	
		//continue...
	
	}
	
	function setup_cookies_mocks(Cookies $cookies){
	
		$id = '1';
		$autoCode = '1234dsf4846dcvx4v459';
		
		$cookies->get_cookie(Argument::any())->willReturn(serialize(['id' => (integer) $id, 'autoCode' => $autoCode]));
		
		//set cookie should be set in this way!
		$cookies->set_cookie('autologin', serialize(['id' => (integer) $id, 'autoCode' => $autoCode]), $this->options['login_expiration'])->willReturn(true);
		
		$cookies->delete_cookie(Argument::any())->willReturn(true);
		
		return [
			'cookies'	=> $cookies,
		];
	
	}
	
	function setup_login_attempts_mocks(LoginAttempts $login_attempts){
	
		//needs more work
		$login_attempts->clear(Argument::cetera())->willReturn(true);
		return [
			'login_attempts'	=> $login_attempts->reveal(),
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