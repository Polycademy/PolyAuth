<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;

use PolyAuth\Options;
use PolyAuth\Language;

use PolyAuth\Exceptions\ValidationExceptions\RegisterValidationException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\UserExceptions\UserDuplicateException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;

class AccountsManagerSpec extends ObjectBehavior{

	public $prophet;
	public $user;

	function let(
		PDO $db,
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
		$mocks += $this->setup_db_mocks($db, $sth);
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
		
		return $user->reveal();
	
	}
	
	function setup_db_mocks(PDO $db, PDOStatement $sth){
	
		//STH
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(true);
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
			'banned'
		));
		
		//PDO
		$db->prepare(Argument::any())->willReturn($sth);
		$db->lastInsertId()->willReturn(1);
		$db->getAttribute(PDO::ATTR_DRIVER_NAME)->willReturn('mysql');
		
		return [
			'db'	=> $db, 
		];
	
	}
	
	function setup_options_language_mocks(Options $options_object, Language $language_object){
	
		//OPTIONS
		$options = $this->prophet->prophesize('PolyAuth\Options');
		$options_array = $options_object->options;
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
		$options = $options->reveal();
		
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
		$language = $language->reveal();
		
		//OPTIONS FIXTURES
		$options['login_forgot_expiration'] = 1000;
		
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
	
	function setup_rbac_mocks(){
	
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
	
		$rbac = $this->prophet->prophesize('PolyAuth\Accounts\Rbac');
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
			'rbac'	=> $rbac->reveal(),
		];
	
	}
	
	function setup_password_complexity_mocks(){
	
		$password_complexity = $this->prophet->prophesize('PolyAuth\Security\PasswordComplexity');
		
		$password_complexity->complex_enough(Argument::type('string'), Argument::any(), Argument::any())->will(
			function($args){
				if(strlen($args[0]) < 8){
					$this->get_error()->willReturn('Password is not long enough.');
					return false;
				}elseif(strlen($args[0]) > 32){
					$this->get_error()->willReturn('Password is too long.');
					return false;
				}
				return true;
			}
		);
		
		return [
			'password_complexity'	=> $password_complexity->reveal(),
		];
	
	}
	
	function setup_random_mocks(){
	
		$random = $this->prophet->prophesize('PolyAuth\Security\Random');
		$random->generate(40)->willReturn('1234dsf4846dcvx4v45984839ghhghfjhgj5gfh6');
		$random->generate(32, true)->willReturn('1243b48%*&#$bi40*@(&^b465o^RFSDG');
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
	
	function it_checks_for_duplicate_identity_when_registering(){
		
		//this input data has the same username identity as the user fixture!
		$input_data = array(
			'username'			=> 'CMCDragonkai',
			'password'			=> 'P@szw0rd',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
		
		$this->shouldThrow(new UserDuplicateException('Username already used or invalid.'))->duringRegister($input_data);
	
	}
	
	function it_checks_for_password_complexity_when_registering(PDOStatement $sth){
	
		//to counteract the duplicate identity check
		$sth->fetch()->willReturn(false);
	
		$input_data = array(
			'username'			=> 'Deltakai',
			'password'			=> 'a', //<- this is too low for the minimum which is  by default 8
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
		
		$this->shouldThrow(new PasswordValidationException('Password is not long enough.'))->duringRegister($input_data);
	
	}
	
	function it_should_register_new_users_with_appropriate_permissions(PDOStatement $sth){
	
		//to counteract the duplicate identity check
		$sth->fetch()->willReturn(false);
		
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		//for the get_user query to return a database object
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($user_object);
	
		$input_data = array(
			'username'			=> 'CMCDragonkai',
			'password'			=> 'P@szw0rd',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
		
		$user_account = $this->register($input_data);
		
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		
		//with no password
		$user_account->get_user_data()->shouldReturn(array(
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		));
		
		$user_account->has_permission('Permission Name')->shouldReturn(true);
	
	}
	
	function it_should_activate_users(PDOStatement $sth){
	
		//for the update of the db record
		$sth->rowCount()->willReturn(1);
		$this->activate($this->user)->shouldReturn(true);
		
	}
	
	function it_should_not_activate_users_on_incorrect_activation_code(){
	
		//in the user fixture, the correct code is abcd1234
		$this->activate($this->user, 'nottheactivationcode')->shouldReturn(false);
		
	}
	
	function it_should_activate_users_on_correct_activation_code(PDOStatement $sth){
	
		//for the update of the db record
		$sth->rowCount()->willReturn(1);
		$this->activate($this->user, 'abcd1234')->shouldReturn(true);
		
	}
	
	function it_should_deactivate_users_and_return_activation_code(PDOStatement $sth){
	
		//for the update of the db record
		$sth->rowCount()->willReturn(1);
		$this->user['active'] = 1;
		$this->user['activationCode'] = '';
		$this->deactivate($this->user)->shouldBeString();
	
	}
	
	function it_should_be_able_to_complete_the_forgotten_cycle(PDOStatement $sth, Options $options_object){
	
		$sth->rowCount()->willReturn(1);
		
		//the login_forgot_expiration is set for 1000 seconds from our fixtures
	
		//let's assume that the forgotten emails were sent out
		$this->user['forgottenCode'] = 'abcd1234';
		
		//assume that the user placed the request 900 seconds ago
		$this->user['forgottenDate'] = date('Y-m-d H:i:s', strtotime('- 900 seconds', time()));
		
		$this->forgotten_check($this->user, 'abcd1234')->shouldReturn(true);
		
		$this->forgotten_check($this->user, 'notthecorrectforgottencode')->shouldReturn(false);
		
		//exceeding the time should return false
		$this->user['forgottenDate'] = date('Y-m-d H:i:s', strtotime('- 3000 seconds', time()));
		$this->forgotten_check($this->user, 'abcd1234')->shouldReturn(false);
	
	}
	
	function it_should_manipulate_passwords(PDOStatement $sth){
	
		//for the password update query
		$sth->rowCount()->willReturn(1);
	
		$this->change_password($this->user, 'blah1234')->shouldReturn(true);
		
		$this->shouldThrow(new PasswordValidationException('Password is not long enough.'))->duringChange_password($this->user, 'a');
		
		$this->shouldThrow(new PasswordValidationException('Password is too long.'))->duringChange_password($this->user, uniqid('abcdpefdgdutrghksdfnufg', true));
		
		$this->force_password_change(array($this->user))->shouldReturn(true);
	
	}
	
	function it_should_pass_password_complexity_checks_when_resetting_passwords(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
		
		$this->reset_password($this->user)->shouldBeString();
	
	}
	
	function it_should_be_able_to_get_a_user(PDOStatement $sth){
	
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		//for the get_user query to return a database object
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($user_object);
		
		$user_account = $this->get_user(1);
		
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		
		//with no password
		$user_account->get_user_data()->shouldReturn(array(
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		));
		
		$user_account->has_permission('Permission Name')->shouldReturn(true);
	
	}
	
	function it_should_be_able_to_get_an_array_of_users(PDOStatement $sth){
	
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		$user_object2 = new \stdClass;
		$user_object2->id = 2;
		$user_object2->username = 'CMCDragonkai';
		$user_object2->password = 'P@szw0rd';
		$user_object2->email = 'example@example.com';
		$user_object2->extraRandomField = 'Hoopla!';
		
		$sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array(
			$user_object,
			$user_object2,
		));
		
		$this->get_users(array(1, 2))->shouldBeArray();
		$this->get_users(array(1, 2))->shouldHaveCount(2);
		
		$users = $this->get_users(array(1, 2));
		
		//based on their ids
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		$users[1]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		
		$users[0]->has_permission('Permission Name')->shouldReturn(true);
	
	}
	
	function it_should_get_users_by_roles(PDOStatement $sth){
	
		$role_object = new \stdClass;
		$role_object->subject_id = 1;
		
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		$sth->fetchAll(PDO::FETCH_OBJ)->will(function() use ($role_object, $user_object){
			$this->fetchAll(PDO::FETCH_OBJ)->willReturn(array($user_object));
			return array($role_object);
		});
		
		$users = $this->get_users_by_role(array('random_role_name'));
		
		$users->shouldBeArray();
		$users->shouldHaveCount(1);
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
	
	}
	
	function it_should_get_users_by_permissions(PDOStatement $sth){
	
		$permission_object = new \stdClass;
		$permission_object->subject_id = 1;
		
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		// $sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array($role_object));
		$sth->fetchAll(PDO::FETCH_OBJ)->will(function() use ($permission_object, $user_object){
			$this->fetchAll(PDO::FETCH_OBJ)->willReturn(array($user_object));
			return array($permission_object);
		});
		
		$users = $this->get_users_by_permission(array('random_permission_name'));
		
		$users->shouldBeArray();
		$users->shouldHaveCount(1);
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
	
	}
	
	function it_should_update_users_with_new_data(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
	
		//adding new additional data
		$this->user['extraRandomField'] = 'Blah';
		$new_additional_data['extraRandomField'] = 'Replaced';
		$new_additional_data['anotherRandomField'] = 'Blah2';
	
		$user_account = $this->update_user($this->user, $new_additional_data);
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		$user_account['extraRandomField']->shouldReturn('Replaced');
		$user_account['anotherRandomField']->shouldReturn('Blah2');
		$user_account['id']->shouldReturn(1);
		
		$this->shouldThrow(new DatabaseValidationException('Cannot update without valid data fields.'))->duringUpdate_user($this->user, array('nonexisting' => 'notgoingtowork'));
	
	}
	
	function it_should_ban_and_unban_users(PDOStatement $sth){
	
		//update query
		$sth->rowCount()->willReturn(1);
		
		$user_account = $this->ban_user($this->user);
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		$user_account['banned']->shouldReturn(1);
		
		$user_account = $this->unban_user($user_account);
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		$user_account['banned']->shouldReturn(0);
	
	}
	
}
