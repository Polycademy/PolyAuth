<?php 

namespace PolyAuth\Authentication;


use PolyAuth\Storage\StorageInterface;
use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\Accounts\Rbac;
use PolyAuth\Security\LoginAttempts;

use PolyAuth\UserAccount;

use Symfony\Component\HttpFoundation\Request;

use PolyAuth\Exceptions\UserExceptions\UserPasswordChangeException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserExceptions\UserBannedException;
use PolyAuth\Exceptions\UserExceptions\UserInactiveException;
use PolyAuth\Exceptions\ValidationExceptions\StrategyValidationException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\ValidationExceptions\LoginValidationException;

class Authenticator{

	protected $strategy;
	protected $storage;
	protected $options;
	protected $lang;
	protected $accounts_manager;
	protected $rbac;
	protected $login_attempts;
	protected $request;

	protected $user;

	public function __construct(
		$strategy, 
		StorageInterface $storage, 
		Options $options, 
		Language $language, 
		AccountsManager $accounts_manager = null, 
		Rbac $rbac = null,
		LoginAttempts $login_attempts = null,
		Request $request = null
	){

		$this->strategy = $strategy;
		$this->storage = $storage;
		$this->options = $options;
		$this->lang = $language;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);
		$this->rbac = ($rbac) ? $rbac : new Rbac($storage, $language);
		$this->login_attempts = ($login_attempts) ? $login_attempts : new LoginAttempts($storage, $options);
		$this->request = ($request) ? $request : Request::createFromGlobals();
	
	}

	/**
	 * Start the tracking sessions. You should only call this once. However multiple calls to this function
	 * is idempotent.
	 * It will:
	 * 		assign anonymous users an anonymous session, 
	 *   	attempt autologin, 
	 *    	detect inactive users, -> exception and logged out
	 *     	detect banned users, -> exception and logged out
	 *      detect whether passwords need to change, -> exception 
	 *      and expire long lived sessions. -> logged out
	 * Wrap this call in a try catch block and handle any exceptions.
	 * The exceptions stem from autologin conditions, such as banned.
	 */
	public function start(){

		if(!empty($this->user)){
			return;
		}

		$this->strategy->start_session();

		$session = $this->strategy->get_session();

		//check the session then the $this->user object
		$user_id = false;
		if(!empty($session['user_id']) OR $session['user_id'] === 0){
			$user_id = $session['user_id'];
		}elseif($this->user instanceof UserAccount AND (!empty($this->user['id']) OR $this->user['id'] === 0)){
			$user_id = $this->user['id'];
		}

		//check the database
		try{
			if($user_id){
				$user = $this->accounts_manager->get_user($user_id);
			}else{
				$user = false;
			}
		}catch(UserNotFoundException $e){
			$user = false;
		}

		if($user){
			
			$this->set_session_state($user);

		}else{

			//create an anonymous user
			$this->set_session_state();
			//attempt autologin, it would overwrite the anonymous user if it succeeds
			$this->autologin();

		}
	
	}

	/**
	 * Manually logs in the user, given a $data array of input parameters.
	 * The input parameter can be an array of ['identity'] (string) AND ['password'] (string) AND ['autologin'] (boolean)
	 * However it is also optional, if you are using Oauth or HTTP auth.
	 * In that case, it will automatically extract the necessary tokens.
	 * If you wish to bypass the login throttling, just pass in $force_login as true.
	 * You should use $force_login in conjunction with a captcha form to allow real users to bypass.
	 * After all login throttling is meant to be used against bots. Not real users.
	 * Beware of forgotten password or identity, when a user completes the cycle, they should still be able to login
	 *
	 * @param $data array optional
	 * @param $force_login boolean
	 * @return boolean
	 */
	public function login(array $data, $temp = false, $force_login = false, $strategy = false){

		//this only works with composite strategy,
		//this is mainly used in case you know the context will default the first strategy
		//but you want to login via a different strategy in the composite strategy
		if($strategy){
			$this->strategy->switch_context($strategy);
		}

		if(!$force_login AND !empty($this->options['login_lockout'])){
			//is the current login attempt locked out?
			$lockout_time = $this->login_attempts->locked_out($data['identity']);
			//if the lockout_time is true, non-zero integer
			if($lockout_time){
				$this->login_failure($data, sprintf($this->lang['login_lockout'], $lockout_time));
			}
		}

		$user = $this->strategy->login($data);

		//returning false would indicate that the login did not run at all, which is suitable for certain flows
		if(!$user){
			return false;
		}

		//if the user returned was not UserAccount, that means it failed to login
		if(!$user instanceof UserAccount){

			//Consider OAuthProvider
			//1. Auth Code grant -> client credentials could be wrong and resource owner credentials could be wrong
			//2. Resource Owner Password -> cc could be wrong, roc could also be wrong
			//3. Client Credentials -> cc could be wrong
			//For 1. You cannot get the ip of the client who redirected the user. Therefore it's not reliable and
			//cannot be throttled. Besides how do you throttle redirects!?
			//For 2. The ROC is who you would throttle. This is because the ROC is an attempt to login into the
			//resource using ROC credentials. But the IP would be from the CC, since it's sending a request.
			//For 3. The CC is who you would throttle. So in this the case, the $data makes sense. They need the 
			//'identity'!
			
			//BASICALLY, the throttling needs to be more detailed in relation to OAuthProvision since the IP may not represent the actual credentials. And that there is actually 2 credentials from separate users. The client and resource owner.

			$this->login_failure($user['identity'], $user['message'], $user['throttle']);
		}

		if(!empty($this->options['login_lockout'])){
			$this->login_attempts->clear($this->user[$this->options['login_identity']]);
		}

		//if temp is true, this returns the user account after validating the credentials
		//but it does not set any kind of loggedin state
		//this is useful for 2 factor authentication, where you need to get the user details
		//to implement the second factor authentication, and then login for real after the second factor has been validated
		if($temp){
			return $user;
		}

		//set the user
		$this->set_session_state($user);

		$this->storage->update_last_login($this->user['id'], $this->get_ip());

		$this->check_inactive($this->user);
		$this->check_banned($this->user);
		$this->check_password_change($this->user);

		return true;
	
	}

	/**
	 * Logout, this will destroy all the previous session data and recreate an anonymous session.
	 * It is possible to call this without calling $this->start().
	 * It will also delete the session cookie and autologin cookie.
	 * It will clear the $this->user variable
	 */
	public function logout(){
		
		//perform any custom authentication functions
		$this->strategy->logout();

		//clears the current user
		$this->user = null;
		
		//start a new session that would anonymous
		$this->start();
	
	}

	public function get_response(){

		return $this->strategy->get_response();

	}

	/**
	 * Gets the currently logged in user's user account
	 * It calls accounts manager rather than just returning the user here because
	 * the user here is not as up to date as the one from the database.
	 * @return object|null gives back null if anonymous, otherwise an UserAccount object
	 */
	public function get_user(){

		return $this->user;
	
	}
	
	/**
	 * Gets the current session manager if you want granular control.
	 */
	public function get_session(){
		
		return $this->strategy->get_session();
	
	}

	public function get_strategy(){

		return $this->strategy;

	}

	public function send_challenge(){

		$this->strategy->challenge();
	
	}
	
	protected function set_session_state(UserAccount $user = null){

		$session = $this->strategy->get_session();

		//if the user doesn't exist, we'll setup an anonymous user
		if(!$user){

			$session['user_id'] = false;
			$anonymous_user = new UserAccount(false);
			$anonymous_user->set_user_data(array(
				'anonymous'	=> true
			));
			$this->user = $anonymous_user;

		}else{

			$session['user_id'] = $user['id'];
			$this->user = $user;
			
		}

	}
	
	/**
	 * Autologin cycles through all of the authentication strategies to check if at least one of the autologins worked.
	 * As soon as one of them works, it breaks the loop, and then updates the last login, and sets the session parameters.
	 * The user_id gets set the passed back user id. The anonymous becomes false, and the timeout is refreshed.
	 * This checks for password change and banned status and will throw appropriate exceptions.
	 * It will assign the user account to the $this->user variable.
	 *
	 * @return boolean
	 */
	protected function autologin(){

		$user = $this->strategy->autologin();
		
		if($user){

			//user is now logged in
			$this->set_session_state($user);

			$this->storage->update_last_login($this->user['id'], $this->get_ip());
			
			//final checks before we proceed (inactive or banned would logout the user)
			$this->check_inactive($this->user);
			$this->check_banned($this->user);
			$this->check_password_change($this->user);
			
			return true;
		
		}else{
		
			return false;
		
		}
	
	}
	
	/**
	 * Login failure should be called when the login did not succeed. This throws the LoginValidationException.
	 * However it also increments the login attempts and calls the logout hook.
	 * You can pass the third parameter to prevent it from incrementing the login attempts.
	 * The third parameter should be true when the attempt is a real login attempt.
	 * The only attempt that should be throttled is ones where the attempt
	 * was one with a real identity but the wrong password. Other attempts will not be considered.
	 *
	 * @param $data anything
	 * @param $message string
	 * @param $throttle boolean
	 * @throw Exception LoginValidationException
	 */
	protected function login_failure($identity, $message, $throttle = false){
	
		$exception = new LoginValidationException($message);
		
		//if the identity does not exist, there's no point throttling, even on ip addresses
		//this would be the equivalent of an attacker trying to login with no username/email
		//or it could just be a user that forgot to enter the username
		//at any case, it's not a threat
		if(!empty($identity) AND $throttle AND !empty($this->options['login_lockout'])){
			$this->login_attempts->increment($identity);
		}
		
		//everytime the user fails to login, we log him out completely, this could have ramifications if users login after they are already logged in
		$this->logout();
		
		throw $exception;
	
	}
	
	/**
	 * Checks if a user is inactive. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserInactiveException
	 */
	protected function check_inactive(UserAccount $user){
	
		if($user['active'] == 0){
			$this->login_failure(false, $this->lang['user_inactive']);
		}
	
	}
	
	/**
	 * Checks if a user is banned. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserBannedException
	 */
	protected function check_banned(UserAccount $user){
	
		if($user['banned'] == 1){
			$this->login_failure(false, $this->lang['user_banned']);
		}
	
	}
	
	/**
	 * Checks if a user needs to change his current password.
	 *
	 * @param $user UserAccount
	 * @throw Exception PasswordChangeException
	 */
	protected function check_password_change(UserAccount $user){
		
		if($user['passwordChange'] == 1){
			throw new UserPasswordChangeException($this->lang['password_change_required']);
		}
		
	}

	/**
	 * Helper function to get the ip and format it correctly for insertion.
	 *
	 * @return $ip_address binary | string
	 */
	protected function get_ip() {
	
		$ip_address = $this->request->getClientIp();
		return inet_pton($ip_address);
		
	}
	
}