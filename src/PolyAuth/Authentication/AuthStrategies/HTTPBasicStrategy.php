<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Sessions\SessionManager;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\UserAccount;
use PolyAuth\Security\Encryption;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class HTTPBasicStrategy extends AbstractStrategy{

	protected $storage;
	protected $session_manager;
	protected $basic_options;
	protected $request;
	protected $response;
	protected $accounts_manager;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		Language $language, 
		SessionManager $session_manager, 
		array $basic_options = null,
		Request $request = null, 
		Response $response = null, 
		AccountsManager $accounts_manager = null,
		Encryption $encryption = null
	){
		
		$this->storage = $storage;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);
		$this->encryption = ($encryption) ? $encryption : new Encryption;

		//http basic can use the "key" instead of the password as the password, this is preferred by APIs
		$this->basic_options = array_merge(
			array(
				'realm'		=> 'Protected by PolyAuth',
				'secret'	=> 'password',
			),
			$basic_options
		);
		
	}

	/**
	 * Detects if the request headers contains HTTP basic authorization. This also makes sure
	 * that the request body does not have 'grant_type' in application/x-www-form-urlencoded
	 * Because that would conflict with the OAuth flows which may authenticate the client using
	 * HTTP Basic as well.
	 * @return Boolean
	 */
	public function detect_relevance(){

		if(
			$this->request->headers->has('php_auth_user') 
			AND 
			$this->request->headers->has('php_auth_pw') 
			AND 
			!$this->request->request->has('grant_type')
		){

			return true;

		}

		return false;

	}

	/**
	 * Starts an anonymous session as this stateless.
	 * @return Void
	 */
	public function start_session(){

		$this->session_manager->start();

	}
	
	/**
	 * Autologin is based on the HTTP header containing HTTP Basic authorization
	 * @return UserAccount|Boolean
	 */
	public function autologin(){

		$identity = $this->request->headers->get('php_auth_user');
		$password = $this->request->headers->get('php_auth_pw');

		if($identity AND $password){

			$row = $this->storage->get_login_check($identity);

			if($this->basic_options['secret'] == 'password'){

				if($row AND password_verify($password, $row->password)){

					return $this->accounts_manager->get_user($row->id);
				
				}

			}elseif($this->basic_options['secret'] == 'key'){

				$key = $this->encryption->decrypt($row->sharedKey, $this->options['shared_key_encryption']);

				if($row AND $password == $key){

					return $this->accounts_manager->get_user($row->id);
				
				}

			}

		}

		return false;
	
	}
	
	/**
	 * Login does not do anything. Hence returns false.
	 * @return Boolean
	 */
	public function login(array $data, $external = false){
		
		return false;
	
	}
	
	/**
	 * Logout just destroys the session.
	 * @return Void
	 */
	public function logout(){

		$this->session_manager->finish();
	
	}
	
	/**
	 * Challenges the client in the response. Get the response object and 
	 * send the headers.
	 * @param  String $realm HTTP Basic realm
	 * @return Void
	 */
	public function challenge($realm = false){

		$realm = ($realm) ? $realm : $this->basic_options['realm'];
		$this->response->setStatusCode(401, 'Unauthorized');
		$this->response->headers->set('WWW-Authenticate', 'Basic realm="' . $realm . '"');
	
	}

}