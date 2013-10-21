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

class HTTPDigestStrategy extends AbstractStrategy implements StrategyInterface{

	protected $storage;
	protected $options;
	protected $session_manager;
	protected $realm;
	protected $request;
	protected $response;
	protected $accounts_manager;
	protected $encryption;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		Language $language, 
		SessionManager $session_manager, 
		$realm = false, 
		Request $request = null, 
		Response $response = null, 
		AccountsManager $accounts_manager = null, 
		Encryption $encryption = null
	){
		
		$this->storage = $storage;
		$this->options = $options;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);
		$this->encryption = ($encryption) ? $encryption : new Encryption;

		$this->realm = ($realm) ? $realm : 'Protected by PolyAuth';
		
	}

	/**
	 * Detects if the request headers contains HTTP digest authorization. This also makes sure
	 * that the request body does not have 'grant_type' in application/x-www-form-urlencoded
	 * Because that would conflict with the OAuth flows which may authenticate the client using
	 * HTTP Digest as well.
	 * @return Boolean
	 */
	public function detect_relevance(){

		if(
			$this->request->headers->has('php_auth_digest') 
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
	 * Autologin is based on the HTTP header containing HTTP Digest authorization.
	 * HTTP Digest relies on sharedKey not password.
	 * @return UserAccount|Boolean
	 */
	public function autologin(){

		$digest = $this->request->headers->get('php_auth_digest');

		if($digest){

			$digest_parts = $this->parse_digest($digest);

			$row = $this->storage->get_login_check($digest_parts['username']);

			if($row){

				$shared_key = $this->encryption->decrypt($row->sharedKey, $this->options['shared_key_encryption']);

				$a1 = md5($digest_parts['username'] . ':' . $this->realm . ':' . $shared_key);
				$a2 = md5($this->request->getMethod() . ':' . $digest_parts['uri']);

				$valid_response_hash = md5(
					$a1 . 
					':' . 
					$digest_parts['nonce'] . 
					':' . 
					$digest_parts['nc'] . 
					':' . 
					$digest_parts['cnonce'] . 
					':' . 
					$digest_parts['qop'] . 
					':' . 
					$a2
				);

				if($valid_response_hash == $digest_parts['response']){

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
	public function login($data, $external = false){
		
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
	 * send the headers. Digest realm should not be changed, as it is relied to create 
	 * response hash during autologin.
	 * @return Void
	 */
	public function challenge(){

		$realm = $this->realm;
		$nonce = md5(uniqid());
		$opaque = md5(uniqid());
		$this->response->setStatusCode(401, 'Unauthorized');
		$this->response->headers->set('WWW-Authenticate', sprintf('Digest realm="%s", nonce="%s", opaque="%s"', $realm, $nonce, $opaque));
	
	}

	/**
	 * Parses the digest authorization header. This returns an array of digest parts.
	 * @param  String $digest Digest HTTP Authorization
	 * @return Array
	 */
	protected function parse_digest($digest){

		$needed_parts = array(
			'nonce'		=> 1, 
			'nc'		=> 1, 
			'cnonce'	=> 1, 
			'qop'		=> 1, 
			'username'	=> 1, 
			'uri'		=> 1, 
			'response'	= >1
		);

		$data = array();

		$keys = implode('|', array_keys($needed_parts));

		preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

		foreach($matches as $m){

			$data[$m[1]] = $m[3] ? $m[3] : $m[4];
			unset($needed_parts[$m[1]]);
		
		}

		return $needed_parts ? false : $data;

	}

}