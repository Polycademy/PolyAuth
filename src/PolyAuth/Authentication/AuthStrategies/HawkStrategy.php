<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Sessions\SessionManager;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\UserAccount;

use Dflydev\Hawk\Credentials\Credentials;
use Dflydev\Hawk\Server\ServerBuilder;
use Dflydev\Hawk\Server\UnauthorizedException;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class HawkStrategy extends AbstractStrategy implements StrategyInterface{

	protected $storage;
	protected $session_manager;
	protected $hawk_options;
	protected $request;
	protected $response;
	protected $accounts_manager;
	protected $random;
	protected $hawk_server;

	protected $credentials;
	protected $artifacts;

	public function __construct(
		StorageInterface $storage, 
		Options $options,
		Language $language, 
		SessionManager $session_manager, 
		array $hawk_options = array(), 
		Request $request = null, 
		Response $response = null, 
		AccountsManager $accounts_manager = null, 
		Credentials $credentials = null, 
		ServerBuilder $server_builder = null
	){

		$this->storage = $storage;
		$this->lang = $language;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);

		$this->hawk_options = array_merge(
			array(
				'algorithm'				=> 'sha256',
				'payload_validation'	=> false //payload validation may be cpu intensive if the payload is large, or you may even run out of memory
			),
			$hawk_options
		);

		//the server requires a function that will get the hmac shared secret based on the identity to compare with
		//the hawk request credentials
		$algorithm = $this->hawk_options['algorithm'];
		$credentials_provider = function($identity) use ($algorithm){

			$row = $this->storage->get_login_check($identity);

			//hmac will always be stored for each user
			//however if the identity doesn't exist, we'll return a credential with a false secret
			//it won't match any credentials passed in the request
			if($row){
				$secret = $row->hmac;
				$id = $row->id;
			}else{
				$secret = false;
				$id = false;
			}

			//third parameter of credentials is optional, we are going to return an array that contains
			//both the id and the identity of the this authenticated user
			return new Credentials(
				$secret,
				$algorithm, 
				array(
					'id'		=> $id,
					'identity'	=> $identity
				)
			);

		};

		$this->hawk_server = ServerBuilder::create($credentials_provider)->build();

	}

	public function detect_relevance{

		$authorization = $this->request->headers->get('authorization');

		if($authorization){

			//check if it has Hawk at the start
			$position = strpos($authorization, 'Hawk');

			if($position === 0){

				return true;
			
			}

		}

		return false;

	}

	public function start_session(){

		$this->session_manager->start();

	}

	public function autologin(){

		$payload = null;

		if($hawk_options['payload_validation']){

			$request_method = $this->request->getMethod();

			if(
				$request_method == 'POST' 
				OR 
				$request_method == 'PUT' 
				OR 
				$request_method == 'PATCH' 
				OR 
				$request_method == 'OPTIONS'
			){

				$payload = $this->request->getContent();

			}

		}

		try{

			$response = $this->hawk_server->authenticate(
				$this->request->getMethod(),
				$this->request->getHost(),
				$this->request->getPort(),
				$this->request->getRequestUri(),
				$this->request->headers->get('content-type'),
				$payload,
				$this->request->headers->get('authorization')
			);

		}catch(UnauthorizedException $e){

			return false;

		}

		$this->credentials = $response->credentials();
		$this->artifacts = $response->artifacts();

		//we need the id, not the identity to get the user account
		return $this->accounts_manager->get_user($response->credentials()->id()['id']);

	}

	public function login($data, $external = false){

		return false;

	}

	public function logout(){

		$this->session_manager->finish();

	}

	public function challenge(){

		$this->response->setStatusCode(401, 'Unauthorized');
		$this->response->headers->set('WWW-Authenticate', 'Hawk');

	}

	//unique to hawk!
	public function authenticate_response($payload, $content_type, $ext = null, $raw = false){

		//cannot authenticate response without an authenticated request
		if(empty($this->credentials)){
			return false;
		}

		$header = $this->hawk_server->createHeader(
			$this->credentials,
			$this->artifacts,
			array(
				'payload'		=> $payload,
				'content_type'	=> $content_type,
				'ext'			=> $ext
			)
		);

		if($raw){
			return array($header->fieldName() => $header->fieldValue());
		}else{
			$this->response->headers->set($header->fieldName(), $header->fieldValue());
			return true;
		}

	}

}