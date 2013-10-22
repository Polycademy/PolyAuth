<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

use PolyAuth\Options;
use PolyAuth\Language;

use PolyAuth\Exceptions\ValidationExceptions\PersonaValidationException;
use PolyAuth\Exceptions\HttpExceptions\HttpPersonaException;

/*
	PersonaDecorator relies on Email as the user identity. You must be using email as the login identity for
	this to work.
 */
class PersonaDecorator extends AbstractDecorator{

	protected $options;
	protected $lang;
	protected $audience;
	protected $verifier;

	/**
	 * Construct Persona Decorator. It requires language for a potential error in requesting the verifier.
	 * It also supplies optional $audience and $verifier. If you are not sure if the server is setup securely,
	 * you should supply an $audience directly as it is difficult for PolyAuth to ascertain the real and
	 * non-tampered server domain name. It requires the scheme, domain and port if necessary.
	 * @param AbstractStrategy|AbstractDecorator $strategy
	 * @param Language                           $language
	 * @param String|Boolean                     $audience
	 * @param String|Boolean                     $verifier
	 */
	public function __construct(
		$strategy, 
		Options $options, 
		Language $language, 
		$audience = false, 
		$verifier = false
	){

		$this->strategy = $strategy;
		$this->options = $options;
		$this->lang = $language;
		$this->audience = ($audience) ? $audience : $this->strategy->request->getSchemeAndHttpHost();
		$this->verifier = ($verifier) ? $verifier : 'https://verifier.login.persona.org/verify';

		if($this->options['login_identity'] != 'email'){
			throw PersonaValidationException('PersonaDecorator requires "login_identity" in Options to be set to "email"');
		}

	}

	/**
	 * Login via Persona. It expects an assertion field containing the Persona certificate, which is 
	 * requested client side. If the identity never existed in PolyAuth, it will automatically create 
	 * an account.
	 * @param  Array   $data     $data field with an assertion field
	 * @param  Boolean $external Pass $external from upstream Decorators
	 * @return UserAccount|Array
	 */
	public function login($data, $external = false){

		if(!empty($data['assertion'])){

			$request_body = http_build_query(
				array(
					'assertion'	=> $data['assertion'],
					'audience'	=> $this->audience
				),
				null,
				'&'
			);

			$context = stream_context_create(array(
				'http' => array(
					'method'			=> 'POST',
					'header'			=> 'Content-type: application/x-www-form-urlencoded',
					'content'			=> $request_body,
					'protocol_version'	=> '1.1',
					'user_agent'		=> 'PolyAuth',
					'max_redirects'		=> 5,
					'timeout'			=> 15
				)
			));

			$level = error_reporting(0);
			$response = file_get_contents($this->verifier, false, $context);
			error_reporting($level);

			//if response was false, this means the url could not be accessed
			if($response === false){
				$last_error = error_get_last();
				if(is_null($last_error)){
					throw new HttpPersonaException($this->lang['persona_verifier']);
				}
				throw new HttpPersonaException($last_error['message']);
			}

			$response = json_decode($response, true);

			if($response['status'] == 'okay'){

				$row = $this->strategy->storage->get_login_check($response['email']);

				//if the identity doesn't exist, we'll create a new account
				if(!$row){
					$this->strategy->accounts_manager->external_register(array(
						'email'	=> $response['email']
					));
				}

				return $this->strategy->accounts_manager->get_user(false, $response['email']);

			}

			//failed to login via persona, the login failed!
			return array(
				'Anonymous',
				$this->lang['login_unsuccessful'],
				false
			);

		}else{

			$this->strategy->login($data, $external);

		}

	}

}