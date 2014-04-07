<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

use PolyAuth\Options;
use PolyAuth\Language;

use Guzzle\Http\Client;

use Guzzle\Http\Exception\BadResponseException;
use Guzzle\Http\Exception\CurlException;

use PolyAuth\Exceptions\ValidationExceptions\PersonaValidationException;
use PolyAuth\Exceptions\HttpExceptions\HttpPersonaException;

/*
	PersonaDecorator relies on Email as the user identity. You must be using email as the login identity for
	this to work.
 */
class PersonaClientDecorator extends AbstractDecorator{

	protected $options;
	protected $lang;
	protected $audience;
	protected $verifier;
	protected $client;

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
		$verifier = false,
		Client $client = null
	){

		$this->strategy = $strategy;
		$this->options = $options;
		$this->lang = $language;
		$this->audience = ($audience) ? $audience : $this->strategy->request->getSchemeAndHttpHost();
		$this->verifier = ($verifier) ? $verifier : 'https://verifier.login.persona.org/verify';
		$this->client = ($client) ? $client : new Client;

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

			try{

				$this->client->setUserAgent('PolyAuth');

				$request = $this->client->post(
					$this->verifier, 
					array(
						'Content-Type': 'application/x-www-form-urlencoded'
					), 
					array(
						'assertion'	=> $data['assertion'],
						'audience'	=> $this->audience
					)
				);

				$response = $request->send();

			}catch(BadResponseException $e){

				throw new HttpPersonaException($this->lang['persona_verifier']);

			}catch(CurlException $e){

				throw new HttpPersonaException($this->lang['persona_verifier']);

			}

			$response = $response->json();

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