<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Storage\StorageInterface;
use PolyAuth\Cookies;
use PolyAuth\Security\Random;
use PolyAuth\Accounts\AccountsManager;

use OAuth\Common\Http\Uri\UriFactory;
use OAuth\ServiceFactory;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Storage\Memory;

use PolyAuth\Exceptions\PolyAuthException;

//if there's an error in getting the access token
use OAuth\Common\Http\Exception\TokenResponseException;
//if the token expired already
use OAuth\Common\Token\Exception\ExpiredTokenException;
//oauth1 exception
use OAuth\OAuth1\Signature\Exception\UnsupportedHashAlgorithm;
//oauth2 exceptions
use OAuth\OAuth2\Service\Exception\InvalidScopeException;
use OAuth\OAuth2\Service\Exception\MissingRefreshTokenException;

//NEED TO SET A STATE COOKIE upon start. This a session + httpOnly cookie! will be compared with redirect.
//Also query param of provider on redirect!


//GET authorisation uri

//here's what needs to happen:
//1. cascading multiple strategies
//2. pass in providers here and in options
//3. autologin can cascade easily
//4. login cannot cascade easily, it requires data to be passed in and is unique to each strategy

//try extending OAuthStrategy to CookieStrategy, to allow independent logins and autologin functionality
class OAuthClientDecorator extends AbstractDecorator{

	protected $storage;
	protected $options;
	protected $language;
	protected $cookies;
	protected $random;
	protected $accounts_manager;
	protected $uri_factory;
	protected $service_factory;
	protected $providers;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options,
		Language $language, 
		Cookies $cookies = null, 
		Random $random = null,
		AccountsManager $accounts_manager = null,
		UriFactory $uri_factory = null,
		ServiceFactory $service_factory = null
	){

		$this->storage = $storage;
		$this->options = $options;
		$this->language = $language;
		$this->cookies = ($cookies) ? $cookies : new Cookies($options);
		$this->random = ($random) ? $random : new Random;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);
		$this->uri_factory = ($uri_factory) ? $uri_factory : new UriFactory;
		$this->service_factory = ($service_factory) ? $service_factory : new ServiceFactory;

		$this->providers = $this->setup_providers($this->options['external_providers']);
		
	}

	public function autologin(){

		//IN THE AUTOLOGIN... it would have to direct itself not to the subsequent autologin, but to the login().
		//Right now it would have to pass $data['identity'], $data['password'] and $data['autologin'] <= this would be 
		//true automatically depending on the options it passes in. And it would return a user account from there.
		//It obviously cannot pass password as that would be null. 
		//So it would just pass $data['identity'], $data['autologin'] and then a second parameter of $external

		if($auth_code){
			$user = $this->strategy->login(array(
				'identity'	=> $identity,
				'autologin'	=> ($autologin) ? true : false
			), true);

			if(!$user instanceof UserAccount){
				return false;
			}
			
			return $user;

		}

	}

	//this function should return the providers object
	//so they can be used to request stuff... independently,
	//basically so the API is exposed.
	public function get_providers(){

		return $this->providers;

	}

	/**
	 * Returns the url to authorise the users via the external provider.
	 * You can do a redirect, or simply give the link to the user to click on.
	 * I recommend using a popup based redirect, that way your user doesn't lose their work.
	 * @param  string $provider Name of the provider
	 * @return string           Url to be redirected to
	 */
	public function get_auth_endpoint($provider){

		return $this->providers[$provider]['service']->getAuthorizationUri();

	}

	public function autologin(){

	};
	
	public function set_autologin($user_id){

	};
	
	//This is actually called after the provider has redirected back to you
	//You do not normally hit $this->login, cause you need to get them to go to other URL first
	//When they redirect back with the code, you can then use this
	public function login_hook($data){

		if(empty($_GET['code']) OR empty($_GET['provider'])){
			throw new PolyAuthException('You only login with the OAuth strategy after the provider has redirected back to you. It needs $_GET[\'code\'] and $_GET[\'provider\']');
		}

		$provider = $this->providers[$_GET['provider']];

		//exchange the code for the access token
		$token = $provider['service']->requestAccessToken($_GET['code']);

		//we need to identify if this is a prexisting user
		$identifier_type = $provider['identifier']['type'];
		$identifier_key = $provider['identifier']['key'];
		$identifier_api = $provider['identifier']['api'];

		//so we'll inspect an external identifier
		$user_profile = json_decode($provider['service']->request($identifier_api), true);
		$external_identifier = $user_profile[$identifier_key];

		//now let's check with the accounts manager
		//the value will be prefixed with the type
		//so that there is no confusion between identifiers
		$external_identifier = $identifier_type . ':' . $external_identifier;

		$provider_records = $this->accounts_manager->external_provider_check($external_identifier, $provider['name']);

		if(!empty($provider_records['provider_id'])){

			//update existing provider
			$this->accounts_manager->update_external_provider(
				$provider_records['provider_id'], 
				array('tokenObject' => $token)
			);
			$user_id = $provider_records['user_id'];

		}elseif(!empty($provider_records['user_id']) AND $this->options['external_federation']){

			//federate the providers (add the provider to an existing user)
			$this->accounts_manager->register_external_provider(array(
				'userId'				=> $provider_records['user_id'],
				'provider'				=> $provider['name'],
				'externalIdentifier'	=> $external_identifier,
				'tokenObject'			=> $token,
			));
			$user_id = $provider_records['user_id'];

		}else{

			//create a new user account and add the provider to an existing user
			$user_id = $this->accounts_manager->external_register()['id'];
			$this->accounts_manager->register_external_provider(array(
				'userId'				=> $user_id,
				'provider'				=> $provider['name'],
				'externalIdentifier'	=> $external_identifier,
				'tokenObject'			=> $token,
			));

		}

		//at this point we have the user. But we cannot pass back an identity and password
		//this is because the password does not exist...
		//so we'll require a different login function
		//or an augmented login function, perhaps the login function can check if $data is the user id, just an integer...?
		return (int) $user_id;
		//this will require more modification!
		//and cleanup
		//CONTINUE HERE, you need to modify the login function and UserSessions... etc
		//Along with AccountsManager



		//the steps (for OAUTH2)
		//request the access token
		//request the user details from the options
		//check for correspondence through the external identity (may require AccountsManager), we also need to extract the user id
		//if the same user + same account, just login normally and update the tokens
		//if the same user + different accounts, federate the accounts
		//if new user, create a new user (leniently)
		//the identity and password will be randomised with a prefix
		//store the token object (acquire it first) permanently, or update it
		//remember the options
		//get the user details, and return it
		//you need to return an array of identity & password
		//RECHECK the flow of OAUTH1 and branch accordingly

	};
	
	public function logout_hook(){

	};

	/**
	 * Setup providers is used to setup all the necessary objects for Oauth. 
	 * This is done for each provider that is listed in the options.
	 * Each provider hence has their own set of objects.
	 * The provider that will be used when logging in is determine at the point of logging in.
	 * It setups the default callback url, credentials, storage, service and version.
	 * @param  array  $external_providers The external providers option array.
	 * @return array                      A new augmented external providers array
	 */
	protected function setup_providers(array $external_providers){

		foreach($external_providers as $provider_name => $provider_parameters){

			//setup the callback urls
			if(empty($provider_parameters['callback_url'])){
				$uri = $this->uri_factory->createFromSuperGlobalArray($_SERVER);
			}else{
				$uri = $this->uri_factory->createFromAbsolute($provider_parameters['callback_url']);
			}

			//we'll use this in order to determine which provider redirected to us
			$uri->addToQuery('provider', $provider_name);
			$callback_url = $uri->getAbsoluteUri();

			//setup the credentials of each one
			$credentials = new Credentials(
				$provider_parameters['key'],
				$provider_parameters['secret'],
				$callback_url
			);

			//each service will have its own in memory token storage
			$storage = new Memory;

			//each service obviously has their own independent service object
			$service = $this->service_factory->createService(
				$provider_name,
				$credentials,
				$storage,
				$provider_parameters['scope']
			);

			//determine whether strategy is OAuth1 or OAuth2, will be required to branch logic
			if(is_in_namespace('OAuth1', $service)){
				$version = 1;
			}elseif(is_in_namespace('OAuth2', $service){
				$version = 2;
			};

			//we'll need all of them, merge back into the original array
			$external_providers[$provider_name] = array_merge(
				$external_providers[$provider_name], 
				array(
					'callback_url'	=> $callback_url,
					'credentials'	=> $credentials,
					'service'		=> $service,
					'version'		=> $version,
					'name'			=> $provider_name, //just to make it easier to get the name
				)
			);

		}

		return $external_providers;

	}

	protected function is_in_namespace($namespace, $object){

		return stripos(get_class($object), $namespace . '\\') === 0;

	}
	
}
