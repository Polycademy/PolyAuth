<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

use PolyAuth\Options;
use PolyAuth\Language;

//WHEN OPENID creates a new account from someone who signed in/up
//it creates a user account with a prefilled username and external_provider row as well
//the external_provider determines the identity of the user whenever they need to sign into their open id
//the username will be prefilled with their open id, however OpenIdClient does not use the username or login_identity
//to determine if it's the same user. If the username is an identity field, and it needs to be unique, it will add
//a number to that open id
//We cannot get information from the service, because not all services provide information.
//If you do want extra information from the user, you should use OAuth, not OpenId, attribute exchange could work
//but it's all optional for the service providers
class OpenIdClientDecorator extends AbstractDecorator{

	protected $options;
	protected $lang;

	public function __construct(
		$strategy, 
		Options $options, 
		Language $language
	){

		$this->strategy = $strategy;
		$this->options = $options;
		$this->lang = $language;

	}

	public function detect_relevance(){

		//this is similar to Oauth's redirect, detect the redirect parameters

		return $this->strategy->detect_relevance();

	}

	public function autologin(){

		//from Open Id redirect

		return $this->strategy->autologin();

	}

	public function get_auth_endpoint($openid_identifier){

		//this login function may force a redirect, or give back the redirect uri
		//since this is created at run time depending on the open id uri, this has to be called
		//after the user submits the form
		//so therefore if you want js to go through a popup, this gives back the uri and then the redirect will
		//happen therefore the login being taken over by the autologin
		//actually this affects the response object and returns false...?
		//No either: array for failure, UserAccount for success, false for not running at all...?

		//this should be called instead when you need to login
		//because we would need to login directly...?
		//No there's a redirect that needs to happen

		$claimed_id = $this->normalize_uri($data['openid_identifier']);

		//id was malformed, so the login failed!
		if(!$claimed_id){
			return array(
				$data['openid_identifier'],
				$this->lang['login_unsuccessful'],
				false
			);
		}

		//perform discovery on auth end point: xri or yadis or html discovery
		if(isset($claimed_id['xri'])){
			//implement xri discovery
		}else{



		}

	}

	/**
	 * Parse the claimed identity uri. This will ignore any usernames, passwords or query parameters in the uri.
	 * That's to prevent different identity uris that point to the same identity. This works for xris as well.
	 * Code is taken and modified from Poidsy: http://apps.md87.co.uk/openid/
	 * If the uri is malformed, then it returns false.
	 */
	protected function normalize_uri($uri){

		//strip xri:// prefix
		if (substr($uri, 0, 6) == 'xri://') {
			$uri = substr($uri, 6);
		}

		//if the first char is a global context symbol, then return the full uri as an xri
		if (in_array($uri[0], array('=', '@', '+', '$', '!'))) {

			return array(
				'id'	=> $uri,
				'type'	=> 'xri'
			);

		}

		// Add http:// if needed
		if(strpos($uri, '://') === false){
			$uri = 'http://' . $uri;
		}

		$bits = parse_url($uri);

		//malformed uri, return false
		if(!$bits){
			return false;
		}

		$result = $bits['scheme'] . '://';

		$result .= preg_replace('/\.$/', '', $bits['host']);

		//add port if necessary
		if(
			isset($bits['port']) 
			AND 
			!empty($bits['port']) 
			AND 
			(
				($bits['scheme'] == 'http' AND $bits['port'] != '80') 
				OR 
				($bits['scheme'] == 'https' AND $bits['port'] != '443') 
				OR 
				($bits['scheme'] != 'http' AND $bits['scheme'] != 'https')
			)
		){
			$result .= ':' . $bits['port'];
		}

		//resolve path or trailing slashes
		if(isset($bits['path'])){

			do{
				$bits['path'] = preg_replace('#/([^/]*)/\.\./#', '/', str_replace('/./', '/', $old = $bits['path']));
			}while($old != $bits['path']);

			$result .= $bits['path'];

		}else{

			$result .= '/';

		}

		return array(
			'id'	=> $result,
			'type'	=> 'url'
		);

	}

}