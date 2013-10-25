<?php

namespace PolyAuth\Authentication\AuthStrategies\Decorators;

use PolyAuth\Options;
use PolyAuth\Language;
use Purl\Url;
use Guzzle\Http\Client;
use Guzzle\Http\Exception\BadResponseException;
use Guzzle\Http\Exception\CurlException;
use QueryPath;

use PolyAuth\Exceptions\HttpExceptions\HttpOpenIdException;

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
	protected $xri_resolver;
	protected $purl;
	protected $client;
	protected $parser;

	public function __construct(
		$strategy, 
		Options $options, 
		Language $language,
		$xri_resolver = false, 
		Url $purl = null,
		Client $client = null,
		QueryPath $parser = null
	){

		$this->strategy = $strategy;
		$this->options = $options;
		$this->lang = $language;

		//add a trailing slash if it doesn't have one
		$this->xri_resolver = ($xri_resolver) ? rtrim($xri_resolver, '/') . '/' : 'https://xri.net/';

		$this->purl = ($purl) ? $purl : new Url;
		$this->client = ($client) ? $client : new Client;
		$this->client->setUserAgent('PolyAuth');
		$this->parser = ($parser) ? $parser : new QueryPath;

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

		$claimed_id = $this->normalize_uri($data['openid_identifier']);

		//id was malformed, so the login failed!
		if(!$claimed_id){
			return array(
				$data['openid_identifier'],
				$this->lang['login_unsuccessful'],
				false
			);
		}

		//use $claimed_id['uri'] as the actual open id identity

		$disovery_uri = $claimed_id['uri'];
		$type = $claimed_id['type'];

		//perform discovery on auth end point: xri or yadis or html discovery
		if($type == 'xri'){
			$discovery_uri = $this->resolve_xri_to_uri($discovery_uri);
			$xrds = $this->discover_xri($discovery_uri);
			$endpoint = $this->parse_xrds($xrds);
		}

		if($xrds = $this->discover_yadis($discovery_uri)){
			$endpoint = $this->parse_xrds($xrds);
		}else($html = $this->discover_html($discovery_uri)){
			$endpoint = $this->parse_html($html);
		}

		//xri failed, yadis failed, html failed - could not discover the end point
		if(!$endpoint){
			return false;
		}

		//add the extra parameters to the end point

	}

	protected function discover_xri($xri){

		try{

			$request = $this->client->get($xri);
			$response = $request->send();
		
		}catch(BadResponseException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}catch(CurlException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}

		return $response->xml();

	}

	protected function discover_yadis($uri){

		try{

			$request = $this->client->get($uri, array(
				'Accept'	=> 'application/xrds+xml'
			));
			$response = $request->send();
		
		}catch(BadResponseException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}catch(CurlException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}

		//if it led us directly to the xrds document, just return it as xml
		if(stripos($response->getContentType(), 'application/xrds+xml') !== false){
			return $response->xml();
		}

		//find the X-XRDS-Location header
		$headers = array_change_key_case($response->getHeaders(), CASE_LOWER);
		if(isset($headers['x-xrds-location'])){
			return $this->discover_yadis($headers['x-xrds-location']);
		}

		//find the meta tag in the head section
		//example: <meta http-equiv="X-XRDS-Location" content="http://example.com/yadis.xml">
		$body = $response->getBody(true);
		$body = current(explode('</head>', $body, 2));
		$meta_tags = $this->get_tags($body, 'meta', 'http-equiv', 'content');
		//get_tags will make sure the keys are lower case
		if(isset($meta_tags['x-xrds-location'])){
			return $this->discover_yadis($meta_tags['x-xrds-location']);
		}

		return false;

	}

	protected discover_html($uri){

		try{

			$request = $this->client->get($uri);
			$response = $request->send();
		
		}catch(BadResponseException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}catch(CurlException $e){

			throw new HttpOpenIdException($this->lang['openid_discovery']);

		}

		//we only need the head section
		$body = $response->getBody(true);
		$body = current(explode('</head>', $body, 2));

		return $body;

	}

	protected function parse_xrds(\SimpleXmlElement $xrds){

		//expects simple xml element!

	}

	protected function parse_html($html){

		$links = $this->get_tags($html, 'link', 'rel', 'href', true);

		//openid 2.0 and 1.1
		if(isset($links['openid2.provider'])){

			return $links['openid2.provider'];
		
		}elseif(isset($links['openid.server'])){

			return $links['openid.server'];

		}

		return false;

	}

	//this function can be used to get the meta tag links or the normal links
	protected function get_tags($data, $tag, $att1, $att2, $split = false){

		//this should look for:
		//<meta http-equiv="X-XRDS-Location" content="http://example.com/yadis.xml">
		//OR
		//<link rel="openid2.provider openid.server" href="http://www.livejournal.com/openid/server.bml"/>
		//<link rel="openid2.local_id openid.delegate" href="http://exampleuser.livejournal.com/"/>
		//Note that the rel="" may include either the openid2.provider or just openid.server or both
		//The 2 is for OpenID2 and the openid.server is for 1.1
		//Always prefer the 2.0 version over the 1.1 version
		//this should be converted to using QueryPath, mainly because the XRDS parsing can also use QueryPath

		preg_match_all('#<' . $tag . '\s*(.*?)\s*/?' . '>#is', $data, $matches);

		$links = array();

		foreach ($matches[1] as $link) {

			$rel = $href = null;

			if(preg_match('#' . $att1 . '\s*=\s*(?:([^"\'>\s]*)|"([^">]*)"|\'([^\'>]*)\')(?:\s|$)#is', $link, $m)){
				array_shift($m);
				$rel = implode('', $m);
			}

			if(preg_match('#' . $att2 . '\s*=\s*(?:([^"\'>\s]*)|"([^">]*)"|\'([^\'>]*)\')(?:\s|$)#is', $link, $m)){
				array_shift($m);
				$href = implode('', $m);
			}

			if($split){

				foreach (explode(' ', strtolower($rel)) as $part) {
					$links[$part] = html_entity_decode($href);
				}

			}else{

				$links[strtolower($rel)] = html_entity_decode($href);

			}

		}

		return $links;

	}

	/**
	 * Parse the claimed identity uri. This will ignore any usernames, passwords or query parameters in the uri.
	 * That's to prevent different identity uris that point to the same identity. This works for xris as well.
	 * Code is taken and modified from Poidsy: http://apps.md87.co.uk/openid/
	 * If the uri is malformed, then it returns false.
	 */
	protected function normalize_uri($uri){

		//first remove the xri:// scheme if it exists
		if(substr($uri, 0, 6) == 'xri://'){
			$uri = substr($uri, 6);
		}

		//xri parsing, xris could also be passed without the xri:// scheme
		if(in_array($uri[0], array('=', '@', '+', '$', '!'))){

			return array(
				'uri'	=> $uri,
				'type'	=> 'xri'
			);

		}

		//parse normal http urls
		$uri = $this->purl::parse($uri);
		if(!$uri->getData()){
			return false;
		}

		//add http:// if needed
		if(!$uri->scheme){
			$uri->scheme = 'http';
		}

		return array(
			'uri'	=> $uri->getUrl(),
			'type'	=> 'url'
		);

	}

	protected function resolve_xri_to_uri($xri){

		//add the proxy resolver
		$uri = $this->xri_resolver . $xri;

		$uri = $this->purl::parse($uri);
		if(!$uri->getData()){
			return false;
		}

		//add the xrds query parameter to get the xrds document for discovery
		$uri->query->set('_xrd_r', 'application/xrds+xml');

		return $uri->getUrl();

	}

}