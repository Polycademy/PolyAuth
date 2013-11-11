<?php

namespace PolyAuth\Authentication\AuthStrategies;

use Symfony\Component\HttpFoundation\Request;

abstract class AbstractStrategy{

	/**
	 * Returns the session manager which can be used as an array to manipulate the session data.
	 * @return ArrayObject
	 */
	public function get_session(){

		return $this->session_manager;

	}

	/**
	 * Establishes a Symfony request object. This augments the request object with the Authorization 
	 * header since it's not available by default.
	 * @return Object
	 */
	protected function get_request(){

		$request = Request::createFromGlobals();
		//php-fpm doesn't support getallheaders yet: https://bugs.php.net/bug.php?id=62596
		//however apache and fast-cgi does support getallheaders
		if(function_exists('getallheaders')){
			$headers = getallheaders();
			if(isset($headers['Authorization'])){
				$request->headers->set('Authorization', $headers['Authorization']);
			}
		}
		return $request;

	}

	/**
	 * Get the HTTPFoundation response object. PolyAuth is working with many authentication flows that each 
	 * have their own unique standards regarding how to respond to the client. However PolyAuth won't 
	 * automatically output these responses, to allow you the end developer some flexibility in the 
	 * implementation of your authentication. Therefore all possible responses are added into this response 
	 * object. This object can contain headers (cookies), body output and even redirects. There are 3 main 
	 * times you should check the response object and decide to output. First it's right after starting the 
	 * Authenticator (this includes both session start and autologin). Second is after you run 
	 * Authenticator::login, and third is after you run Authenticator::logout. Getting the response also 
	 * allows you format the response data. By default it will output any potential response body output as
	 * application/x-www-form-urlencoded.
	 * @param  String|Boolean $data_type Body output data type, can be 'xml' or 'json' or leave it as blank
	 * @return Response
	 */
	public function get_response($data_type = false){

		//this will take the response data and turn it into either form url encoded, json encoded or xml encoded
		//data type can be set manually, but if it isn't set, then it will check the accept header in the request
		//the default encoding is form url encoded
		if(!empty($this->response_data)){

			$data = '';

			if($data_type){

				$data = $this->set_response_data_and_type($this->response_data, $data_type);

			}else{

				$accepts = $this->request->getAcceptableContentTypes();

				foreach($accepts as $accept){
					if($accept == 'application/json'){
						$data = $this->set_response_data_and_type($this->response_data, 'json');
						break;
					}elseif($accept == 'application/xml' OR $accept == 'text/xml'){
						$data = $this->set_response_data_and_type($this->response_data, 'xml');
						break;
					}
				}

				if(empty($data)){
					$data = $this->set_response_data_type($this->response_data);
				}

			}

			//set the content
			$this->response->setContent($data);

		}

		//this will prepare the response with the correct parameters relative to the request
		return $this->response->prepare($this->request);

		/*
			Things you can do with the response object:
			http://api.symfony.com/2.3/Symfony/Component/HttpFoundation/Response.html
			You can continue using it as your response object. This object is returned by reference.
			So if you just call get_response() after session_start. And just keep using that returned object.
			You can:

			1. Keep using the object and add properties to it.
			2. Check if there are headers that need to be sent, if the headers do need to be sent, ->sendHeaders()
				(note that there are no headers sent by PolyAuth other than a: redirect headers, b: cookie headers).
			3. Check if there are cookies to be send using ->headers->getCookies(), then ->sendHeaders()
			4. Check if there is a redirect header using ->isRedirect() or ->isRedirection, then ->sendHeaders()
			5. Check if there is body output using ->getContent(), then ->sendContent()
			6. Extract all parameters and just respond in your own way. You can get all the headers from ->headers
			and all the content from ->getContent() and the status code from ->getStatusCode().

			Most importantly, make sure to buffer your output beforehand. Sending headers is fairly easy, you can
			overwrite headers even after you have ran ->sendHeaders(), even the status code! The header() replaces 
			by default, even the initial declaration. The http_ response_ code can replace the status code aswell.
			But after you send content, then you cannot do anything more.
		 */

	}

	/**
	 * Encodes the response data in either JSON, XML or form url encoded.
	 * The default is form url encoded. This also sets the Content-Type 
	 * headers on the response object.
	 * @param  Array  $data
	 * @param  String $type Can either be 'json', 'xml' or false
	 * @return String The formatted data
	 */
	protected set_response_data_and_type($data, $type = false){

		switch($type){
			case 'json':
				$data = json_encode($data);
				$this->response->headers->set('Content-Type', 'application/json');
			break;
			case: 'xml':
				$xml = new \SimpleXMLElement('<OAuth></OAuth>');
				$this->array_to_xml($data, $xml);
				$data = $xml->asXML();
				$this->response->headers->set('Content-Type', 'text/xml');
			break;
			default:
				$data = http_build_query($data);
				$this->response->headers->set('Content-Type', 'application/x-www-form-urlencoded');
		}

		return $data;

	}

	/**
	 * Converts a PHP array to XML. It takes a SimpleXMLElement object by reference
	 * and add properties to it.
	 * @param  Array            $data       Array of data
	 * @param  SimpleXMLElement $xml_object SimpleXMLElement object that is added nodes by reference
	 * @return SimpleXMLElement
	 */
	protected function array_to_xml(array $data, &$xml_object){

		foreach($data as $key => $value){

			if(is_array($value)){

				if(!is_numeric($key)){
					$subnode = $xml_object->addChild("$key");
					$this->array_to_xml($value, $subnode);
				}else{
					$subnode = $xml_object->addChild("item$key");
					$this->array_to_xml($value, $subnode);
				}

			}else{

				$xml_object->addChild("$key","$value");

			}

		}

	}

	/**
	 * Start_session will find the relevant session id/token and the transport method, and start
	 * the session tracking
	 */
	abstract public function start_session();

	/**
	 * Autologin method. Use this to determine how to log the user in automatically.
	 * Therefore it will need to extract identity and password in appropriate places, such as cookies or HTTP headers.
	 */
	abstract public function autologin();
	
	/**
	 * Login hook is called just before the manual login. This modifies the $data variable must return the $data variable.
	 * Modify the $data variable to fill it with ['identity'] AND ['password'] AND ['autologin'].
	 * Certain strategies may use login hook to create the random account on the fly such as Oauth or OpenId.
	 * PolyAuth will create any corresponding server session data.
	 */
	abstract public function login(array $data, $external = false);
	
	/**
	 * Destroy any client session data. PolyAuth will destroy the corresponding server session data.
	 */
	abstract public function logout();

	abstract public function challenge();

}