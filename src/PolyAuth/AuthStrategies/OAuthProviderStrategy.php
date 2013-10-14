<?php

//THIS DOES BOTH:

//1. Authorization Code Grant 
//2. Resource Owner Password Credentials Grant

/**
 * Basically it receives a authentication request.
 * Request passes credentials.
 * The credentials can either be of 2 things:
 * 1. Auth Code Grant => Client Credentials + Resource Owner Credentials (third party)
 * 2. Resource Owner Password Credentials => Resource Owner Credentials (trusted application) and/or Client Credentials
 * For 1. it returns an Auth Code and Redirects!
 * For 2. it returns the Access Token.
 * For 1., the client needs to resend a request with the Auth Code and Redirection and Exchange it for Access Token.
 * Once client has access token, all API requests needs to have an access token to be valid!
 *
 * So there's a branching part here:
 * First detect if access token exists, if it exists and is valid, pass through.
 * Then detect if a refresh token exists, if it exists and is valid, return a new access token. (Also this may check for client credentials if necessary).
 * The client credentials may be registered against a list of clients.
 * If it's an auth request, check for the grant_type. If Auth Code Grant, check client credentials.
 *
 * Regardless of whether it's 3 legged or 2 legged. The clients should still be registered against the server!
 * That way the client is always authenticated on every request!
 */

//THESE ARE THE THINGS THAT WOULD INDICATE OAUTH2 request:
//1. Authorization: OAuth ##### -> NOT STANDARD!
//2. Authorization: Bearer #### -> STANDARD
//3. ?access_token=####
//4. Authorization: Mac ... blah blah (support MAC later...) 
//5. Post body is also possible, but that's a stupid way of doing things!

//http://tools.ietf.org/html/rfc6750#section-2.3

//Also session ids are the access tokens.