/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        April 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description Test class for the OAuthJwtClientAuthentication class methods
 */
@IsTest
private with sharing class OAuthJwtClientAuthenticationTest {
	
	/** **************************************************************************************************** **
	 **                                      PRIVATE TEST DATA VARIABLE                                      **
	 ** **************************************************************************************************** **/
	// Variables for holding test data
	private static OAuthJwtClientAuthentication authProvider;
	private static Map<String,String> authProviderConfig;


	/** **************************************************************************************************** **
	 **                                             TEST METHODS                                             **
	 ** **************************************************************************************************** **/
	@IsTest
	static void testInitiate(){
		
		// Test the method
		Test.startTest();
		PageReference pageReference = getAuthProvider().initiate(getAuthProviderConfig(),'TestState');
		Test.stopTest();
		
		// Assert test results
		System.assertEquals(
			pageReference.getUrl(),
			URL.getSalesforceBaseUrl().toExternalForm() + '/services/authcallback/TestAuthProvider?code=NoCodeRequiredButMandatory&state=TestState',
			'Unexpected callback URL'
		);
	}

	@IsTest
	static void testHandleCallback(){
		
		// Set a mock resonse for the token
		Test.setMock(HttpCalloutMock.class, new MockTokenResponse()); 

		// Test the method
		Test.startTest();
		Auth.AuthProviderTokenResponse tokenResponse = getTokenResponse();
		Test.stopTest();

		// Assert test results
		System.assertEquals('access_token_value',	tokenResponse.oauthToken, 'Unexpected oauthToken value');
		System.assertEquals('TestState',			tokenResponse.state		, 'Unexpected state value');
	}


	@IsTest
	static void testRefresh(){
		
		// Set a mock resonse for the token
		Test.setMock(HttpCalloutMock.class, new MockTokenResponse()); 

		// Test the method
		Test.startTest();
		Auth.OAuthRefreshResult refreshResult = getAuthProvider().refresh(getAuthProviderConfig(),'[REFRESH_TOKEN]');
		Test.stopTest();

		// Assert test results
		System.assertEquals('access_token_value',	refreshResult.accessToken, 'Unexpected accessToken value');
	}


	@IsTest
	static void testGetUserInfo(){
		
		// Set a mock resonse for the token
		Test.setMock(HttpCalloutMock.class, new MockTokenResponse());

		// Test the method
		Test.startTest();
		Auth.UserData userData = getAuthProvider().getUserInfo(
			getAuthProviderConfig(),
			getTokenResponse()
		);
		Test.stopTest();

		// Assert test results
		System.assertEquals('integration.user@example.com.invalid',	userData.email, 'Unexpected email value');
	}


	/** **************************************************************************************************** **
	 **                                      PRIVATE TEST DATA METHODS                                       **
	 ** **************************************************************************************************** **/
	/**
	 * Method to get a token response object
	 */
	private static Auth.AuthProviderTokenResponse getTokenResponse(){
		return getAuthProvider().handleCallback(
			getAuthProviderConfig(),
			new Auth.AuthProviderCallbackState(
				null,
				null,
				new Map<String,String>{
					'code' => 'NoCodeRequiredButMandatory',
					'state'=> 'TestState'
				}
			)
		);
	}


	/**
	 * Method to get a dummy auth provider
	 */
	private static OAuthJwtClientAuthentication getAuthProvider(){
		if(authProvider == null){
			authProvider = new OAuthJwtClientAuthentication();
		}
		return authProvider;
	}


	/**
	 * Method to generate the dummy configuration data
	 */
	private static Map<String,String> getAuthProviderConfig(){
		if(authProviderConfig == null){
			authProviderConfig=  new Map<String,String>{
				getAuthProvider().GRANT_TYPE_FIELD_NAME				=> 'client_credentials',
				getAuthProvider().TOKEN_ENDPOINT_FIELD_NAME			=> 'https://localhost/oauth/token',
				getAuthProvider().TOKEN_HEADERS_FIELD_NAME			=> 'apiKey : [TEST_KEY]',
				getAuthProvider().JWT_ALGORITHM_FIELD_NAME			=> 'RS512',
				getAuthProvider().JWT_TYPE_FIELD_NAME				=> 'JWT',
				getAuthProvider().JWT_KID_FIELD_NAME				=> 'TEST-KEY-ID',
				getAuthProvider().JWT_SUBJECT_FIELD_NAME			=> '[SUBJECT]',
				getAuthProvider().JWT_ISSUER_FIELD_NAME				=> '[ISSUER]',
				getAuthProvider().JWT_AUDIENCE_FIELD_NAME			=> '[AUDIENCE]',
				getAuthProvider().AUTH_PROVIDER_NAME_FIELD_NAME		=> 'TestAuthProvider',
				getAuthProvider().JWS_SIGNING_CERT_FIELD_NAME		=> 'certName',
				getAuthProvider().JWS_SIGNING_ALGORITHM_FIELD_NAME	=> 'RSA-SHA512'
			};
		}
		return authProviderConfig;
	}


	/** **************************************************************************************************** **
	 **                                         PRIVATE MOCK CLASSES                                         **
	 ** **************************************************************************************************** **/
	private class MockTokenResponse implements HttpCalloutMock { 
		public HttpResponse respond(HTTPRequest req) { 
			
			OAuthJwtClientAuthentication.TokenResponse tokenResponse = new OAuthJwtClientAuthentication.TokenResponse();
			tokenResponse.access_token 	= 'access_token_value';
			tokenResponse.token_type	= 'Bearer';
			tokenResponse.expires_in	= '1682439225';

			HttpResponse httpResponse = new HttpResponse();
			httpResponse.setStatusCode(200);
			httpResponse.setBody(JSON.serializePretty(tokenResponse));

			return httpResponse;
		}
	}
}