/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        April 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description Class for testing the OAuthJwtClientAuthentication Methods
 */
@IsTest
private with sharing class OAuthJwtClientCredentialsTest {
    
    /** **************************************************************************************************** **
     **                                      PRIVATE TEST DATA VARIABLE                                      **
     ** **************************************************************************************************** **/
    // Variables for holding test data
    private static OAuthJwtClientCredentials authProvider;
    private static Map<String,String> authProviderConfig; 


    /** **************************************************************************************************** **
     **                                             TEST METHODS                                             **
     ** **************************************************************************************************** **/
    /**
     * @description Method to test the initiate function
     */
    @IsTest
    static void testInitiate(){
        
        // Test the method
        Test.startTest();
        PageReference pageReference = getAuthProvider().initiate(getAuthProviderConfig(),'TestState');
        Test.stopTest();
        
        // Assert test results
        System.assertEquals(
            pageReference.getUrl(),
            URL.getSalesforceBaseUrl().toExternalForm() + '/services/authcallback/TestAuthProvider?state=TestState',
            'Unexpected callback URL'
        );
    }


    /**
     * @description Method to test the handleCallback() function
     */
    @IsTest
    static void testHandleCallback(){
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, new MockTokenResponse()); 

        // Test the method
        Test.startTest();
        Auth.AuthProviderTokenResponse tokenResponse = getTokenResponse();
        Test.stopTest();

        // Assert test results
        System.assertEquals('access_token_value', tokenResponse.oauthToken, 'Unexpected oauthToken value');
        System.assertEquals('TestState',          tokenResponse.state     , 'Unexpected state value');
    }


    /**
     * @description Method to test the refresh() function
     */
    @IsTest
    static void testRefresh(){
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, new MockTokenResponse()); 

        // Test the method
        Test.startTest();
        Auth.OAuthRefreshResult refreshResult = getAuthProvider().refresh(getAuthProviderConfig(),'[REFRESH_TOKEN]');
        Test.stopTest();

        // Assert test results
        System.assertEquals('access_token_value',    refreshResult.accessToken, 'Unexpected accessToken value');
    }


    /**
     * @description Method to test the getUserInfo() function
     */
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
        System.assertEquals('integration.user@example.com.invalid',    userData.email, 'Unexpected email value');
    }


    /**
     * @description Method to test the getCustomMetadataType() function
     */
    @IsTest
    static void testGetCustomMetadataType(){
        // Assert test results
        System.assertEquals(
            String.valueOf(OAuth_JWT_Client_Authentication__mdt.getSObjectType()),
            getAuthProvider().getCustomMetadataType(),
            'Unexpected custom metadata value'
        );
    }


    /**
     * @description Method to test the generateHttpRequest() function
     */
    @IsTest
    static void testGenerateHttpRequest(){
        
        // Test the http request is generated correcty
        Test.startTest();
        HttpRequest httpRequest = getAuthProvider().generateHttpRequest(getAuthProviderConfig(),'test=body');
        Test.stopTest();

        // Validate
        System.assertEquals('test=body&tenant=%5BTENANT%5D&client_id=%5BCLIENT_ID%5D', httpRequest.getBody(),'Unexpected request body');
        
        // Assert test results for custom headers
        System.assertEquals('[TEST_KEY]', httpRequest.getHeader('apiKey'),'Expected header "apiKey" does not exist');
        System.assertEquals('[API_ID]',   httpRequest.getHeader('apiId'), 'Expected header "apiId" does not exist');
        
        // assert result for the endpoint
        System.assertEquals(
            getAuthProviderConfig().get(OAuthJwtClientCredentials.TOKEN_ENDPOINT_FIELD_NAME),
            httpRequest.getEndpoint(),
            'Unexpected endpoint'
        );
    }


    /**
     * @description Method to test the validateJwsHeaderAlgorithm() function
     */
    @IsTest
    static void testValidateJwsHeaderAlgorithm(){
        // Happy path
        System.assertEquals('RS512', getAuthProvider().validateJwsHeaderAlgorithm('RS512'), 'Unexpected algorithm');

        // Exception path
        try {
            getAuthProvider().validateJwsHeaderAlgorithm('invalid');
        }catch(OAuthJwtClientCredentials.JwsException e){
            System.assertEquals(
                OAuthJwtClientCredentials.JWS_INVALID_HEAD_ALG_EXCEPTION_MSG,
                e.getMessage(),
                'Unexpected exception message'
            );
        }
    }


    /**
     * @description Method to test the validateJwsHeaderAlgorithm() function
     */
    @IsTest
    static void testValidateJwsSigningAlgorithm(){
        // Happy path
        System.assertEquals('RSA-SHA512', getAuthProvider().validateJwsSigningAlgorithm('RSA-SHA512'), 'Unexpected algorithm');

        // Exception path
        try {
            getAuthProvider().validateJwsSigningAlgorithm('invalid');
        }catch(OAuthJwtClientCredentials.JwsException e){
            System.assertEquals(
                OAuthJwtClientCredentials.JWS_INVALID_SIGN_ALG_EXCEPTION_MSG,
                e.getMessage(),
                'Unexpected exception message'
            );
        }
    }


    /**
     * @description Method to test the exceptions thrown in case there is no package installed
     */
    @IsTest
    static void testGetAuthProviderUtil(){
        try{
            OAuthJwtClientCredentials.getAuthProviderUtil();
        }catch(Exception e){
            try{
                OAuthJwtClientCredentials.handleException(e,getAuthProviderConfig());
            }catch(Exception se){
                System.assertEquals(
                    String.format(
                        OAuthJwtClientCredentials.GENERIC_EXCEPTION_MSG, 
                        new String[]{e.getTypeName(), e.getMessage()}
                    ),
                    se.getMessage(),
                    'Unexpected exception message'
                );
            }
        }
    }
    

    /** **************************************************************************************************** **
     **                                      PRIVATE TEST DATA METHODS                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Method that return a mock token response
     * @return      Mock token reponse
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
     * @description Method to create a Auth Provider (OAuthJwtClientCredentials) class instance that is
     *              used for testing
     * @return      Class representing the Auth Provider
     */
    private static OAuthJwtClientCredentials getAuthProvider(){
        if(authProvider == null){
            authProvider = new OAuthJwtClientCredentials();
        }
        return authProvider;
    }


    /**
     * @description Method to generate the Auth Provider Config data that is used for testing
     * @return      The auth provider configuration data map
     */
    private static Map<String,String> getAuthProviderConfig(){
        if(authProviderConfig == null){
            authProviderConfig=  new Map<String,String>{
                OAuthJwtClientCredentials.SCOPE_FIELD_NAME                  => 'web,api',
                OAuthJwtClientCredentials.TOKEN_ENDPOINT_FIELD_NAME         => 'https://localhost/oauth/token',
                OAuthJwtClientCredentials.TOKEN_HEADERS_FIELD_NAME          => 'apiKey : [TEST_KEY], apiId : [API_ID]',
                OAuthJwtClientCredentials.TOKEN_PARAMS_FIELD_NAME           => 'tenant : [TENANT], client_id : [CLIENT_ID]',
                OAuthJwtClientCredentials.JWT_ALGORITHM_FIELD_NAME          => 'RS512',
                OAuthJwtClientCredentials.JWT_KID_FIELD_NAME                => 'TEST-KEY-ID',
                OAuthJwtClientCredentials.JWT_SUBJECT_FIELD_NAME            => '[SUBJECT]',
                OAuthJwtClientCredentials.JWT_ISSUER_FIELD_NAME             => '[ISSUER]',
                OAuthJwtClientCredentials.JWT_AUDIENCE_FIELD_NAME           => '[AUDIENCE]',
                OAuthJwtClientCredentials.AUTH_PROVIDER_NAME_FIELD_NAME     => 'TestAuthProvider',
                OAuthJwtClientCredentials.JWS_SIGNING_CERT_FIELD_NAME       => 'certName',
                OAuthJwtClientCredentials.JWS_SIGNING_ALGORITHM_FIELD_NAME  => 'RSA-SHA512',
                OAuthJwtClientCredentials.ENABLE_PER_USER_MODE_FIELD_NAME   => 'false',
                OAuthJwtClientCredentials.ENABLE_ERROR_LOGGING_FIELD_NAME   => 'false',
                OAuthJwtClientCredentials.ENABLE_LOGIN_LOGGING_FIELD_NAME   => 'false'
                
            };
        }
        return authProviderConfig;
    }


    /** **************************************************************************************************** **
     **                                         PRIVATE MOCK CLASSES                                         **
     ** **************************************************************************************************** **/
    /**
     * @description Class for testing the OAuthJwtClientAuthentication Methods
     */
     private class MockTokenResponse implements HttpCalloutMock { 
        
        /**
         * @description Method to generate the mock token response
         * @param       httpRequest The HttpRequest object to add the header values to
         * @return      The mocked HttpResponse (Token)
         */
        public HttpResponse respond(HttpRequest httpRequest) { 
            
            OAuthJwtClientCredentials.TokenResponse tokenResponse = new OAuthJwtClientCredentials.TokenResponse();
            tokenResponse.access_token  = 'access_token_value';
            tokenResponse.token_type    = 'Bearer';
            tokenResponse.expires_in    = '1682439225';

            HttpResponse httpResponse = new HttpResponse();
            httpResponse.setStatusCode(200);
            httpResponse.setBody(JSON.serializePretty(tokenResponse));

            return httpResponse;
        }
    }
}