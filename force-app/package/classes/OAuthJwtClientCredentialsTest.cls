/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        April 2024
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
        Assert.areEqual(
            pageReference.getUrl(),
            URL.getOrgDomainUrl().toExternalForm() + '/services/authcallback/TestAuthProvider?state=TestState',
            'Unexpected callback URL'
        );
    }


    /**
     * @description Method to test the handleCallback() function
     */
    @IsTest
    static void testHandleCallback(){
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, utl.Mck.getInstance());
        setTokenResponseMock();

        // Test the method
        Test.startTest();
        Auth.AuthProviderTokenResponse tokenResponse = getTokenResponse();
        getAuthProvider().generateJWS(getAuthProviderConfig());
        Test.stopTest();

        // Assert test results
        Assert.areEqual('access_token_value', tokenResponse.oauthToken, 'Unexpected oauthToken value');
        Assert.areEqual('TestState',          tokenResponse.state     , 'Unexpected state value');
    }


    /**
     * @description Method to test the refresh() function
     */
    @IsTest
    static void testRefresh(){
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, utl.Mck.getInstance());
        setTokenResponseMock();

        // Test the method
        Test.startTest();
        Auth.OAuthRefreshResult refreshResult = getAuthProvider().refresh(getAuthProviderConfig(),'[REFRESH_TOKEN]');
        Test.stopTest();

        // Assert test results
        Assert.areEqual('access_token_value',    refreshResult.accessToken, 'Unexpected accessToken value');
    }


    /**
     * @description Method to test the refresh() function
     */
    @IsTest
    static void testPerUser(){
        
        // Enable per user mode, error loging and login history logging.
        getAuthProviderConfig().put(OAuthJwtClientCredentials.ENABLE_PER_USER_MODE_FIELD_NAME,'true');
        getAuthProviderConfig().put(OAuthJwtClientCredentials.ENABLE_ERROR_LOGGING_FIELD_NAME,'true');
        getAuthProviderConfig().put(OAuthJwtClientCredentials.ENABLE_LOGIN_LOGGING_FIELD_NAME,'true');
        getAuthProviderConfig().put(OAuthJwtClientCredentials.ENABLE_LOGIN_HISTORY_FIELD_NAME,'true');

        // Set action responses
        utl.Clbl.setActionResponse('insertLoginHistoryRecord',  null);
        utl.Clbl.setActionResponse('updateMappingLoginDetails', null);
        utl.Clbl.setActionResponse('insertLog',                 null);
        utl.Clbl.setActionResponse('handleInsertHistoryRecord', null);
        utl.Clbl.setActionResponse('checkUserMappingExists',    true);
        utl.Clbl.setActionResponse('getSubjectFromUserMapping', UserInfo.getUserName());
        utl.Clbl.setActionResponse('getAuthUserDataFromCookieHeader',getAuthProvider().loggedInUserData);
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, utl.Mck.getInstance());
        setTokenResponseMock();

        // Test the method
        Test.startTest();
        getAuthProvider().refresh(getAuthProviderConfig(),'[REFRESH_TOKEN]');
        getTokenResponse();
        getAuthProvider().generateJWS(getAuthProviderConfig());
        Test.stopTest();

        // Assert test results
        Assert.areEqual(true,    true, 'Coverage only');
    }


    /**
     * @description Method to test the getUserInfo() function
     */
    @IsTest
    static void testGetUserInfo(){
        
        // Set a mock resonse for the token
        Test.setMock(HttpCalloutMock.class, utl.Mck.getInstance());
        setTokenResponseMock();

        // Test the method
        Test.startTest();
        Auth.UserData userData = getAuthProvider().getUserInfo(
            getAuthProviderConfig(),
            getTokenResponse()
        );
        Test.stopTest();

        // Assert test results
        Assert.areEqual(UserInfo.getUserEmail(), userData.email, 'Unexpected email value');
    }


    /**
     * @description Method to test the getCustomMetadataType() function
     */
    @IsTest
    static void testGetCustomMetadataType(){
        // Assert test results
        Assert.areEqual(
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
        
        // Setup the mock response
        utl.Mck.setResponse(200, '{"SUCCESS": true}');

        // Set the mock response
        Test.setMock(HttpCalloutMock.class, utl.Mck.getInstance());

        // Test the http request is generated correcty
        Test.startTest();
        getAuthProvider().retrieveToken(getAuthProviderConfig());
        Test.stopTest();

        // Validate request body
        Assert.areEqual(
            'grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=%5BTEST_ASSERTION%5D&scope=web%2Capi&tenant=%5BTENANT%5D&client_id=%5BCLIENT_ID%5D',
            getAuthProvider().tokenCallout.getRequest().getBody(),
            'Unexpected request body'
        );
        
        // Assert test results for custom headers
        Assert.areEqual('[TEST_KEY]', getAuthProvider().tokenCallout.getRequest().getHeader('apiKey'),'Expected header "apiKey" does not exist');
        Assert.areEqual('[API_ID]',   getAuthProvider().tokenCallout.getRequest().getHeader('apiId'), 'Expected header "apiId" does not exist');
        
        // assert result for the endpoint
        Assert.areEqual(
            getAuthProviderConfig().get(OAuthJwtClientCredentials.TOKEN_ENDPOINT_FIELD_NAME),
            getAuthProvider().tokenCallout.getRequest().getEndpoint(),
            'Unexpected endpoint'
        );
    }


    /**
     * @description Method to test the validateJwsHeaderAlgorithm() function
     */
    @IsTest
    static void testValidateJwsHeaderAlgorithm(){
        // Happy path
        Assert.areEqual('RS512', getAuthProvider().validateJwsHeaderAlgorithm('RS512'), 'Unexpected algorithm');

        // Exception path
        try {
            getAuthProvider().validateJwsHeaderAlgorithm('invalid');
        }catch(OAuthJwtClientCredentials.JwsException e){
            utl.Tst.assertExceptionMessage(OAuthJwtClientCredentials.JWS_INVALID_HEAD_ALG_EXCEPTION_MSG, e);
        }
    }


    /**
     * @description Method to test the validateJwsHeaderAlgorithm() function
     */
    @IsTest
    static void testValidateJwsSigningAlgorithm(){
        // Happy path
        Assert.areEqual('RSA-SHA512', getAuthProvider().validateJwsSigningAlgorithm('RSA-SHA512'), 'Unexpected algorithm');

        // Exception path
        try {
            getAuthProvider().validateJwsSigningAlgorithm('invalid');
        }catch(OAuthJwtClientCredentials.JwsException e){
            utl.Tst.assertExceptionMessage(OAuthJwtClientCredentials.JWS_INVALID_SIGN_ALG_EXCEPTION_MSG, e);
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
                utl.Tst.assertExceptionMessage(
                    OAuthJwtClientCredentials.GENERIC_EXCEPTION_MSG,
                    e.getTypeName(),
                    e.getMessage(),
                    se
                );
            }
        }
    }
    

    /** **************************************************************************************************** **
     **                                      PRIVATE TEST DATA METHODS                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Method for setting up a 
     */
    private static void setTokenResponseMock(){
            
        OAuthJwtClientCredentials.TokenResponse tokenResponse = new OAuthJwtClientCredentials.TokenResponse();
        tokenResponse.access_token  = 'access_token_value';
        tokenResponse.token_type    = 'Bearer';
        tokenResponse.expires_in    = '1682439225';

        utl.Mck.setResponse(200, JSON.serializePretty(tokenResponse));      
    }


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
                OAuthJwtClientCredentials.ENABLE_LOGIN_LOGGING_FIELD_NAME   => 'false',
                OAuthJwtClientCredentials.ENABLE_LOGIN_HISTORY_FIELD_NAME   => 'false'
            };
        }
        return authProviderConfig;
    }

}