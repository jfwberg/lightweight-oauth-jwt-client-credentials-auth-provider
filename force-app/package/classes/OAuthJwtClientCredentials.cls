/**
 * @author         Justus van den Berg (jfwberg@gmail.com)
 * @date           April 2023
 * @copyright      (c) 2023 Justus van den Berg
 * @license        MIT (See LICENSE file in the project root)
 * @description    OAuth 2.0 JWT Client Authentication Auth Provider for the use with Client Credentials
 *                 Follows the standard as described in rfc7523Section 2.2
 *                 (https://datatracker.ietf.org/doc/html/rfc7523#section-2.2)
 * @note           In order to use the (error) logging functions and to enabled "Per User" mode for
 *                 user context mappings, It is required that the "Lightweight - Auth Provider Util
 *                 v2" (04t4K000002Jv1tQAC) package is installed.
 * @change         Implemented the following new functions:
 *                 - Optional parameters, azure requires ?client_id=[client_id]&tentant=abcede
 *                 - Error logging
 *                 - Per user principal as well as Named Principal
 *                 - User login logging, to keep track of what users have requested tokens
 * @false-positive PMD.CyclomaticComplexity The Cyclomatic Complexity in this class is quite high.
 *                                          The methods themselves are OK.
 *                                          It's due to the fact that I want al the logic in a
 *                                          single class, as an AuthProvider the class has a single
 *                                          function and is used in a single place.
 *                                          It can be split up, but this keeps it nicely together
 *                                          and the class just under 800 lines what is acceptable
 *                                          imho.
 */
@SuppressWarnings('PMD.CyclomaticComplexity')
public with sharing class OAuthJwtClientCredentials extends Auth.AuthProviderPluginClass{

    /** **************************************************************************************************** **
     **                                          PRIVATE VARIABLES                                           **
     ** **************************************************************************************************** **/
    // For debugging purposes extract the callout data
    private utl.Rst tokenCallout;

    // The optional auth provider util for error logging and per user principal (requires the "Lightweight - Auth Provider Util v2" package)
    // If you dont want this depencency, disable the options "Enable Error Logging", "Enabled Per user principal" and "Enabled Per User Login Logging" in the Custom Auth Provider Setup.
    private static Callable authProviderUtil;

    // The details of the logged in user
    @TestVisible private String        loggedInUserId   = UserInfo.getUserId();
    @TestVisible private Auth.UserData loggedInUserData = new Auth.UserData(
        UserInfo.getUserId(),    // User Id
        UserInfo.getFirstName(), // First Name
        UserInfo.getLastName(),  // Last Name
        UserInfo.getFirstName() + ' ' +  UserInfo.getLastName(), // Full Name (user name here)
        UserInfo.getUserEmail(), // Email Address
        null,                    // Link
        UserInfo.getUserName(),  // Username
        UserInfo.getLocale(),    // Locale
        null,                    // Provider
        null,                    // Site login
        null                     // Attribute map
    );


    /** **************************************************************************************************** **
     **                                          PRIVATE CONSTANTS                                           **
     ** **************************************************************************************************** **/
    // Grant details
    @TestVisible private final static String SCOPE_FIELD_NAME          = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Scope__c);
    @TestVisible private final static String TOKEN_ENDPOINT_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Token_Endpoint_URL__c);
    @TestVisible private final static String TOKEN_HEADERS_FIELD_NAME  = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Additional_Token_Endpoint_Headers__c);
    @TestVisible private final static String TOKEN_PARAMS_FIELD_NAME   = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Additional_Token_Endpoint_Parameters__c);
    @TestVisible private final static String CUSTOM_CALLBACK_FIELD_NAME= String.valueOf(OAuth_JWT_Client_Authentication__mdt.Custom_Callback_URL__c);

    // JWT Header info
    @TestVisible private final static String JWT_ALGORITHM_FIELD_NAME  = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Algorithm__c);
    @TestVisible private final static String JWT_KID_FIELD_NAME        = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Kid__c);

    // JWT Settings
    @TestVisible private final static String JWT_SUBJECT_FIELD_NAME    = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Subject__c);
    @TestVisible private final static String JWT_ISSUER_FIELD_NAME     = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Issuer__c);
    @TestVisible private final static String JWT_AUDIENCE_FIELD_NAME   = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Audience__c);
    
    // Specify the name for your auth provider for the callback URL
    @TestVisible private final static String AUTH_PROVIDER_NAME_FIELD_NAME    = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Auth_Provider_Name__c);

    // The API name of the certificate and the algorithm used for signing the JWT
    @TestVisible private final static String JWS_SIGNING_CERT_FIELD_NAME      = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Signing_Certificate_Name__c);
    @TestVisible private final static String JWS_SIGNING_ALGORITHM_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Signing_Algorithm__c);
    
    // Setup switches
    @TestVisible private final static String ENABLE_PER_USER_MODE_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Enable_Per_User_Mode__c);
    @TestVisible private final static String ENABLE_ERROR_LOGGING_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Enable_Error_Logging__c);
    @TestVisible private final static String ENABLE_LOGIN_LOGGING_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Enable_Per_User_Login_Logging__c);

    // This will generate the GUID that is used to identify this specific transaction so it can be followed through the logs
    @TestVisible private final static String GUID = UUID.randomUUID().toString();

    // Parameter names
    @TestVisible private final static String PARAM_NAME_STATE = 'state';
    
    // Test Cookie header
    @TestVisible private final static String TEST_COOKIE_HEADER = 'sid=[SESSION_ID];';

    // Valid algorithm for JKS Header and JWT Signing Certificate for validating the user inputs based on availible SFDC functionality
    @TestVisible private final static Set<String> VALID_JWS_HEADER_ALGORITHMS  = new Set<String>{'RS256','RS384','RS512','ES256','ES384','ES512'};
    @TestVisible private final static Set<String> VALID_JWS_SIGNING_ALGORITHMS = new Set<String>{'RSA-SHA256','RSA-SHA384','RSA-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512'};
    
    // Any messages go here
    @TestVisible private final static String GENERIC_EXCEPTION_MSG             = 'A {0} was thrown with the message: {1}';
    @TestVisible private final static String NO_USER_MAPPING_MSG               = 'Nu User Mapping Record was found for Auth Proivder "{0}" with user "{1}"';    
    @TestVisible private final static String MISSING_UTIL_PACKAGE_MSG          = 'Issue whilst instantiating the AuthProviderUtil class. Make sure the "Lightweight - Auth Provider Util v2" package is installed. Alternatively, DISABLE the options "Enable Error Logging", "Enable Per user principal" and "Enable Per User Login Logging" in the Custom Auth Provider Setup.';
    @TestVisible private final static String INVALID_TOKEN_RESPONSE_MSG        = 'Unexpected response when calling the token endpoint: {0}';
    @TestVisible private final static String JWS_INVALID_HEAD_ALG_EXCEPTION_MSG= 'Invalid JWS Header Algorithm provided. Valid values are: \'RS256\',\'RS384\',\'RS512\',\'ES256\',\'ES384\' and \'ES512\'';
    @TestVisible private final static String JWS_INVALID_SIGN_ALG_EXCEPTION_MSG= 'Invalid JWS Signing Algorithm provided. Valid values are: \'RSA-SHA256\',\'RSA-SHA384\',\'RSA-SHA512\',\'ECDSA-SHA256\',\'ECDSA-SHA384\',\'ECDSA-SHA512\'';
    

    /** **************************************************************************************************** **
     **                                       PUBLIC INTERFACE METHODS                                       **
     ** **************************************************************************************************** **/
    /**
     * @description     Returns the URL where the user is redirected for authentication.
     * @param           authProviderConfiguration The configuration items for the custom authentication
     *                                            provider that have been configured in the custom
     *                                            metadata type.
     * @param           stateToPropagate          The state passed in to initiate the authentication
     *                                            request for the user
     * @return          The URL of the page where the user is redirected for authentication.
     * @false-positives The URL is generated at a known source and no danger. It's not user updateable.
     *                  Also the remote site settings will prevent any unauthorised endpoint call-outs
     */
    @SuppressWarnings('PMD.ApexOpenRedirect')
    public PageReference initiate(Map<String,String> authProviderConfiguration, String stateToPropagate){ 

        // Get the standard auth provider endpoint url
        PageReference pageReference = this.getSfdcCallbackURL(authProviderConfiguration);
        
        // Add the state parameter
        pageReference.getParameters().put(PARAM_NAME_STATE, stateToPropagate);

        // Return the pageReference
        return pageReference;
    }


    /**
     * @description Uses the authentication provider’s supported authentication protocol to return an
     *              OAuth access token, OAuth secret or refresh token, and the state passed in when the
     *              request for the current user was initiated.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       callbackState             The class that contains the HTTP headers, body, and
     *                                        queryParams of the authentication request.
     * @return      Creates an instance of the AuthProviderTokenResponse class
     * @note        There is no refresh token in the OAUth 2.0 JWT Client Authentication flow so we
     *              just ignore this value or put in a random, invalid value.
     */
    public Auth.AuthProviderTokenResponse handleCallback(Map<String,String> authProviderConfiguration, Auth.AuthProviderCallbackState callbackState){
       try{
            // Check if the "per user" principal is enabled and if so set the logged in user Id
            if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_PER_USER_MODE_FIELD_NAME))){
                this.setLoggedInUserDetails(callbackState);
            }

            // Retrieve a new token from the token endpoint
            TokenResponse tokenResponse = this.retrieveToken(authProviderConfiguration);

            // Manage the login history
            this.handleInsertHistoryRecord(
                authProviderConfiguration,
                'Initial',
                String.isNotBlank(tokenResponse.access_token),
                'JWT_CLIENT_CREDENTIALS',
                this.tokenCallout
            );

            // Check if the per user principal is enabled, if so update the log entry for that user mapping
            if( Boolean.valueOf(authProviderConfiguration.get(ENABLE_PER_USER_MODE_FIELD_NAME)) &&
                Boolean.valueOf(authProviderConfiguration.get(ENABLE_LOGIN_LOGGING_FIELD_NAME))){
                
                // Update the mapping record    
                getAuthProviderUtil().call('updateMappingLoginDetails', new Map<String, Object> { 
                    'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                    'userId'           => loggedInUserId
                });
            }

            // Error with the token, purposely thrown here to manage proper error logging
            if(String.isBlank(tokenResponse.access_token)){
                throw new TokenException(String.format(INVALID_TOKEN_RESPONSE_MSG, new String[]{tokenCallout.getResponse().getBody()}));
            }


            // Return the the token response, there is no refresh token so we just set a random value
            return new Auth.AuthProviderTokenResponse(
                authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                tokenResponse.access_token,
                loggedInUserId,
                callbackState.queryParameters.get(PARAM_NAME_STATE)
            ); 
        }catch(Exception e){
            handleException(e, authProviderConfiguration);
        }

        // Unreachable statement to please the apex compiler
        return null;
    }


    /**
     * @description Returns a new access token, which is used to update an expired access token.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       refreshToken              The refresh token for the user who is logged in.
     * @return      Returns the new access token, or an error message if an error occurs.
     * @note        There is no refresh token in the OAUth 2.0 JWT Client Authentication flow so we
     *              just ignore this value or put in a random, invalid value.
     */
    public override Auth.OAuthRefreshResult refresh(Map<String,String> authProviderConfiguration, String refreshToken){
        try{
            // Check if the "per user" principal is enabled and if so set the logged in user Id
            // This way the correct user is
            if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_PER_USER_MODE_FIELD_NAME))){
                loggedInUserId = refreshToken;
            }

            // Retrieve a new token from the token endpoint
            TokenResponse tokenResponse = this.retrieveToken(authProviderConfiguration);
            
            // Manage the login history
            this.handleInsertHistoryRecord(
                authProviderConfiguration,
                'Refresh',
                String.isNotBlank(tokenResponse.access_token),
                'JWT_CLIENT_CREDENTIALS',
                this.tokenCallout
            );
            
            // Check if the per user principal is enabled, if so update the log entry for that user mapping
            if( Boolean.valueOf(authProviderConfiguration.get(ENABLE_PER_USER_MODE_FIELD_NAME)) &&
                Boolean.valueOf(authProviderConfiguration.get(ENABLE_LOGIN_LOGGING_FIELD_NAME))){
                
                // Update the mapping record    
                getAuthProviderUtil().call('updateMappingLoginDetails', new Map<String, Object> { 
                    'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                    'userId'           => loggedInUserId
                });
            }

            // Error with the token, purposely thrown here to manage proper error logging
            if(String.isBlank(tokenResponse.access_token)){
                throw new TokenException(String.format(INVALID_TOKEN_RESPONSE_MSG, new String[]{this.tokenCallout.getResponse().getBody()}));
            }

            // Return the (refresh) token response
            return new Auth.OAuthRefreshResult(
                tokenResponse.access_token,
                refreshToken
            );
        }catch(Exception e){
            handleException(e, authProviderConfiguration);
        }

        // Unreachable statement to please the apex compiler
        return null;
    }


    /**
     * @description Returns information from the custom authentication provider about the current user.
     *              This information is used by the registration handler and in other authentication
     *              provider flows.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       response                  The OAuth access token, OAuth secret or refresh token,
     *                                        and state provided by the authentication provider to
     *                                        authenticate the current user.
     * @return      Creates a new instance of the Auth.UserData class.
     * @note        User data is not being used in the OAUth 2.0 JWT Client Authentication flow as it
     *              is a system to system integration. As some basic required info I put in an
     *              integration user.
     */
    public Auth.UserData getUserInfo(Map<string,string> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        return this.loggedInUserData;
    }


    /**
     * @description Returns the custom metadata type API name for a custom OAuth-based authentication
     *              provider for single sign-on to Salesforce.
     * @return      The custom metadata type API name for the authentication provider.
     */
    public String getCustomMetadataType() {
        return String.valueOf(OAuth_JWT_Client_Authentication__mdt.getSObjectType());
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE SUPPORT METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description     Method to Generate the standard Salesforce Auth Provider callback URL for the
     *                  specific Auth Provider Name.
     * @param           authProviderConfiguration The configuration items for the custom authentication
     *                                            provider that have been configured in the custom
     *                                            metadata type.
     * @return          The Auth Provider's callback URL
     * @false-positives The URL is generated at a known source and no danger. It's not user updateable.
     *                  Also the remote site settings will prevent any unauthorised endpoint call-outs
     */
    @SuppressWarnings('PMD.ApexOpenRedirect')
    private PageReference getSfdcCallbackURL(Map<String,String> authProviderConfiguration){
        
        // If you have  custom callback URL specified, return the custom callback URL
        if(String.isNotBlank(authProviderConfiguration.get(CUSTOM_CALLBACK_FIELD_NAME)?.trim())){
            return new PageReference(authProviderConfiguration.get(CUSTOM_CALLBACK_FIELD_NAME)?.trim());
        }
        
        // By default generate the Standard Salesforce Callback URL for the Auth Provider
        return new PageReference(
            URL.getOrgDomainUrl().toExternalForm() + '/services/authcallback/' + authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim()
        );
    }


    /**
     * @description Method to parse the token response JSON into a TokenResponse Object
     * @param       tokenResponseJSON The JSON response returned from the Authorisation Server
     * @return      A TokenResponse Object
     */
    private TokenResponse parseTokenResponse(String tokenResponseJSON){
        return (TokenResponse) JSON.deserialize(tokenResponseJSON, TokenResponse.class);
    }




    /**
     * @description Method that generates the JWT, JWS and HTTP Request to retrieve an access token
     *              from the configured token endpoint.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @return      A TokenResponse with the access token
     * @throws      TokenException            There is an error in parsing the token response
     */
    private TokenResponse retrieveToken(Map<String,String> authProviderConfiguration){
        
        // Call SF token endpoint
        this.tokenCallout = new utl.Rst();

        // Generate the full body string as a URL query parameter
        Map<String,String> bodyParameters = new Map<String,String>{
            'grant_type'            => 'client_credentials',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion'      => this.generateJWS(authProviderConfiguration),
            'scope'                 => authProviderConfiguration.get(SCOPE_FIELD_NAME)?.trim()
        };
        
        // Add optional custom headers to the token request (i.e. things like API keys,  X-Correlation-Id etc.)
        this.addStringHeadersToRequest(
            authProviderConfiguration.get(TOKEN_HEADERS_FIELD_NAME)?.trim(),
            this.tokenCallout
        );

        // Add optional custom parameters to the token request (i.e. things client_id , tentant etc.)
        this.addStringParametersToRequest(
            authProviderConfiguration.get(TOKEN_PARAMS_FIELD_NAME)?.trim(),
            bodyParameters
        );

        // Configure and call the endpoint
        this.tokenCallout.setEndpoint(authProviderConfiguration.get(MY_DOMAIN_FIELD_NAME) + '/services/oauth2/token');
        this.tokenCallout.setContentTypeHeaderToFormUrlEncoded(bodyParameters);
        this.tokenCallout.call();
        
        // Parse the response into a token response
        return this.parseTokenResponse(this.tokenCallout.getResponse().getBody());
    }


    /**
     * @description Method to generate a JWT and JWS Compact Serialization
     *              This is in a custom method because the Salesforce Auth.JWS Class does not allow you
     *              to change to any other algorithms than SHA256 (unless I missed something
     *              somewhere...)
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @return      JWS Compact Serialized, generated from the configuration
     */
    private String generateJWS(Map<String,String> authProviderConfiguration){
        
        // Create the JWK header
        String header = JSON.serialize(new Map<String,String>{
            'alg' => this.validateJwsHeaderAlgorithm(authProviderConfiguration.get(JWT_ALGORITHM_FIELD_NAME)?.trim()),
            'typ' => 'JWT',
            'kid' => authProviderConfiguration.get(JWT_KID_FIELD_NAME)?.trim()
        });

        // Create the JWT payload
        String payload = JSON.serialize(new Map<String,Object>{
            'iss' => authProviderConfiguration.get(JWT_ISSUER_FIELD_NAME)?.trim(),
            'aud' => authProviderConfiguration.get(JWT_AUDIENCE_FIELD_NAME)?.trim(),
            'sub' => getSubject(authProviderConfiguration),
            'exp' => (DateTime.now().addSeconds(300).getTime() / 1000),
            'jti' => GUID
        });        
        
        // Encode and combine the header and body for signing
        String b64UrlEncodedHeaderAndPayload = String.format('{0}.{1}',
            new String[]{
                base64UrlEncode(Blob.valueOf(header )),
                base64UrlEncode(Blob.valueOf(payload))
            }
        );

        // Generate the signature
        String b64UrlEncodedSignature = (!Test.isRunningTest()) ? this.base64UrlEncode(
            Crypto.signWithCertificate(
                this.validateJwsSigningAlgorithm(authProviderConfiguration.get(JWS_SIGNING_ALGORITHM_FIELD_NAME)?.trim()),
                Blob.valueOf(b64UrlEncodedHeaderAndPayload),
                authProviderConfiguration.get(JWS_SIGNING_CERT_FIELD_NAME)?.trim()
            )
        ) : '[TEST_CLASS_VALUE_BECAUSE_THERE_IS_NO_MOCK_CERT_OPTION]';

        // Create and return the JWT in a signed and compact serialization
        return String.format('{0}.{1}', new String[]{
            b64UrlEncodedHeaderAndPayload,
            b64UrlEncodedSignature
        });
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE UTILITY METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description Method for encoding a Blob into a Base64 URL encoded String.
     *              This is required for generating the JWS
     * @param       input The input Blob to convert to a Base64Url Encoded String
     * @return      Base64 Url Encoded String
     */
    private String base64UrlEncode(Blob input){
        return EncodingUtil.base64Encode(input).replace('+', '-').replace('/', '_');
    }


    /**
     * @description Methods to add headers from a comma separated key/value pair string to an HttpRequest Object.
     *              Example: "apiKey : apiValue, sysId : sysValue" wil add two header values.
     *              This is required in order to add additional headers to the token response from
     *              custom metadata in the auth provider. Only text fields are supported. Not long text
     *              fields. This is a simple fix.
     * @param       headerValue The comma separated key/value pairs of headers to add
     * @param       httpRequest The HttpRequest object to add the header values to
     */
    private void addStringHeadersToRequest(String headerValue, utl.Rst callout){
        
        // Validate the header has a value
        if(String.isBlank(headerValue)){
            return;
        }

        // Each header should be split by a comma, due to fact multi line is not supported
        for(String line : headerValue.split(',')){
            
            // Check the line contains a colon but still has a value after the colon
            if(line.contains(':')){
                
                // Split the value in key value pair
                String[] keyValueList = line.split(':');
                
                // Validate the header is correct and has a 
                if(keyValueList.size() == 2){
                    callout.addHeader(keyValueList[0]?.trim(), keyValueList[1]?.trim());
                }
            }
        }
    }


    /**
     * @description Method to add additional URL encoded POST Body values to the body. Will take the
     *              base string followed by an ampersand and the value of the parameters.
     *              Parameter format is a colon separated key value pair. For multiple values split the
     *              key value pairs with a comma
     * @param       parameterValue The comma separated key/value pairs of parameters to add. i.e.
     *                             client_id : [CLIENT_ID], tenant : abcde
     * @param       httpRequest    The HttpRequest object to add the parameter values to
     */
    private void addStringParametersToRequest(String parameterValue, Map<String,String> parameterMap){
        
        // Validate the parameter has a value
        if(String.isBlank(parameterValue)){
            return;
        }

        // Each header should be split by a comma, due to fact multi line is not supported
        for(String line : parameterValue.split(',')){
            
            // Check the line contains a colon but still has a value after the colon
            if(line.contains(':')){
                // Split the value in key value pair
                String[] keyValueList = line.split(':');
                
                // Validate the header is correct and has a 
                if(keyValueList.size() == 2){
                    parameterMap.put(keyValueList[0]?.trim(), keyValueList[1]?.trim());
                }
            }
        }
    }


    /**
     * @description Method to validate an Apex Supported JWS Header Algorithm
     * @param       algorithm    The name of the algorithm to validate
     * @return      Name of the input algorithm if validated
     * @throws      JwsException The algorithm is invalid
     */
    @TestVisible
    private String validateJwsHeaderAlgorithm(String algorithm){
        if(String.isNotBlank(algorithm)){
            if(VALID_JWS_HEADER_ALGORITHMS.contains(algorithm?.trim())){
                return algorithm;
            }
        }
        throw new JwsException(JWS_INVALID_HEAD_ALG_EXCEPTION_MSG);
    }


    /**
     * @description Method to validate an Apex Supported JWS Signing Algorithm
     * @param       algorithm    The name of the algorithm to validate
     * @return      Name of the input algorithm if validated
     * @throws      JwsException The algorithm is invalid
     */
    @TestVisible
     private String validateJwsSigningAlgorithm(String algorithm){
        if(String.isNotBlank(algorithm)){
            if(VALID_JWS_SIGNING_ALGORITHMS.contains(algorithm?.trim())){
                return algorithm;
            }
        }
        throw new JwsException(JWS_INVALID_SIGN_ALG_EXCEPTION_MSG);
    }


    /**
     * @description Method that logs an exception and transforms any exception type into a
     *              GenericException
     * @param       e                         The exception that is thrown and needs to be handled
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @throws      GenericException          Always
     */
    @TestVisible
    private static void handleException(Exception e, Map<String,String> authProviderConfiguration){
        
        // Generate a generic exception message for the error handling and to be thrown to the user
        String exceptionMessage = String.format(GENERIC_EXCEPTION_MSG, new String[]{e.getTypeName(), e.getMessage()});
        
        // If logging is enabled use the "Lightweight - Auth Provider Util v2" method to insert an error log
        // This does mean a dependency with a different package, simply remove this code if you don't
        // want to install the dependency      
        if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_ERROR_LOGGING_FIELD_NAME))){
            
            getAuthProviderUtil().call('insertLog', new Map<String, Object> { 
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => UserInfo.getUserId(),
                'logId'            => GUID,
                'message'          => exceptionMessage
            });
        }
        
        // Throw the new generic exception to the user#
        throw new GenericException(exceptionMessage);
    }


    /**
     * @description Method to Switch the mapped subject between per user principal and Named Principal Mode
     *              as a Identity Type
     *              If per user principal is enabled use the "Lightweight - Auth Provider Util v2" method
     *              and populate the mapping fields for each user  that is allowed to get a token.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @return      The subject that will be part of the JWT sub parameter
     */
    private static String getSubject(Map<String,String> authProviderConfiguration){
        
        // Check if the per user principal is enabled
        if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_PER_USER_MODE_FIELD_NAME))){
            
			
            // If no user mapping exists throw an error
            if(! (Boolean) getAuthProviderUtil().call('checkUserMappingExists', new Map<String, Object> { 
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => UserInfo.getUserId()
            })){
                throw new SubjectException(
                    String.format(
                        NO_USER_MAPPING_MSG,
                        new String[]{authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME) , UserInfo.getUserId()}
                    )
                );
            }

            // Return the subject from the user mapping record related to this user and auth provider
            return (String) getAuthProviderUtil().call('getSubjectFromUserMapping', new Map<String, Object> { 
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => UserInfo.getUserId()
            });
        }
        
        // By default return the NamedPrincipal
        return authProviderConfiguration.get(JWT_SUBJECT_FIELD_NAME)?.trim();
    }

    
    /**
     * @description Method to set the user id for the logged in user
     * @param  callbackState The callback state containing the the cookie headers
     */
    @TestVisible
    private void setLoggedInUserDetails(Auth.AuthProviderCallbackState callbackState){
     
        // Get the data for the  logged in user based on the cookie header
        loggedInUserData = (Auth.UserData) getAuthProviderUtil().call('getAuthUserDataFromCookieHeader', new Map<String, Object> { 
            'cookieHeader' => (!Test.IsRunningTest()) ? callbackState.headers.get('Cookie') : TEST_COOKIE_HEADER
        });
        // Extract the user Id for ease of use later
        loggedInUserId = loggedInUserData.identifier;
    }


    /**
     * @description Method to get an instance of the AuthProviderUtil class.
     *              This option requires the "Lightweight - Auth Provider Util v2" (04t4K000002Jv1tQAC)
     *              package to be installed
     * @return      Instance of the AuthProviderUtil class
     * @throws      GenericException The lwt.AuthProviderUtil class does not exist.
     */
    @TestVisible
    private static Callable getAuthProviderUtil(){
        
        // Lazy loading
        if(authProviderUtil == null){
            
            // Dymaically instatiate class 
            authProviderUtil = (Callable) Type.forName('lwt.AuthProviderUtil')?.newInstance();
            
            // Throw an error if the package is not installed
            // Add Test check here so the test does not fail in case the package is installed
            if(authProviderUtil == null || Test.isRunningTest()){
                throw new GenericException(MISSING_UTIL_PACKAGE_MSG);
            }
        }
        return authProviderUtil;
    }

    /**
     * @description Method that generates the JWT, JWS and HTTP Request to retrieve an access token
     *              from the configured token endpoint.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       flowType                  The type of login flow (Initial or Refresh)
     * @param       success                   Inidcator if the login was successful or not
     * @param       providerType              Optional description of the provider. This is handy when you
     *                                        have chained callouts.
     * @param       callout                   The callout details for error logging
     */
    @SuppressWarnings('PMD.ExcessiveParameterList')
    private void handleInsertHistoryRecord(Map<String,String> authProviderConfiguration, String flowType, Boolean success, String providerType, utl.Rst callout){
        // If login history is enabled, create a login history entry
        if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_LOGIN_HISTORY_FIELD_NAME))){
            getAuthProviderUtil().call('insertLoginHistoryRecord', new Map<String, Object> { 
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => loggedInUserId,
                'flowType'         => flowType,
                'timestamp'        => Datetime.now(),
                'success'          => success,
                'providerType'     => providerType,
                'loginInfo'        => success ? null : callout?.getResponse()?.getBody()
            });
        }
    }


    /** **************************************************************************************************** **
     **                                      PRIVATE EXCEPTION CLASSES                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Custom Exception thrown when there is an issue generating the JWS.
     */
    @TestVisible
    private class JwsException    extends Exception{}


    /**
     * @description Custom Exception thrown when there is an issue generating the token.
     */
    @TestVisible
    private class TokenException  extends Exception{}


    /**
     * @description Custom Exception thrown when there is an issue related the subject
     */
    @TestVisible
    private class SubjectException extends Exception{}


    /**
     * @description Custom Exception thrown when there is an issue generating the token.
     */
    @TestVisible
    private class GenericException extends Exception{}


    /** **************************************************************************************************** **
     **                                    PRIVATE DATA STRUCTURE CLASSES                                    **
     ** **************************************************************************************************** **/
    /**
     * @description     Class representing the data strcuture of an OAuth Token Response as described in standard:
     *                  https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
     * @false-positives Namings conventions have to match the JSON response format in order to properly
     *                  deserialize.  In this case the naming conventions will not follow standard
     *                  conventions to accomodate this
     */
    @SuppressWarnings('PMD.VariableNamingConventions, PMD.FieldNamingConventions')
    @TestVisible
    private class TokenResponse{
        
        // Required
        public String access_token;
        public String token_type;

        // Optional
        public String expires_in;
        public String scope;
        public String state;
    }
}