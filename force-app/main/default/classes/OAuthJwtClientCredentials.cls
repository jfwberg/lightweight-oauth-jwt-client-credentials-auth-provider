/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        April 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description OAuth 2.0 JWT Client Authentication Auth Provider for the use with Client Credentials
 *              Follows the standard as described in 
 *              https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
 */
public with sharing class OAuthJwtClientCredentials extends Auth.AuthProviderPluginClass{

    /** ******************************************************************************** **
     **                                PRIVATE CONSTANTS                                 **
     ** ******************************************************************************** **/
    // Grant details
    @TestVisible private final String SCOPE_FIELD_NAME          = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Scope__c);
    @TestVisible private final String TOKEN_ENDPOINT_FIELD_NAME = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Token_Endpoint_URL__c);
    @TestVisible private final String TOKEN_HEADERS_FIELD_NAME  = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Additional_Token_Endpoint_Headers__c);
    @TestVisible private final String CUSTOM_CALLBACK_FIELD_NAME= String.valueOf(OAuth_JWT_Client_Authentication__mdt.Custom_Callback_URL__c);

    // JWT Header info
    @TestVisible private final String JWT_ALGORITHM_FIELD_NAME  = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Algorithm__c);
    @TestVisible private final String JWT_KID_FIELD_NAME        = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Kid__c);

    // JWT Settings
    @TestVisible private final String JWT_SUBJECT_FIELD_NAME    = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Subject__c);
    @TestVisible private final String JWT_ISSUER_FIELD_NAME     = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Issuer__c);
    @TestVisible private final String JWT_AUDIENCE_FIELD_NAME   = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Audience__c);
    
    // Specify the name for your auth provider for the callback URL
    @TestVisible private final String AUTH_PROVIDER_NAME_FIELD_NAME     = String.valueOf(OAuth_JWT_Client_Authentication__mdt.Auth_Provider_Name__c);

    // The API name of the certificate and the algorithm used for signing the JWT
    @TestVisible private final String JWS_SIGNING_CERT_FIELD_NAME       = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Signing_Certificate_Name__c);
    @TestVisible private final String JWS_SIGNING_ALGORITHM_FIELD_NAME  = String.valueOf(OAuth_JWT_Client_Authentication__mdt.JWT_Signing_Algorithm__c);

    // Parameter names
    @TestVisible private final String PARAM_NAME_STATE = 'state';

    // Valid algorithm for JKS Header and JWT Signing Certificate for validating the user inputs based on availible SFDC functionality
    @TestVisible private final Set<String> VALID_JWS_HEADER_ALGORITHMS  = new Set<String>{'RS256','RS384','RS512','ES256','ES384','ES512'};
    @TestVisible private final Set<String> VALID_JWS_SIGNING_ALGORITHMS = new Set<String>{'RSA-SHA256','RSA-SHA384','RSA-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512'};
    
    // Any messages go here
    @TestVisible private final String INVALID_TOKEN_RESPONSE_MSG            = 'Unexpected response when calling the token endpoint: {0}';
    @TestVisible private final String JWS_INVALID_HEAD_ALG_EXCEPTION_MSG    = 'Invalid JWS Header Algorithm provided. Valid values are: \'RS256\',\'RS384\',\'RS512\',\'ES256\',\'ES384\' and \'ES512\'';
    @TestVisible private final String JWS_INVALID_SIGN_ALG_EXCEPTION_MSG    = 'Invalid JWS Signing Algorithm provided. Valid values are: \'RSA-SHA256\',\'RSA-SHA384\',\'RSA-SHA512\',\'ECDSA-SHA256\',\'ECDSA-SHA384\',\'ECDSA-SHA512\'';
    
    

    /** ******************************************************************************** **
     **                             PUBLIC INTERFACE METHODS                             **
     ** ******************************************************************************** **/
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
        pageReference.getParameters().put(this.PARAM_NAME_STATE, stateToPropagate);

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
        
        // Retrieve a new token from the token endpoint
        TokenResponse tokenResponse = this.retrieveToken(authProviderConfiguration);
        
        // Return the the token response, there is no refresh token so we just set a random value
        return new Auth.AuthProviderTokenResponse(
            authProviderConfiguration.get(this.AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
            tokenResponse.access_token,
            'NoRefreshTokenInThisOAuthFlow',
            callbackState.queryParameters.get(this.PARAM_NAME_STATE)
        ); 
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
        
        // Retrieve a new token from the token endpoint
        TokenResponse response = this.retrieveToken(authProviderConfiguration);
        
        // Return the (refresh) token response
        return new Auth.OAuthRefreshResult(
            response.access_token,
            response.token_type
        );
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
        return new Auth.UserData(
            'IntegrationUserId',// User Id
            'Integration',        // First Name
            'User',                // Last Name
            'Integration User',    // Full Name
            'integration.user@example.com.invalid',    // Email Address
            'link',                // Link
            null,                // Username
            null,                 // Locale
            null,                // Provider
            null,                // Site login
            null                // Attribute map
        );
    }


    /**
     * @description Returns the custom metadata type API name for a custom OAuth-based authentication
     *              provider for single sign-on to Salesforce.
     * @return      The custom metadata type API name for the authentication provider.
     */
    public String getCustomMetadataType() {
        return String.valueOf(OAuth_JWT_Client_Authentication__mdt.getSObjectType());
    }


    /** ******************************************************************************** **
     **                             PRIVATE SUPPORT METHODS                              **
     ** ******************************************************************************** **/
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
        if(String.isNotBlank(authProviderConfiguration.get(this.CUSTOM_CALLBACK_FIELD_NAME)?.trim())){
            return new PageReference(authProviderConfiguration.get(this.CUSTOM_CALLBACK_FIELD_NAME)?.trim());
        }
        
        // By default generate the Standard Salesforce Callback URL for the Auth Provider
        return new PageReference(
            URL.getSalesforceBaseUrl().toExternalForm() + '/services/authcallback/' + authProviderConfiguration.get(this.AUTH_PROVIDER_NAME_FIELD_NAME)?.trim()
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
        
        // Generate the full body string as a URL query parameter
        String body =  this.urlParameterQueryString(new Map<String,String>{
            'grant_type'            => 'client_credentials',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion'      => this.generateJWS(authProviderConfiguration),
            'scope'                 => authProviderConfiguration.get(this.SCOPE_FIELD_NAME)?.trim()
        });

        // Create the request to the token endpoint
        HttpRequest httpRequest = new HttpRequest(); 
        httpRequest.setEndpoint(authProviderConfiguration.get(this.TOKEN_ENDPOINT_FIELD_NAME)?.trim()); 
        httpRequest.setHeader('Content-Type','application/x-www-form-urlencoded'); 
        httpRequest.setMethod('POST'); 
        httpRequest.setBody(body);
        
        // Add optional custom headers to the token request (i.e. things like API keys,  X-Correlation-Id etc.)
        this.addStringHeadersToRequest(
            authProviderConfiguration.get(this.TOKEN_HEADERS_FIELD_NAME)?.trim(),
            httpRequest
        );

        
        // fetch the response
        HTTPResponse res = new Http().send(httpRequest); 

        // Check the status is as expexted or throw an exception
        if(res.getStatusCode() != 200){
            throw new TokenException(String.format(this.INVALID_TOKEN_RESPONSE_MSG, new String[]{res.getBody()}));
        }

        // Parse the response into a token response
        return this.parseTokenResponse(res.getBody());
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
            'alg' => this.validateJwsHeaderAlgorithm(authProviderConfiguration.get(this.JWT_ALGORITHM_FIELD_NAME)?.trim()),
            'typ' => 'JWT',
            'kid' => authProviderConfiguration.get(this.JWT_KID_FIELD_NAME)?.trim()
        });

        // Create the JWT payload
        String payload = JSON.serialize(new Map<String,Object>{
            'iss' => authProviderConfiguration.get(this.JWT_ISSUER_FIELD_NAME)?.trim(),
            'aud' => authProviderConfiguration.get(this.JWT_AUDIENCE_FIELD_NAME)?.trim(),
            'sub' => authProviderConfiguration.get(this.JWT_SUBJECT_FIELD_NAME)?.trim(),
            'exp' => (DateTime.now().addSeconds(300).getTime() / 1000),
            'jti' => this.generateGUID()
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
                this.validateJwsSigningAlgorithm(authProviderConfiguration.get(this.JWS_SIGNING_ALGORITHM_FIELD_NAME)?.trim()),
                Blob.valueOf(b64UrlEncodedHeaderAndPayload),
                authProviderConfiguration.get(this.JWS_SIGNING_CERT_FIELD_NAME)?.trim()
            )
        ) : '[TEST_CLASS_VALUE_BECAUSE_THERE_IS_NO_MOCK_CERT_OPTION]';

        // Create and return the JWT in a signed and compact serialization
        return String.format('{0}.{1}', new String[]{
            b64UrlEncodedHeaderAndPayload,
            b64UrlEncodedSignature
        });
    }


    /** ******************************************************************************** **
     **                             PRIVATE UTILITY METHODS                              **
     ** ******************************************************************************** **/
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
     * @description Very basic GUID implementation that you should probably replace this with your own
     *              implementation if you deem it necessary.
     *              These GUIDs are used to populate the "jti" parameter in the JWT to prevent replay
     *              attacks.
     * @return      V4 UUID (GUID)
     */
    private String generateGUID(){
        String randomHexString = EncodingUtil.convertToHex(Crypto.generateAESKey(256));
        return String.join(new String[]{
            randomHexString.substring(0,8),
            randomHexString.substring(8,12),
            randomHexString.substring(12,16),
            randomHexString.substring(16,20),
            randomHexString.substring(20,32)
        },'-');
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
    private void addStringHeadersToRequest(String headerValue, HttpRequest httpRequest){
        if(String.isNotBlank(headerValue)){
            
            // Each header should be split by a comma, due to fact multi line is not supported
            for(String line : headerValue.split(',')){
                
                // Check the line contains a colon but still has a value after the colon
                if(line.contains(':')){
                    
                    // Split the value in key value pair
                    String[] keyValueList = line.split(':');
                    
                    // Validate the header is correct and has a 
                    if(keyValueList.size() == 2){
                        httpRequest.setHeader(keyValueList[0]?.trim(), keyValueList[1]?.trim());
                    }
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
    private String validateJwsHeaderAlgorithm(String algorithm){
        if(String.isNotBlank(algorithm)){
            if(this.VALID_JWS_HEADER_ALGORITHMS.contains(algorithm?.trim())){
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
    private String validateJwsSigningAlgorithm(String algorithm){
        if(String.isNotBlank(algorithm)){
            if(this.VALID_JWS_SIGNING_ALGORITHMS.contains(algorithm?.trim())){
                return algorithm;
            }
        }
        throw new JwsException(this.JWS_INVALID_SIGN_ALG_EXCEPTION_MSG);
    }


    /**
     * @description Method to convert a key/value map into a URL encoded parameter query string that
     *              can be used with url-encoded forms or get queries
     * @param       parameterValueMap A key/value map that contains the parameter name and the
     *                                parameter value
     * @return      a url encoded parameter string formatted like "?key1=value1&key2=value2"
     */
    private String urlParameterQueryString(Map<String,String> parameterValueMap){
        
        // Return an emtpy string if the input is null
        if(parameterValueMap == null || parameterValueMap.isEmpty()){
            return '';
        }

        // Start the query string
        String queryString ='';

        // Parameter string format
        final String PARAMETER_TEMPLATE = '{0}{1}={2}';

        // Add parameter if the parameter has a value
        for(String parameter : parameterValueMap.keySet()){
            if(String.isNotBlank(parameterValueMap.get(parameter))){
                queryString += String.format(PARAMETER_TEMPLATE, new String[]{
                    ((String.isBlank(queryString)) ? '' : '&'),
                    parameter,
                    EncodingUtil.urlEncode(parameterValueMap.get(parameter), 'UTF-8')
                });
            }
        }
        // Return the query string
        return queryString;
    }


    /** ******************************************************************************** **
     **                            PRIVATE EXCEPTION CLASSES                             **
     ** ******************************************************************************** **/
    private class JwsException        extends Exception{}
    private class TokenException    extends Exception{}


    /** ******************************************************************************** **
     **                          PRIVATE DATA STRUCTURE CLASSES                          **
     ** ******************************************************************************** **/
    /**
     * @description     Class representing the data strcuture of an OAuth Token Response as described in standard:
     *                  https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
     * @false-positives Namings conventions have to match the JSON response format in order to properly
     *                  deserialize.  In this case the naming conventions will not follow standard
     *                  conventions to accomodate this
     */
    @SuppressWarnings('PMD.VariableNamingConventions')
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