# OAuth 2.0 JWT Client Credentials Authentication Auth. Provider for use with Salesforce Named and External Credentials
## Description
A reusable Auth Provider that can be used with named / external credentials that executes an OAuth 2.0 JWT Client Authentication flow using a Client Credentials grant type.
The grant type standards are described in https://datatracker.ietf.org/doc/html/rfc7523#section-2.2

## Important
- Security is no easy subject: Before implementing this (or any) solution, always validate what you're doing with a certified sercurity expert and your certified implementation partner
- At the time of writing I work for Salesforce. The views / solutions presented here are strictly MY OWN and NOT per definition the views or solutions Salesforce would recommend. Again; always consult with your certified implementation partner before implementing anything.


## Pre-requisites
- A certificate with private key that is used for signing the JWT with a JWS that is imported in the Salesforce certificate key store
- Alternatively you can use a self signed certificate for testing purposes
- The public key needs te be shared with the authorisation server and setup according to their standards, usually a JWKS
- You'll need all the authorization server details that are required to setup the connection

## 01 :: Setup the Auth. Provider
In my example I am going to connect an api called "PiMoria"; this my test domain that I will use throughout this example.

1. Import the JWT signing certificate into Salesforce (or create a self signed cert), Note down the *Certificate API Name*
2. Deploy the *Apex class* and the *Custom Metadata (including layouts)* to your Org (Or install the package)
3. In setup > Auth Providers > Create a new Auth. Provider Using the *OAuthJwtClientCredentials* class as the type
4. Populate the *Execute Registration As* field first, this is a mandatory field that is not marked as mandatory and will reset the entire form if you forget it. 
5. Populate the fields in the the Auth. Provider. The below table details what is required in the fields

| Field Name                        | Description                                                                                                                                                                   | Example                              |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------|
| Name                              | Auth Provider API Name                                                                                                                                                        | PiMoria PROD                         |
| URL Suffix                        | The URL suffix that is used in the callback URL Make sure this is the same as the name field                                                                                  | PiMoria                              |
| Additional Token Endpoint Headers | Optional headers that are send during the API token request key value pairs are split with a comma and header key values are set using a colon                                | apiId : echo, apiId : 1919           |
| Auth Provider Name                | The name of the Auth Provider: !! This must be the same as the Name field !!                                                                                                  | PiMora                               |
| JWT Algorithm                     | The algoritm used for signing the JWT. Valid values are: 'RS256','RS384','RS512','ES256','ES384','ES512' Note: we are limited to the algorithms supported by the Crypto Class | RS512                                |
| JWT Audience                      | The aud in the JWT                                                                                                                                                            | https://prod.pimoria.com             |
| JWT Issuer                        | The iss in the JWT                                                                                                                                                            | pimoria-client-api-identifier        |
| JWT Kid                           | The Key Id in the JWT                                                                                                                                                         | prod-1                               |
| JWT Signing Algorithm             | The algorithm used to sign the JWT and generate a JWS  'RSA-SHA256','RSA-SHA384','RSA-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512'                                    | RSA-SHA512                           |
| JWT Signing Certificate Name      | The certificate API name that is used for signing the certificate                                                                                                             | PiMoriaProd                          |
| JWT Subject                       | The sub field in the JWT                                                                                                                                                      | system.user@pimoria.com              |
| Token Endpoint URL                | The URL for the token endpoint, usually ends in /oauth2/token                                                                                                                 | https://prod.pimoria.com/oauth2/token|
| Scope                             | Optional value for the scope parameter in the request body                                                                                                                    | api,refresh_token                    |
| Custom Callback URL               | Optionally you can add your custom callback URL, this should not be required. The code generates the callback URL based on the name                                           |                                      |

## 02 :: Setup The Remote Site Setting(s)
In order to make API call-outs to the token endpoint securely, we must setup a remote site setting for the token endpoint.

1. Go to Setup > Security > Remote Site Settings and click *New*
2. Populate the *Remote Site URL* field with the *Token Endpoint Base URL* and set a *Name* and *Description*
3. Press *Save*
4. If your API Base URL is different than your token URL, you need to create separate Remote Site Setting for this API

## 03 :: Create a Permission Set for the External Credential
External Credentials require a Permission Set in order to create a credential type mapping. It's best practice to create a separate Permisison Set for each Extern Credential to keep a strict separation and stick to the least access principle.

## 04 :: Setup the External Credential
Your Auth Provider is now ready for testing. The next step is to create an external credential that connects using your Auth Provider.

1. Go to setup > Security > Named Credentials and click the *External Credentials tab*
2. Click *New*, Set  A Label and a Name
3. Set *Authentication Protocol* to *OAuth 2.0*
4. Set *Authentication Flow Type* to *Browser Flow*. The *Scope* field can be left blank. This is overwritten by our Auth. Provider Settings.
5. Select your created Auth. Provider from the *Auth Provider Picklist* 
6. Press Save
7. Scroll down to the *Permission Set Mappings* section and press *New*
8. 




## Todo: 
- Improve the Test Class, add branched if/else scenarios and test the utility methods
- Run PMD / Graph scan and fix any issues
- Extend header length to match text width to help my OCD
- Explain the way to debug


## Note on coding
- Everything is kept in a single class, to make it small and stand-alone. This includes any validations that could have been in validation rules or messages that could have been in custom labels. This is a contious design decision to keep everything together.
This is a single class with a single purpose, you either want to package it or keep it nicely together.
- Any confguration values are in a constant at the top following the common code structure
- Always use the this keyword properly for readability
- Always add ApexDoc headers even if it seems overkill, it's just good practice
- Certificate related methods cannot be tested because Apex cannot mock certificates. The alternative is to supply a certificate name in the test class but I'd like to keep the tests org agnostic
	


## Steps to import a certificate store (JKS) in a scratch Org when getting "Data Not Available" error message on import
In some cases there is a bug in the certificate import that gives an error if you try to import a JKS It says "Data Not Available".
I have this issue in all my scratch orgs. There is a simple way to resolve this.
1) Go to setup > certificate and key management
2) Create a self signed certficate
3) Go to Setup >> Identity provider
4) Click enable Identity Provider and select the self signed certificate you just created and press save
5) Press the disable button, as we dont really need it
6) Go back to Setup > Certificate and Key Management and try to "import from keystore" again, it should work now.
