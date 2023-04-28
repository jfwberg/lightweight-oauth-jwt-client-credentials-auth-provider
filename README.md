# OAuth 2.0 JWT Client Credentials Authentication Auth Provider for use with Salesforce Named and External Credentials
## Important
- Security is no easy subject: Before implementing this (or any) solution, always validate what you're doing with a certified sercurity expert and your certified implementation partner
- At the time of writing I work for Salesforce. The views / solutions presented here are stricktly MY OWN and NOT per definition the views or solutions from Salesforce. Again, always consult with your certified implementation partner before implementing anything.

## Goal
A reusable Auth Provider that can be used with named / external credentials that executes an OAuth 2.0 JWT Client Authentication flow using a Client Credentials grant type.
The grant type standards are described in https://datatracker.ietf.org/doc/html/rfc7523#section-2.2

## Requirements
- A certificate with private key that is used for signing the JWT with a JWS that is imported in the Salesforce certificate key store
- Alternatively you can use a self signed certificate for testing purposes
- The public key needs te be shared with the authorisation server and setup according to their standards, usually a JWKS
- You'll need all the authorization server details that are required to setup the connection

## Setup steps
1. Import the signing certificate into Salesforce (or create a self signed cert), Note down the certificate API Name
2. Deploy the Apex class and the Custom Metadata to your Org
3. Create a new Auth Provider Using this class
| Field Name                        	| Description                                                                                                                                                                   	| Example                              	|
|-----------------------------------	|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|--------------------------------------	|
| Name                              	| Auth Provider API Name                                                                                                                                                        	| MY_AUTHP                             	|
| URL Suffix                        	| The URL suffix that is used in the callback URL Make sure this is the same as the name field                                                                                  	| MY_AUTHP                             	|
| Additional Token Endpoint Headers 	| Optional headers that are send during the API token request key value pairs are split with a comma and header key values are set using a colon                                	| apiKey : MyApiKey, custId : myCustId 	|
| Auth Provider Name                	| The name of the Auth Provider: !! This must be the same as the Name field !!                                                                                                  	| MY_AUTHP                             	|
| JWT Algorithm                     	| The algoritm used for signing the JWT. Valid values are: 'RS256','RS384','RS512','ES256','ES384','ES512' Note: we are limited to the algorithms supported by the Crypto Class 	| RS512                                	|
| JWT Audience                      	| The aud in the JWT                                                                                                                                                            	| https://login.salesforce.com         	|
| JWT Issuer                        	| The iss in the JWT                                                                                                                                                            	| f3fjd983nfgd2334jdf8gdl334920fg23    	|
| JWT Kid                           	| The Key Id in the JWT                                                                                                                                                         	| test-1                               	|
| JWT Signing Algorithm             	| The algorithm used to sign the JWT and generate a JWS  'RSA-SHA256','RSA-SHA384','RSA-SHA512','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512'                                    	| RSA-SHA512                           	|
| JWT Signing Certificate Name      	| The certificate API name that is used for signing the certificate                                                                                                             	| myCert                               	|
| JWT Subject                       	| The sub field in the JWT                                                                                                                                                      	| f3fjd983nfgd2334jdf8gdl334920fg23    	|
| Token Endpoint URL                	| The URL for the token endpoint, usually ends in /oauth2/token                                                                                                                 	| [HOST]/oauth2/token                  	|
| Scope                             	| Optional value for the scope parameter in the request body                                                                                                                    	| refresh_token,api,web                	|
| Custom Callback URL               	| Optionally you can add your custom callback URL, this should not be required. The code generates the callback URL based on the name                                           	| https://localhost:1919/callback      	|

4. Create a match 
- Remember the separation of concerns; each auth provider should have its own executing Integration User whenever possible. So one integration is separate from the other
- No secrets should have to be configured.. If this is required

## Note on coding
- Everything is kept in a single class, to make it small and stand-alone. This includes any validations that could have been in validation rules or messages that could have been in custom labels. This is a contious design decision to keep everything together.
This is a single class with a single purpose, you either want to package it or keep it nicely together.
- Any confguration values are in a constant at the top following the common code structure
- Always use the this keyword properly for readability
- Always add ApexDoc headers even if it seems overkill, it's just good practice
- Certificate related methods cannot be tested because Apex cannot mock certificates. The alternative is to supply a certificate name in the test class but I'd like to keep the tests org agnostic
	
## Todo: 
- Improve the Test Class, add branched if/else scenarios and test the utility methods
- Run PMD / Graph scan and fix any issues
- Extend header length to match text width to help my OCD

## Steps to import a certificate store (JKS) in a scratch Org when getting "Data Not Available" error message on import
In some cases there is a bug in the certificate import that gives an error if you try to import a JKS It says "Data Not Available".
I have this issue in all my scratch orgs. There is a simple way to resolve this.
1) Go to setup > certificate and key management
2) Create a self signed certficate
3) Go to Setup >> Identity provider
4) Click enable Identity Provider and select the self signed certificate you just created and press save
5) Press the disable button, as we dont really need it
6) Go back to Setup > Certificate and Key Management and try to "import from keystore" again, it should work now.
