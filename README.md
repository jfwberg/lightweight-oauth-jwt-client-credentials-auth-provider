# OAuth 2.0 JWT Client Authentication Auth Provider for use with Salesforce Named and External Credentials
## Goals
- Create a reusable Auth Provider to be used with named credentials, that executes a OAuth 2.0 JWT Client Authentication flow using a Client Credentials grant type using the standards as described in https://datatracker.ietf.org/doc/html/rfc7523#section-2.2

## Requirements
- A certificate imported in the Salesforce key store 
- The public key shared with the authorisation server 
- All details required to setup the connection

## Important
- Security is no easy subject: Before implementing this solution always validate what you're doing with a certified sercurity expert and your implementation partner

## Setup
- Import the signing certificate into Salesforce
- Deploy the class and the custom metadata
- Create a new Auth Provider Using this class
- Remember the separation of concerns; each auth provider should have its own executing Integration User whenever possible. So one integration is separate from the other
- No secrets should have to be configured.. If this is required

## Note on coding
- Everything is kept in a single class, to make it small and stand-alone. This includes any validations that could have been in validation rules or messages that could have been in custom labels. This is a contious design decision to keep everything together.
This is a single class with a single purpose, you either want to package it or keep it nicely together.
- Any confguration values are in a constant at the top following the common code structure
- Always use the this keyword properly for readability
- Always add ApexDoc headers even if it seems overkill, it's just good practice
	
## Todo: 
- Write a Test Class
- Run security scan on the class
- Run PMD / Graph and fix any issues
- Put the params names in constants
- Validate quiddity
- Create a namespaced managed package
- Add example data to package (named + external credential)
