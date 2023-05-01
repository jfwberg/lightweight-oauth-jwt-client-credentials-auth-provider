rem CREATE A PACKAGE - UPDATE DEVHUB
sf package create --name "OAuth 2.0 JWT Client Credentials Authentication Auth Provider" --description "A generic Auth Provider Apex class that can be used with named/external credentials to get an access token using the OAuth 2.0 JWT Client Credentials Authentication Flow." --package-type "Managed" --path "force-app" --target-dev-hub "[DEVHUB NAME]"

rem CREATE A PACKAGE VERSION - UPDATE DEVHUB
sf package version create --package "OAuth 2.0 JWT Client Credentials Authentication Auth Provider" --installation-key-bypass --code-coverage --target-dev-hub  "[DEVHUB NAME]" -w 30

rem PROMOTE THE PACKAGE VERSION - UPDATE NAME + DEVHUB
sf package version promote --package "OAuth 2.0 JWT Client Credentials Authentication Auth Provider@0.1.0-2" --target-dev-hub  "[DEVHUB NAME]"
