rem CREATE A PACKAGE - UPDATE DEVHUB
sf package create --name "OAuth 2.0 JWT Client Credentials Authentication Auth Provider" --description "A lightweight generic Auth Provider Apex class that can be used with named/external credentials to get an access token using the OAuth 2.0 JWT Client Credentials Authentication Flow." --package-type "Managed" --path "force-app" --target-dev-hub "[DEVHUB NAME]"

rem CREATE A PACKAGE VERSION - UPDATE DEVHUB
sf package version create --package "Lightweight - OAuth 2.0 JWT Client Credentials Auth Provider" --installation-key-bypass --code-coverage --target-dev-hub  "[DEVHUB NAME]" -w 30

rem PROMOTE THE PACKAGE VERSION - UPDATE NAME + DEVHUB
sf package version promote --package "Lightweight - OAuth 2.0 JWT Client Credentials Auth Provider@0.1.0-1" --target-dev-hub  "[DEVHUB NAME]"
