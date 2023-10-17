REM *****************************
REM        PACKAGE CREATION   
REM *****************************

REM Package Create Config
SET devHub=devHubAlias
SET packageName=Lightweight - OAuth 2.0 JWT Client Credentials Auth Provider (Unlocked)
SET packageDescription=A lightweight generic Auth Provider Apex class that can be used with named/external credentials to get an access token using the OAuth 2.0 JWT Client Credentials Authentication Flow.
SET packageType=Unlocked
SET packagePath=force-app/package

REM Package Config
SET packageId=
SET packageVersionId=

REM Create package
sf package create --name "%packageName%" --description "%packageDescription%" --package-type "%packageType%" --path "%packagePath%" --target-dev-hub %devHub%

REM Create package version
sf package version create --package "%packageName%"  --target-dev-hub %devHub% --code-coverage --installation-key-bypass --wait 30

REM Delete package
sf package:delete -p %packageId% --target-dev-hub %devHub% --no-prompt

REM Delete package version
sf package:version:delete -p %packageVersionId% --target-dev-hub %devHub% --no-prompt

REM Promote package version
sf package:version:promote -p %packageVersionId% --target-dev-hub %devHub% --no-prompt
