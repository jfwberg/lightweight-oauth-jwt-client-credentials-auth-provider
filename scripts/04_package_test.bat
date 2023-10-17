REM *****************************
REM      INSTALL ON TEST ORG   
REM *****************************

REM Config
SET testOrg=orgAlias
SET packageVersionId=
SET dependencyVersionId=

REM Install the package dependencies
sf package:install -p %dependencyVersionId% --target-org %testOrg% --wait 30

REM Install the package
sf package:install -p %packageVersionId% --target-org %testOrg% --wait 30

REM Uninstall the package
sf package uninstall --package %packageVersionId% --target-org %testOrg% --wait 30

REM Uninstall the dependencies
sf package uninstall --package %packageVersionId% --target-org %testOrg% --wait 30
