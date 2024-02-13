REM --------------------------------------------------------
REM MANGED DEPENDENCIES (PICK EITHER MANAGED OR UNLOCKED)  -
REM --------------------------------------------------------
rem Lightweight - Apex Unit Test Util v2@2.4.0-2
sf package install -p "04tP3000000M6OXIA0" -w 30

rem Lightweight - REST Util@0.11.0-1
sf package install -p "04tP3000000M6gHIAS" -w 30

REM ----------------- OPTIONAL BUT ADVICED -----------------
rem Lightweight - Auth Provider Util v2@0.12.0-1
sf package install -p "04tP3000000MVUzIAO" -w 30


REM --------------------------------------------------------
REM UNLOCKED DEPENDENCIES (PICK EITHER MANAGED OR UNLOCKED)-
REM --------------------------------------------------------
rem Lightweight - Apex Unit Test Util v2 (Unlocked)@2.4.0-2
sf package install -p "04tP3000000M6Q9IAK" -w 30

rem Lightweight - REST Util (Unlocked)@0.11.0-1
sf package install -p "04tP3000000M6htIAC" -w 30

REM ----------------- OPTIONAL BUT ADVICED -----------------
rem Lightweight - Auth Provider Util v2 (Unlocked)@0.12.0-1
sf package install -p "04tP3000000MW1FIAW" -w 30


REM --------------------------------------------------------
REM                  ASSIGN PERMISSION SETS                -
REM --------------------------------------------------------
sf org assign permset --name "Lightweight_Apex_Unit_Test_Util_v2"
sf org assign permset --name "Lightweight_REST_Util"
sf org assign permset --name "Lightweight_Auth_Provider_Util"
sf org assign permset --name "Lightweight_OAuth_JWT_Client_Credential_Auth_Provider"

