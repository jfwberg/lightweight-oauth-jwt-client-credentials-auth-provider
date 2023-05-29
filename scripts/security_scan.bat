rem SECURITY SCAN - PMD
call sfdx scanner:run -t "C:/VSCode Projects/lightweight-oauth-jwt-client-credentials-auth-provider/force-app" -f html -o "scan-results/pmd-result.html" --verbose

rem SECURITY SCAN - GRAPH RULES
call sfdx scanner:run:dfa -t "force-app/main/default/classes/*.cls" -p "C:/VSCode Projects/lightweight-oauth-jwt-client-credentials-auth-provider" -f html -o "scan-results/graph-result.html" --verbose
