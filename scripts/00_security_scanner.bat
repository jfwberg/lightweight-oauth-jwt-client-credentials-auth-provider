rem SECURITY SCAN - PMD
sfdx scanner:run -t "../force-app" -f html -o "scan-results/pmd-result.html" --verbose

rem SECURITY SCAN - GRAPH RULES
sfdx scanner:run:dfa --target "classes\*.cls" --projectdir "../force-app/package" -f html -o "scan-results/graph-result.html" --verbose