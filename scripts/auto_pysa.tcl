spawn pyre init-pysa
expect "current directory*" { send "Y\n" }
expect "should pyre analyze*" { send ".\n" }
expect "project dependencies now*" { send "n\n" }
expect "generate type annotations*" { send "Y\n" }
expect "filters to sapp*" { send "n\n" }