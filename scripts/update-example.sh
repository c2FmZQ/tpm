#!/bin/bash -e

sed -ne '0,/^## Example/p' < README.md > README.md.new
echo >> README.md.new
echo '```go' >> README.md.new
cat example/main.go >> README.md.new
echo '```' >> README.md.new
echo >> README.md.new
echo '```sh' >> README.md.new
echo '$ go run ./example --sim' >> README.md.new
go run ./example --sim >> README.md.new
echo '```' >> README.md.new
mv -f README.md.new README.md
