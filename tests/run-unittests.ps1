[CmdletBinding()]
param (
  [ValidateSet('always', 'never')]
  [string] $pull = 'always'
)

# Run all tests using docker and a read-only file system so the docker image cannot impact the local files.

$rootFolder = Split-Path $PSScriptRoot
docker run --pull $pull --rm -v "${rootFolder}:/pwd:ro" python bash /pwd/tests/run-unittests.sh