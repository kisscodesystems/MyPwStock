# Runs the MyPwStock regression tests.
#
# > powershell -ExecutionPolicy Bypass -File .\MyPwStock_run_tests_windows.ps1
#
# Compiles the current sources, then compiles and runs the JUnit tests that
# check the validators, password generation and the encrypted-file format.

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Join-Path $PSScriptRoot '..')
$root = (Get-Location).Path

$src = Join-Path $root 'src\com\kisscodesystems\MyPwStock'
$build = Join-Path $root 'build\testrun'
$jars = Join-Path $root 'lib'
$junit = Join-Path $jars 'junit-4.12.jar'
$hamcrest = Join-Path $jars 'hamcrest-core-1.3.jar'

if (Test-Path -LiteralPath $build)
{
  Remove-Item -LiteralPath $build -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $build 'main_out') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $build 'test_out') -Force | Out-Null

$sources = Get-ChildItem -LiteralPath $src -Filter '*.java' | ForEach-Object { $_.FullName }

# 1. Compile the current sources.
javac -d (Join-Path $build 'main_out') $sources
if ($LASTEXITCODE -ne 0)
{
  Write-Output "The sources could not be compiled."
  exit 1
}

# 2. Compile and run the tests. The classpath is separated by ; on windows.
$cp = ((Join-Path $build 'main_out'), $junit, $hamcrest) -join ';'
javac -cp $cp -d (Join-Path $build 'test_out') (Join-Path $root 'test\com\kisscodesystems\MyPwStock\MyPwStockTest.java')
if ($LASTEXITCODE -ne 0)
{
  Write-Output "The tests could not be compiled."
  exit 1
}
java -cp ($cp + ';' + (Join-Path $build 'test_out')) org.junit.runner.JUnitCore com.kisscodesystems.MyPwStock.MyPwStockTest
exit $LASTEXITCODE
