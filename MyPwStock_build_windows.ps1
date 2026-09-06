# Builds the MyPwStock application.
#
# > powershell -ExecutionPolicy Bypass -File .\MyPwStock_build_windows.ps1

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# 1. Compile the sources into a fresh output directory.
#    javac and jar do not open wildcards on windows, the shell has to give them the
#    file list.
$sources = Get-ChildItem -LiteralPath 'src\com\kisscodesystems\MyPwStock' -Filter '*.java' | ForEach-Object { $_.FullName }
javac -d bin $sources
if ($LASTEXITCODE -ne 0)
{
  Write-Output "The sources could not be compiled."
  exit 1
}

# 2. Package a runnable jar using the bundled manifest (it sets Main-Class).
#    The jar entries have to stay relative to bin, so the packaging runs from there.
Push-Location 'bin'
$classes = Get-ChildItem -LiteralPath 'com\kisscodesystems\MyPwStock' -Filter '*.class' -Name | ForEach-Object { "com/kisscodesystems/MyPwStock/$_" }
jar cvfm 'MyPwStock.jar' '..\src\com\kisscodesystems\MyPwStock\manifest.txt' $classes
if ($LASTEXITCODE -ne 0)
{
  Pop-Location
  Write-Output "The jar could not be created."
  exit 1
}
Copy-Item -LiteralPath 'MyPwStock.jar' -Destination '..' -Force
Pop-Location

Write-Output ""
Write-Output "You can now start your application by"
Write-Output "java -jar MyPwStock.jar interactive mode"
