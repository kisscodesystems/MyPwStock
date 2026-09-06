#!/bin/bash

# This is the macos version. Nothing of this build is platform specific: javac, jar
# and the : separator of the classpath work the same way on linux and on macos, so
# this script is the very same as MyPwStock_build_linux.sh.

# 1. Compile the sources into a fresh output directory.
javac -d bin src/com/kisscodesystems/MyPwStock/*.java

# 2. Package a runnable jar using the bundled manifest (it sets Main-Class).
cd bin && jar cvfm MyPwStock.jar ../src/com/kisscodesystems/MyPwStock/manifest.txt com/kisscodesystems/MyPwStock/*.class

cp MyPwStock.jar ../

echo ""
echo "You can now start your application by"
echo "java -jar MyPwStock.jar interactive mode"
