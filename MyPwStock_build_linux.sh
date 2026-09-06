#!/bin/bash

# 1. Compile the sources into a fresh output directory.
javac -d bin src/com/kisscodesystems/MyPwStock/*.java

# 2. Package a runnable jar using the bundled manifest (it sets Main-Class).
cd bin && jar cvfm MyPwStock.jar ../src/com/kisscodesystems/MyPwStock/manifest.txt com/kisscodesystems/MyPwStock/*.class

cp MyPwStock.jar ../

echo ""
echo "You can now start your application by"
echo "java -jar MyPwStock.jar interactive mode"
