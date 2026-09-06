#!/bin/bash
#
# Runs the MyPwStock regression tests.
#
# It compiles the current sources, then compiles and runs the JUnit tests that
# check the validators, password generation and the encrypted-file format.
#
# This is the macos version. Nothing of this run is platform specific: javac, java
# and the : separator of the classpath work the same way on linux and on macos, so
# this script is the very same as MyPwStock_run_tests_linux.sh.
#
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

SRC="src/com/kisscodesystems/MyPwStock"
BUILD="$ROOT/build/testrun"
JARS="$ROOT/lib"
JUNIT="$JARS/junit-4.12.jar"
HAMCREST="$JARS/hamcrest-core-1.3.jar"

rm -rf "$BUILD"
mkdir -p "$BUILD/main_out" "$BUILD/test_out"

# 1. Compile the current sources.
javac -d "$BUILD/main_out" "$SRC"/*.java

# 2. Compile and run the tests.
CP="$BUILD/main_out:$JUNIT:$HAMCREST"
javac -cp "$CP" -d "$BUILD/test_out" test/com/kisscodesystems/MyPwStock/MyPwStockTest.java
java  -cp "$CP:$BUILD/test_out" org.junit.runner.JUnitCore com.kisscodesystems.MyPwStock.MyPwStockTest
