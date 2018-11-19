#!/bin/bash

# Oracle/OpenJDK JRE version 1.8+ has to be present on your path
# OR in a directory called "jre" in the same directory as this script

# detect real location of this script, regardless aliases and symlinks
if [[ "$OSTYPE" == "darwin"* ]]; then
    REAL_SCRIPT_PATH=$(python -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$0")
else
    REAL_SCRIPT_PATH=$(readlink -f "$0")
fi

SCRIPT_DIR=$(dirname "$REAL_SCRIPT_PATH")
JAR_FILE="${SCRIPT_DIR}/kse.jar"

if [ -d "${SCRIPT_DIR}/jre" ]; then
    "${SCRIPT_DIR}/jre/bin/java" -jar "${JAR_FILE}" "$@"
else
    java -jar "${JAR_FILE}" "$@"
fi
