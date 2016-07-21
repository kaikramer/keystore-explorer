#!/bin/bash

# Oracle/OpenJDK JRE version 1.6+ has to be present on your path
# OR in a directory called "jre" in the same directory as this script

# detect parent folder of script, regardless aliases and symlinks
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
JAR_FILE="${SCRIPT_DIR}/kse.jar"

if [ -d "${SCRIPT_DIR}/jre" ]; then
    "${SCRIPT_DIR}/jre/bin/java" -jar "${JAR_FILE}" "$@"
else
    java -jar "${JAR_FILE}" "$@"
fi
