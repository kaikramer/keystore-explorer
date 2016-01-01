#!/bin/bash

# Oracle/OpenJDK JRE version 1.6+ has to be present on your path 
# OR in a directory called "jre" in the same directory as this script 

SCRIPT_DIR="`dirname \"$0\"`"
JAR_FILE="${SCRIPT_DIR}/kse.jar"

if [ -d "${SCRIPT_DIR}/jre" ]; then
    "${SCRIPT_DIR}/jre/bin/java" -jar "${JAR_FILE}" "$@"
else
    java -jar "${JAR_FILE}" "$@"
fi

