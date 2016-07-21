#!/bin/bash

# Oracle/OpenJDK JRE version 1.6+ has to be present on your path
# OR in a directory called "jre" in the same directory as this script

# detect parent folder of script, regardless aliases and symlinks
SOURCE="${BASH_SOURCE[0]}"
# resolve $SOURCE until the file is no longer a symlink
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

JAR_FILE="${SCRIPT_DIR}/kse.jar"

if [ -d "${SCRIPT_DIR}/jre" ]; then
    "${SCRIPT_DIR}/jre/bin/java" -jar "${JAR_FILE}" "$@"
else
    java -jar "${JAR_FILE}" "$@"
fi
