#!/bin/bash

SCRIPT_DIR=`dirname $0`
APP_JAR=${SCRIPT_DIR}/kse.jar

# Oracle/OpenJDK JRE version 1.6+ has to be present on your path 
# OR in a directory called "jre" in the same directory as this script 

if [ -d "jre" ]; then
	./jre/bin/java -jar ${APP_JAR} 
else
	java -jar ${APP_JAR}
fi