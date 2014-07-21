#!/bin/bash

# Oracle/OpenJDK JRE version 1.6+ has to be present on your path 
# OR in a directory called "jre" in the same directory as this script 

if [ -d "jre" ]; then
	./jre/bin/java -jar kse.jar 
else
	java -jar kse.jar
fi
