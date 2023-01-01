#!/bin/bash

#
# Copyright 2004 - 2013 Wayne Grant
#           2013 - 2023 Kai Kramer
#
# This file is part of KeyStore Explorer.
#
# KeyStore Explorer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# KeyStore Explorer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
#

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
JAVA_OPTIONS="-splash:${SCRIPT_DIR}/splash.png"

if [ -d "${SCRIPT_DIR}/jre" ]; then
    "${SCRIPT_DIR}/jre/bin/java" ${JAVA_OPTIONS} -jar "${JAR_FILE}" "$@"
else
    java ${JAVA_OPTIONS} -jar "${JAR_FILE}" "$@"
fi
