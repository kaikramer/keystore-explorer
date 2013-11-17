#!/bin/sh

# KeyStore Explorer requires that an Oracle/OpenJDK JRE of version 1.6+ be present on your path

java -classpath kse.jar:bcprov.jar:bcpkix.jar:jhall.jar:jgoodies-looks.jar:jgoodies-common.jar:miglayout-core.jar:miglayout-swing.jar net.sf.keystore_explorer.KSE
