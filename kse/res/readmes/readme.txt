================================
 KeyStore Explorer Manual Setup
================================

Prerequisites
-------------

KeyStore Explorer requires that an Oracle Java Runtime
Environment (JRE) be installed on your computer.
KeyStore Explorer requires JRE version 1.7 or
greater.  The latest version of the Oracle JRE is
available free of charge from www.java.com.


Local JRE
---------

Both the shell script and the exe first search for 
a local JRE, i.e. a directory with name "jre" in the 
KSE directory. If it exists, it is used for running KSE. 
This allows to use another JRE for KSE than the default 
system JRE.

All you have to do is copy the jre, jre7 or jre8 
directory into the KSE directory and rename it to "jre". 


Windows Command-Line
--------------------

1) These instructions assume that the JRE's bin
   directory has been added to your path.
   
2) Change to the kse directory   

3) Enter the following command:

       java -jar kse.jar

Unix/Linux Command-Line
-----------------------

1) These instructions assume that the JRE's bin
   directory has been added to your path.

2) Change to the kse directory

3) Enter the following command:

       ./kse.sh

===========================================
 Copyright 2004 - 2013 Wayne Grant
           2013 - 2018 Kai Kramer
===========================================

