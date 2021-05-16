# KeyStore Explorer
[![Build Status](https://img.shields.io/github/workflow/status/kaikramer/keystore-explorer/Java%20CI%20with%20Gradle)](https://github.com/kaikramer/keystore-explorer/actions/workflows/gradle.yml)
[![Release](https://img.shields.io/github/v/release/kaikramer/keystore-explorer)](https://github.com/kaikramer/keystore-explorer/releases)
[![Downloads](https://img.shields.io/github/downloads/kaikramer/keystore-explorer/total)](https://tooomm.github.io/github-release-stats/?username=kaikramer&repository=keystore-explorer)
[![License](https://img.shields.io/github/license/kaikramer/keystore-explorer)](https://github.com/kaikramer/keystore-explorer/blob/master/LICENSE)

KeyStore Explorer is a free GUI replacement for the Java command-line utilities keytool and jarsigner.

Official website: http://keystore-explorer.org/

![Screenshot](https://raw.githubusercontent.com/kaikramer/kaikramer.github.io/main/images/win10_mykeystore.png)

## Features:

 -   Create, load, save and convert between various KeyStore types: JKS, JCEKS, PKCS#12, BKS (V1 and V2) and UBER
 -   Change KeyStore and KeyStore entry passwords
 -   Delete or rename KeyStore entries
 -   Cut/copy/paste KeyStore entries
 -   Append certificates to key pair certificate chains
 -   Generate RSA, ECC and DSA key pairs with self-signed X.509 certificates
 -   Apply X.509 certificate extensions to generated key pairs and Certificate Signing Requests (CSRs)
 -   View X.509 Certificate, CRL and CRL entry X.509 V3 extensions
 -   Import and export keys and certificates in many formats: PKCS#12, PKCS#8, PKCS#7, DER/PEM X.509 certificate files, Microsoft PVK, SPC, PKI Path, OpenSSL
 -   Generate, view and sign CSRs in PKCS #10 and SPKAC formats
 -   Sign JAR files
 -   Configure a CA Certs KeyStore for use with KeyStore operations
 
## Building

To do a clean build, issue the following command from the `kse` directory:

    $ ./gradlew clean build

This runs the unit tests and compiles a new `kse.jar` into `build/libs`. You can then update an existing KSE installation by replacing its kse.jar with this one.

The `build.gradle` file contains further instructions for building the platform specific distribution packages. In a nutshell:

For the ZIP package:

    $ ./gradlew zip 

For the Windows installer:    

    $ ./gradlew nsis

For the MacOS application:    

    $ ./gradlew appbundler

## Running

To run the application, issue the following command from the `kse` directory:

    $ ./gradlew run

## Contributing

We encourage you to contribute to KSE! Please check out the [Contributing to KSE guide](https://github.com/kaikramer/keystore-explorer/blob/master/CONTRIBUTING.md) for guidelines about how to proceed.

## License

[GNU General Public License v3.0](https://github.com/kaikramer/keystore-explorer/blob/master/LICENSE)
