# Contributing to the KeyStore Explorer Project

- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Contributing to the Code](#contributing-to-the-code)
  - [Contributing to the Documentation or Website](#contributing-to-the-documentation-or-website)
- [List of Contributions](#list-of-contributions)
  - [Code Contributions](#code-contributions)
  - [Documentation](#documentation)
  - [Translations](#translations)

## How Can I Contribute?

First of all, thanks for taking the time to contribute!

The following is a set of suggestions and guidelines for contributing to KSE. They make it easier for users who would
like to get involved.

### Reporting Bugs

One of the best ways you can help us improve KSE is to let us know about any problems you find with it.

The KSE project uses [GitHub issues](https://github.com/kaikramer/keystore-explorer/issues) to report and track bugs.

Before you file an issue, search for it to see if anyone has already reported it. If you find your issue, check if you
can provide additional information, that might be useful to resolve the issue.

If no one has reported your bug, file the bug. Please describe the problem in detail. Be sure to include:
* Steps to reproduce the problem.
* What happened.
* What you think the correct behavior should be.
* Don't forget to mention which operating system and which version of Java and KSE you're using.

In general, put as much information in bugs as you can. The more detail you provide, the more likely your issue is to be resolved.

**Important:** Please be on the lookout for any follow-up questions we may have.

### Contributing to the Code 

If you want to contribute to the code, go to GitHub, fork the KSE repository, apply your changes and open a pull
request (PR). GitHub provides detailed information on the process on their website:
[GitHub - Contributing to a Project](https://guides.github.com/activities/contributing-to-open-source/#contributing)

In order to make the review of the PR a pleasant experience for contributors and reviewers and to preserve the quality
of the code base, it is important to:

* Make sure the code changes are well tested and that they cause no unwanted side effects.
* Verify that all existing and new tests pass.
* Check that the code formatting matches the existing code. For IntelliJ IDEA you can
  use [this formatter configuration](https://keystore-explorer.org/kse_formatter.xml), for other IDEs you should at least
  modify the default formatter so that lines are wrapped at 120 characters and all indentations are spaces (no tabs).
* Make sure no unrelated or unnecessary reformatting changes are included.

If you intend to implement a non-trivial enhancement or a new feature, please make sure there is
an [issue](https://github.com/kaikramer/keystore-explorer/issues) that corresponds to your contribution &ndash; either
created by you or by somebody else. Announce in the issue that you intend to work on it to make sure that the work is
not done twice. This is also a good way to get some guidance on how to best tackle a problem or discuss implementation
ideas.

### Contributing to the Documentation or Website

Good documentation is crucial for any kind of software. You can help improving the documentation:
* Please report missing, incorrect, or out-dated documentation as an [issue](https://github.com/kaikramer/keystore-explorer/issues).
* The [KSE website](https://keystore-explorer.org) is in
  a [GitHub repository](https://github.com/kaikramer/kaikramer.github.io) just like the KSE source code, which means
  improvements for the website can be contributed in the same way as code contributions. Or you could open
  an [issue](https://github.com/kaikramer/keystore-explorer/issues) if you think the website could be improved, but
  don't want to do it yourself.

## List of Contributions

We would like to thank all contributors for their commitment and support.

Those who contributed code, documentation or translations are listed by name below.

### Code Contributions

| Contributor | Version | Contribution |
| --- | --- | --- |
| David Harper | 5.1.1 | Fixed Linux start script, it works now if called from outside the KSE folder. |
| Uri Blumenthal | 5.1.1 | Fixed import of EC keys. |
| Chris Kistner | 5.2.0 | Support viewing of non-CRT RSA private key fields. |
| Chris Ridd | 5.2.0 | Added IPv6 addresses for SubjAltName extension. |
| Davy Defaud | 5.2.0 | Added RPM packaging for Mageia. |
| Kevin Herron | 5.2.0 | Installing the JCE Unlimited Crypto Strength policy is no longer necessary. |
| Uri Blumenthal | 5.2.0 | Added several ExtendedKeyUsage (AdobePDFSigning, ...) types. |
| Filip Jirsák | 5.2.0 | Fixed AuthorityKeyIdentifier extension. |
| Josef Ludvicek | 5.2.1 | Fixed a problem with kse.sh when it's executed through a symlink. |
| Peter Breur | 5.2.2 | Fixed authorityCertIssuer in AKI extension. |
| Andreas Schwier | 5.2.2 | Ignoring unsupported certificate types now. |
| Andreas Schwier | 5.2.2 | Fixed problem when generating EC keys with crypto devices. |
| Michele Mariotti | 5.3.0 | Added flexible validity date selection. |
| Luís Câmara | 5.3.0 | Changed maximum key length for DSA keys to 2048. |
| Jordi Pinzón | 5.3.0 | Added QcStatement types for eIDAS certificates. |
| Wim Ton | 5.4.0 | Configurable columns on main display. |
| Benny Prange | 5.4.0 | Added certificate export in certificate details view. |
| Kable Wilmoth | 5.4.0 | Added support for Bouncy Castle's BCFKS keystore type. |
| Jordi Pinzón | 5.4.2 | Certificate generation: Editing of extensions fixed |
| Michele Mariotti | 5.4.2 | Fixed date/time spinners and added shortcut buttons. |
| Jordi Pinzón | 5.4.3 | Custom (i.e. user definable) extended key usages |
| Vakhtang Laluashvili | 5.4.3 | TSL (Trust-service Status Lists) signing extended key usage, OID "0.4.0.2231.3.0" |
| Lothar Haeger | 5.4.3 | VAqua Look&Feel for macOS |
| Stephen Tomkinson | 5.4.4 | Enter certificate serial numbers in hexadecimal format |
| Stephen Tomkinson | 5.4.4 | Additional button in "Certificate Extensions" window to save those extensions as a template |
| Christoph Kaser | 5.4.4 | Allow to select multiple keystore entries (and cut/copy/paste/delete them) |
| Gary Bartlett | 5.4.4 | Fixed an incompatibility with VAqua |
| Patrick Decat | 5.4.4 | Allow running the application directly with './gradlew run' command |
| Colbix | 5.5.0 | Sign multiple jars |
| Colbix | 5.5.0 | Various improvements of JavaFX file chooser usage |
| Colbix | 5.5.0 | Added generation of Diffie-Hellman parameter files |
| Jairo Graterón | 5.5.0 | CRL Signing |
| Jairo Graterón | 5.5.0 | Certificate Validation |
| Jairo Graterón | 5.5.0 | CRL Distribution Points Extension (CDP) |
| Jairo Graterón | 5.5.0 | Additional name components for distinguished names |
| Jairo Graterón | 5.5.0 | Find (multiple) keystore entries |
| Jairo Graterón | 5.5.0 | Input suggestions for object identifiers (OIDs) |
| Jairo Graterón | 5.5.0 | Examine Clipboard for URLs |
| Jairo Graterón | 5.5.0 | Fixed display of General Name "IPAddress" |
| Matteo Baccan | 5.5.0 | Code quality improvements |
| Bill Stewart | 5.5.0 | Windows library for detecting Java installations |
| Bill Stewart | 5.5.0 | InnoSetup configuration |
| Jairo Graterón | 5.5.1 | Sign JWT (JSON Web Token) |
| The-Lum | 5.5.1 | Added "Verify Certificate" menu item for Trusted Certificate entries |
| The-Lum | 5.5.2 | Improved French translation |
| Jan S. (jpstotz) | 5.5.2 | Updated HTTP URLs |
| Colbix | 5.5.2 | Redesign of Preferences dialog |
| Jairo Graterón | 5.5.2 | "Transfer Name and Extensions" feature for generating new certificates based on existing ones |
| Colbix | 5.5.2 | Updated JavaFXFileChooser to include setSelectedExtensionFilter |
| Colbix | 5.5.2 | Updated DErrorCollection |
| Björn Michael | 5.5.3 | Certificate validity as additional column for main table view |
| dedabob | 5.5.3 | Added configurable size of random bytes to serial number |
| Jairo Graterón | 5.5.3 | Added export button in private key view dialog |
| Jairo Graterón | 5.5.3 | HTTP redirects for downloads of CRLs and CRTs are now supported |
| Afonso Fernandes | 5.5.3 | Added functionality to examine JWT in clipboard |
| Sergey Ponomarev | 5.5.3 | Export private key: changed default extension to .p8 for DER |
| Sergey Ponomarev | 5.5.3 | Added .p8, p8e and .pk8 as file extension filters for selecting PKCS#8 files |
| Sergey Ponomarev | 5.5.3 | Code refactorings |
| Piotr Kubiak | 5.5.3 | Changed certificate viewer dialog to be non-modal |
| The-Lum | 5.5.3 | Improved certificate key usage and EKU dialogs by adding tooltips |
| The-Lum | 5.5.3 | Improved ASN.1 view |
| tenpertur | 5.6.0 | Key Export in JWK Format |
| jonwltn | 5.6.0 | File signing and verification using PKCS#7/CMS |
| jonwltn | 5.6.0 | Added revocation reason code in CRL view |
| jonwltn | 5.6.0 | Added keyboard support for context menu |
| Erik Mattheis | 5.6.0 | Additional options for OCSP requests |
| Jairo Graterón | 5.6.0 | Verification of JWT Signatures |
| Jairo Graterón | 5.6.0 | Improved display of certificate and public key fingerprints |
| Jairo Graterón | 5.6.0 | Export multiple certificates |
| Jairo Graterón | 5.6.0 | Added DESCRIPTION (OID 2.5.4.13) for DNs |
| Jairo Graterón | 5.6.0 | DH parameters are now displayed in a scrollable pane |
| Jairo Graterón | 5.6.0 | Additional file name extensions supported for "Examine Clipboard" and "Extension Viewer" |
| Jairo Graterón | 5.6.0 | Copy error message to clipboard |
| AndresQ | 5.6.0 | "View Private Key" dialog now displays the original key format |
| Colbix | 5.6.0 | Improved usage of JavaFX file chooser in various ways |
| dadaewq | 5.6.0 | Support executing kse.sh with spaces in JAVA_OPTIONS |
| Sergey Ponomarev | 5.6.0 | Added more MIME types to the kse.desktop files for Linux |
| Sergey Ponomarev | 5.6.0 | Fixed Debian package lint warnings |
| Sergey Ponomarev | 5.6.0 | Various code quality improvements |
| jonwltn | 5.6.1 | Verification of JAR Files, PQC (SLH-DSA, ML-KEM), SM2 and ECGOST support, CSV export, and many other improvements and bugfixes. |
| AnassBousseaden | 5.6.1 | Support for ML-DSA algorithm. |
| Jairo Graterón | 5.6.1 | Certificate validity information, SCTs extension support, improved key pair import and other improvements. |
| The-Lum | 5.6.1 | Additional keyboard shortcuts, MS extensions support, CRL reason code format, ASN.1 viewer improvements. |
| idvolkov | 5.6.1 | Show certificate fingerprint in overview table and other improvements. |
| beth-soptim | 5.6.1 | Support Brainpool curves in P12/JKS/JCEKS keystores and use of string SecureRandom. |
| tenpertur | 5.6.1 | Allow leading or trailing spaces in PEM data. |

### Documentation
| Contributor | Date | Contribution |
|---|-------------|---|
| The-Lum | 2021-12-15  | Added Edwards curves to the EC (elliptic curve) table |
| The-Lum | 2021-12-15  | Added RSASSA-PSS to the signature algorithm list |
| The-Lum | 2021-12-15  | Fixed link to release 5.4 |
| The-Lum | 2022-02-02  | Created README.md |
| The-Lum | 2022-05-24  | Fixed 5.5 keyboard shortcuts documentation |
| The-Lum | 2022-05-25  | Fixed path to specifications page |
| The-Lum | 2022-07-07  | Fixed minor typo |
| The-Lum | 2023-01-25  | Fixed typo |
| The-Lum | 2025-07-22  | Fixed minor spacing typos |
| The-Lum | 2025-07-22  | Added "verify JWT" and "export as JWK" to Features page |
| The-Lum | 2025-07-22  | Documented PKCS#7 CMS signing and verification support |
| The-Lum | 2025-07-22  | Completed the Keyboard Shortcuts list with missing entries |
| The-Lum | 2025-07-22  | Fixed macOS shortcut note (F2 not available) |
| The-Lum | 2025-07-25  | Replaced "SSL" with "TLS/SSL" across docs (esp. 5.6) |
| The-Lum | 2025-11-15  | Added a new History page migrating Wayne Grant's blog content |
| The-Lum | 2025-11-16  | Fixed "History" nav item not showing as active |
| The-Lum | 2025-11-16  | Replaced external links with internal links in news |
| The-Lum | 2026-01-27  | Updated Tool Bar and Keyboard Shortcuts docs for v5.6.1 |
| The-Lum | 2026-01-31  | Updated Shortcut page with `<kbd>` tags and icons|


### Translations

| Language | Contributor |
| --- | --- |
| French | Davy Defaud, The-Lum |
| German | Frank Dietrich |
| Spanish | Jairo Graterón |
| Russian | Sergey Ponomarev |
| Chinese | liyansong2018 |
| Finnish | Ricky Tigg |
