/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.sf.keystore_explorer.crypto.x509;

import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * Convert between BC's X.509 Names and Oracle's X.500 Principals. Out of the
 * box each supports DN components the other doesn't. This converter deals with
 * these differences by extending each type's DN support.
 * 
 */
public class X500NameConverter {
	private X500NameConverter() {
	}

	/**
	 * Convert an X.500 Principal to an X.500 Name.
	 * 
	 * @param principal
	 *            X.500 Principal
	 * @return X.500 Name
	 */
	public static X500Name x500PrincipalToX500Name(X500Principal principal) {
		return X500Name.getInstance(KseX500NameStyle.INSTANCE, principal.getEncoded());
	}

	/**
	 * Convert an X.500 Name to an X.500 Principal.
	 * 
	 * @param name
	 *            X.500 Name
	 * @return X.500 Principal
	 * @throws IOException if an encoding error occurs (incorrect form for DN)
	 */
	public static X500Principal x500NameToX500Principal(X500Name name) throws IOException {
		return new X500Principal(name.getEncoded());
	}

	/**
	 * The BC X500Name class have been deprecated in favor of X500Name but are
	 * still required by some classes in the library (e.g.
	 * PKCS10CertificationRequest). Convert X.509 to X.500 names in here only to
	 * reduce deprecation warnings.
	 * 
	 * @param name
	 *            X.509 name
	 * @return X.500 name
	 */
	@SuppressWarnings("deprecation")
	public static X500Name x509NameToX500Name(org.bouncycastle.asn1.x509.X509Name name) {
		return new X500Name(KseX500NameStyle.INSTANCE, name.toString());
	}

	/**
	 * The BC X509Name class have been deprecated in favor of X500Name but are
	 * still required by some classes in the library (e.g.
	 * PKCS10CertificationRequest). Convert X.500 to X.509 names in here only to
	 * reduce deprecation warnings.
	 * 
	 * @param name
	 *            X.500 name
	 * @return X.509 name
	 */
	@SuppressWarnings("deprecation")
	public static org.bouncycastle.asn1.x509.X509Name x500PrincipalToX509Name(X500Principal name) {
		return new org.bouncycastle.asn1.x509.X509Name(name.toString());
	}
}
