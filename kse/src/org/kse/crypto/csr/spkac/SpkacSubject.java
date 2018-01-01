/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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
package org.kse.crypto.csr.spkac;

import java.util.ArrayList;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.kse.crypto.x509.KseX500NameStyle;

/**
 * SPKAC subject. Holder for all possible DN components that can be included in
 * a SPKAC request.
 *
 */
public class SpkacSubject {
	/** Common name property */
	public static final String CN_PROPERTY = "CN";

	/** Organisational unit property */
	public static final String OU_PROPERTY = "OU";

	/** Organisation property */
	public static final String O_PROPERTY = "O";

	/** Locality property */
	public static final String L_PROPERTY = "L";

	/** State property */
	public static final String ST_PROPERTY = "ST";

	/** Country property */
	public static final String C_PROPERTY = "C";

	// Subject values
	private String cn;
	private String ou;
	private String o;
	private String l;
	private String st;
	private String c;

	/**
	 * Construct SpkacSubject.
	 *
	 * @param cn
	 *            Common name
	 * @param ou
	 *            Organisational unit
	 * @param o
	 *            Organisation
	 * @param l
	 *            Locality
	 * @param st
	 *            State
	 * @param c
	 *            Country
	 */
	public SpkacSubject(String cn, String ou, String o, String l, String st, String c) {
		this.cn = cn;
		this.ou = ou;
		this.o = o;
		this.l = l;
		this.st = st;
		this.c = c;
	}

	/**
	 * Construct SpkacSubject.
	 *
	 * @param name
	 *            Name
	 */
	public SpkacSubject(X500Name name) {
		cn = getRdn(name, BCStyle.CN);
		ou = getRdn(name, BCStyle.OU);
		o = getRdn(name, BCStyle.O);
		l = getRdn(name, BCStyle.L);
		st = getRdn(name, BCStyle.ST);
		c = getRdn(name, BCStyle.C);
	}

	private String getRdn(X500Name name, ASN1ObjectIdentifier rdnOid) {
		RDN[] rdns = name.getRDNs(rdnOid);

		if (rdns.length > 0) {
			RDN rdn = rdns[0];
			String value = rdn.getFirst().getValue().toString();

			return value;
		}

		return null;
	}

	/**
	 * Get common name.
	 *
	 * @return Common name
	 */
	public String getCN() {
		return cn;
	}

	/**
	 * Get organisational unit.
	 *
	 * @return Organisational unit
	 */
	public String getOU() {
		return ou;
	}

	/**
	 * Get organisation.
	 *
	 * @return Organisation
	 */
	public String getO() {
		return o;
	}

	/**
	 * Get locality.
	 *
	 * @return Locality
	 */
	public String getL() {
		return l;
	}

	/**
	 * Get state.
	 *
	 * @return State
	 */
	public String getST() {
		return st;
	}

	/**
	 * Get country.
	 *
	 * @return Country
	 */
	public String getC() {
		return c;
	}

	/**
	 * Get subject as an X.509 name.
	 *
	 * @return Name
	 */
	public X500Name getName() {
		X500NameBuilder x500NameBuilder = new X500NameBuilder(KseX500NameStyle.INSTANCE);

		if (c != null) {
			x500NameBuilder.addRDN(BCStyle.C, c);
		}

		if (st != null) {
			x500NameBuilder.addRDN(BCStyle.ST, st);
		}

		if (l != null) {
			x500NameBuilder.addRDN(BCStyle.L, l);
		}

		if (o != null) {
			x500NameBuilder.addRDN(BCStyle.O, o);
		}

		if (ou != null) {
			x500NameBuilder.addRDN(BCStyle.OU, ou);
		}

		if (cn != null) {
			x500NameBuilder.addRDN(BCStyle.CN, cn);
		}

		return x500NameBuilder.build();
	}

	@Override
	public int hashCode() {
		final int prime = 31;

		int result = 1;

		result = prime * result + ((c == null) ? 0 : c.hashCode());
		result = prime * result + ((cn == null) ? 0 : cn.hashCode());
		result = prime * result + ((l == null) ? 0 : l.hashCode());
		result = prime * result + ((o == null) ? 0 : o.hashCode());
		result = prime * result + ((ou == null) ? 0 : ou.hashCode());
		result = prime * result + ((st == null) ? 0 : st.hashCode());

		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		final SpkacSubject other = (SpkacSubject) obj;

		if (c == null) {
			if (other.c != null) {
				return false;
			}
		} else if (!c.equals(other.c)) {
			return false;
		}

		if (cn == null) {
			if (other.cn != null) {
				return false;
			}
		} else if (!cn.equals(other.cn)) {
			return false;
		}

		if (l == null) {
			if (other.l != null) {
				return false;
			}
		} else if (!l.equals(other.l)) {
			return false;
		}

		if (o == null) {
			if (other.o != null) {
				return false;
			}
		} else if (!o.equals(other.o)) {
			return false;
		}

		if (ou == null) {
			if (other.ou != null) {
				return false;
			}
		} else if (!ou.equals(other.ou)) {
			return false;
		}

		if (st == null) {
			if (other.st != null) {
				return false;
			}
		} else if (!st.equals(other.st)) {
			return false;
		}

		return true;
	}

	private String formatNameValue(String name, String value) {
		return name + "=" + value;
	}

	/**
	 * Return subject as a distinguished name.
	 *
	 * @return Distinguished name
	 */
	@Override
	public String toString() {
		ArrayList<String> properties = new ArrayList<String>();

		if (getCN() != null) {
			properties.add(formatNameValue(CN_PROPERTY, getCN()));
		}

		if (getOU() != null) {
			properties.add(formatNameValue(OU_PROPERTY, getOU()));
		}

		if (getO() != null) {
			properties.add(formatNameValue(O_PROPERTY, getO()));
		}

		if (getL() != null) {
			properties.add(formatNameValue(L_PROPERTY, getL()));
		}

		if (getST() != null) {
			properties.add(formatNameValue(ST_PROPERTY, getST()));
		}

		if (getC() != null) {
			properties.add(formatNameValue(C_PROPERTY, getC()));
		}

		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < properties.size(); i++) {
			sb.append(properties.get(i));

			if ((i + 1) < properties.size()) {
				sb.append(", ");
			}
		}

		return sb.toString();
	}
}
