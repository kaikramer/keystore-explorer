/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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
package org.kse.crypto.x509;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * InhibitAnyPolicy extension from RFC 5280.
 *
 * <pre>
 * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 */
public class InhibitAnyPolicy extends ASN1Object {

    int skipCerts;

    /**
     * Creates an new instance with the given skipCerts.
     */
    public InhibitAnyPolicy(int skipCerts) {
        this.skipCerts = skipCerts;
    }

    /**
     * Returns the value of skipCerts.
     */
    public int getSkipCerts() {
        return skipCerts;
    }

    public static InhibitAnyPolicy getInstance(Object obj) {
        if (obj instanceof InhibitAnyPolicy) {
            return (InhibitAnyPolicy) obj;
        }
        if (obj instanceof ASN1Integer) {
            int skipCerts = ((ASN1Integer) obj).getValue().intValue();
            return new InhibitAnyPolicy(skipCerts);
        }
        if (obj instanceof byte[]) {
            int skipCerts = ASN1Integer.getInstance(obj).getValue().intValue();
            return new InhibitAnyPolicy(skipCerts);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(skipCerts);
    }
}