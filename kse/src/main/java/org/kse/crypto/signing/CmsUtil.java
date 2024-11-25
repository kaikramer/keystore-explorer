/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
package org.kse.crypto.signing;

import java.io.IOException;

import org.bouncycastle.cms.CMSSignedData;
import org.kse.crypto.CryptoException;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

public class CmsUtil {
    private static final String CMS_PEM_TYPE = "CMS";
    private static final String PKCS7_PEM_TYPE = "PKCS7";

    private CmsUtil() {
    }

    /**
     * PEM encode a CMS signature.
     *
     * @param cms The CMS signature
     * @return The PEM'd encoding
     */
    public static String getPem(CMSSignedData cms) throws CryptoException {
        // Use PKCS7 PEM header since it can be verified using GnuTLS certtool and OpenSSL.
        try {
            PemInfo pemInfo = new PemInfo(PKCS7_PEM_TYPE, null, cms.getEncoded());
            return PemUtil.encode(pemInfo);
        } catch (IOException e) {
            // TODO JW Auto-generated catch block
            throw new CryptoException(e);
        }
    }
}
