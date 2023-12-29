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

package org.kse.gui.dialogs.sign;

import java.math.BigInteger;
import java.util.Date;

/**
 * Class for an entry revoked certificate.
 */
public class RevokedEntry {

    private BigInteger userCertificateSerial;
    private Date revocationDate;
    private int reason;

    /**
     * Construct a new RevokedEntry.
     *
     * @param userCertificateSerial Serial number
     * @param revocationDate        Revocation date
     * @param reason                Reason why a certificate is revoked
     */
    public RevokedEntry(BigInteger userCertificateSerial, Date revocationDate, int reason) {
        super();
        this.userCertificateSerial = userCertificateSerial;
        this.revocationDate = revocationDate;
        this.reason = reason;
    }

    /**
     * Gets the serial number from this RevokedEntry.
     *
     * @return the serial number.
     */
    public BigInteger getUserCertificateSerial() {
        return userCertificateSerial;
    }

    /**
     * Gets the revocation date from this RevokedEntry.
     *
     * @return the revocation date
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * Returns the reason the certificate has been revoked.
     *
     * @return reason.
     */
    public int getReason() {
        return reason;
    }

}
