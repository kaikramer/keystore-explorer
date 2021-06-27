package org.kse.gui.dialogs.sign;

import java.math.BigInteger;
import java.util.Date;

/**
 * Class for a entry revoked certificate.
 *
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
