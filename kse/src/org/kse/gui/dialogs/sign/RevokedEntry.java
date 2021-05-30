package org.kse.gui.dialogs.sign;

import java.math.BigInteger;
import java.util.Date;

public class RevokedEntry {

	private BigInteger userCertificateSerial;
	private Date revocationDate;
	private int reason;
	
	public RevokedEntry(BigInteger userCertificateSerial, Date revocationDate, int reason) {
		super();
		this.userCertificateSerial = userCertificateSerial;
		this.revocationDate = revocationDate;
		this.reason = reason;
	}

	public BigInteger getUserCertificateSerial() {
		return userCertificateSerial;
	}

	public Date getRevocationDate() {
		return revocationDate;
	}

	public int getReason() {
		return reason;
	}
	
}
