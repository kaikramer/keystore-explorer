/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2020 Kai Kramer
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
package org.kse.gui;

/**
 * POJO class to configure the cells shown in the KeyStore table of KeyStore Explorer.
 *
 */
public class KeyStoreTableColumns {
	private int expiryWarnDays;
	private boolean bEnableEntryName;
	private boolean bEnableAlgorithm;
	private boolean bEnableKeySize;
	private boolean bEnableCertificateExpiry;
	private boolean bEnableLastModified;
	private boolean bEnableSKI;
	private boolean bEnableAKI;
	private boolean bEnableIssuerDN;
	private boolean bEnableSubjectDN;
	private boolean bEnableIssuerCN;
	private boolean bEnableSubjectCN;
	private boolean bEnableIssuerO;
	private boolean bEnableSubjectO;
	private boolean bEnableCurve;
	private boolean bEnableSerialNumberHex;
	private boolean bEnableSerialNumberDec;
	/** Column for a property */
	private int iNameColumn = -1;
	private int iAlgorithmColumn = -1;
	private int iKeySizeColumn = -1;
	private int iCurveColumn = -1;
	private int iCertExpiryColumn = -1;
	private int iLastModifiedColumn = -1;
	private int iAKIColumn = -1;
	private int iSKIColumn = -1;
	private int iIssuerDNColumn = -1;
	private int iSubjectDNColumn = -1;
	private int iIssuerCNColumn = -1;
	private int iSubjectCNColumn = -1;
	private int iIssuerOColumn = -1;
	private int iSubjectOColumn = -1;
	private int iSerialNumberHexColumn = -1;
	private int iSerialNumberDecColumn = -1;

	// As default set to previous layout from older KSE versions
	public KeyStoreTableColumns() {
		expiryWarnDays = 0;
		bEnableEntryName = true;
		bEnableAlgorithm = true;
		bEnableKeySize = true;
		bEnableCertificateExpiry = true;
		bEnableLastModified = true;
		bEnableSKI = false;
		bEnableAKI = false;
		bEnableIssuerDN = false;
		bEnableSubjectDN = false;
		bEnableCurve = false;
		bEnableIssuerCN = false;
		bEnableSubjectCN = false;
		bEnableIssuerO = false;
		bEnableSubjectO = false;
		bEnableSerialNumberHex = false;
		bEnableSerialNumberDec = false;
	}



	public KeyStoreTableColumns(boolean bEnableEntryName, boolean bEnableAlgorithm,
			boolean bEnableKeySize, boolean bEnableCertificateExpiry, boolean bEnableLastModified, boolean bEnableSKI,
			boolean bEnableAKI, boolean bEnableIssuerDN, boolean bEnableSubjectDN, boolean bEnableIssuerCN,
			boolean bEnableSubjectCN, boolean bEnableIssuerO, boolean bEnableSubjectO, boolean bEnableCurve,
			int expiryWarnDays, boolean bEnableSerialNumberHex, boolean bEnableSerialNumberDec) {
		super();
		this.bEnableEntryName = bEnableEntryName;
		this.bEnableAlgorithm = bEnableAlgorithm;
		this.bEnableKeySize = bEnableKeySize;
		this.bEnableCertificateExpiry = bEnableCertificateExpiry;
		this.bEnableLastModified = bEnableLastModified;
		this.bEnableSKI = bEnableSKI;
		this.bEnableAKI = bEnableAKI;
		this.bEnableIssuerDN = bEnableIssuerDN;
		this.bEnableSubjectDN = bEnableSubjectDN;
		this.bEnableIssuerCN = bEnableIssuerCN;
		this.bEnableSubjectCN = bEnableSubjectCN;
		this.bEnableIssuerO = bEnableIssuerO;
		this.bEnableSubjectO = bEnableSubjectO;
		this.bEnableCurve = bEnableCurve;
		this.expiryWarnDays = expiryWarnDays;
		this.bEnableSerialNumberHex = bEnableSerialNumberHex;
		this.bEnableSerialNumberDec = bEnableSerialNumberDec;
		sortCol();
	}


	private void sortCol() {
		int col = 2;
		iNameColumn = -1;
		iAlgorithmColumn = -1;
		iKeySizeColumn = -1;
		iCurveColumn = -1;
		iCertExpiryColumn = -1;
		iLastModifiedColumn = -1;
		iAKIColumn = -1;
		iSKIColumn = -1;
		iIssuerDNColumn = -1;
		iSubjectDNColumn = -1;
		iIssuerCNColumn = -1;
		iSubjectCNColumn = -1;
		iIssuerOColumn = -1;
		iSubjectOColumn = -1;
		iSerialNumberHexColumn = -1;
		iSerialNumberDecColumn = -1;

		if (bEnableEntryName) {
			iNameColumn = ++col;
		}
		if (bEnableAlgorithm) {
			iAlgorithmColumn = ++col;
		}
		if (bEnableKeySize) {
			iKeySizeColumn = ++col;
		}
		if (bEnableCurve) {
			iCurveColumn = ++col;
		}
		if (bEnableCertificateExpiry) {
			iCertExpiryColumn = ++col;
		}
		if (bEnableLastModified) {
			iLastModifiedColumn = ++col;
		}
		if (bEnableAKI) {
			iAKIColumn = ++col;
		}
		if (bEnableSKI) {
			iSKIColumn = ++col;
		}
		if (bEnableIssuerDN) {
			iIssuerDNColumn = ++col;
		}
		if (bEnableSubjectDN) {
			iSubjectDNColumn = ++col;
		}
		if (bEnableIssuerCN) {
			iIssuerCNColumn = ++col;
		}
		if (bEnableSubjectCN) {
			iSubjectCNColumn = ++col;
		}
		if (bEnableIssuerO) {
			iIssuerOColumn = ++col;
		}
		if (bEnableSubjectO) {
			iSubjectOColumn = ++col;
		}
		if (bEnableSerialNumberHex) {
			iSerialNumberHexColumn = ++col;
		}
		if (bEnableSerialNumberDec) {
			iSerialNumberDecColumn = ++col;
		}
	}

	public void setColumns(boolean bEnableEntryName, boolean bEnableAlgorithm, boolean bEnableKeySize,
			boolean bEnableCertificateExpiry, boolean bEnableLastModified, boolean bEnableSKI, boolean bEnableAKI,
			boolean bEnableIssuerDN, boolean bEnableSubjectDN, boolean bEnableIssuerCN, boolean bEnableSubjectCN,
			boolean bEnableIssuerO, boolean bEnableSubjectO, boolean bEnableCurve, boolean bEnableSerialNumberHex,
			boolean bEnableSerialNumberDec, int expiryWarnDays) {
		this.bEnableEntryName = bEnableEntryName;
		this.bEnableAlgorithm = bEnableAlgorithm;
		this.bEnableKeySize = bEnableKeySize;
		this.bEnableCertificateExpiry = bEnableCertificateExpiry;
		this.bEnableLastModified = bEnableLastModified;
		this.bEnableSKI = bEnableSKI;
		this.bEnableAKI = bEnableAKI;
		this.bEnableIssuerDN = bEnableIssuerDN;
		this.bEnableSubjectDN = bEnableSubjectDN;
		this.bEnableIssuerCN = bEnableIssuerCN;
		this.bEnableSubjectCN = bEnableSubjectCN;
		this.bEnableIssuerO = bEnableIssuerO;
		this.bEnableSubjectO = bEnableSubjectO;
		this.bEnableCurve = bEnableCurve;
		this.bEnableSerialNumberHex = bEnableSerialNumberHex;
		this.bEnableSerialNumberDec = bEnableSerialNumberDec;
		this.expiryWarnDays = expiryWarnDays;
		sortCol();
	}

	/**
	 * Restore from bitmap
	 *
	 * @param col
	 */
	public void setColumns(int col) {

		bEnableEntryName = ((col & 1) != 0);
		bEnableAlgorithm = ((col & 2) != 0);
		bEnableKeySize = ((col & 4) != 0);
		bEnableCertificateExpiry = ((col & 8) != 0);
		bEnableLastModified = ((col & 0x10) != 0);
		bEnableSKI = ((col & 0x20) != 0);
		bEnableAKI = ((col & 0x40) != 0);
		bEnableIssuerDN = ((col & 0x80) != 0);
		bEnableSubjectDN = ((col & 0x100) != 0);
		bEnableCurve = ((col & 0x200) != 0);
		bEnableIssuerCN = ((col & 0x400) != 0);
		bEnableSubjectCN = ((col & 0x800) != 0);
		bEnableIssuerO = ((col & 0x1000) != 0);
		bEnableSubjectO = ((col & 0x2000) != 0);
		bEnableSerialNumberHex = ((col & 0x4000) != 0);
		bEnableSerialNumberDec = ((col & 0x8000) != 0);
		sortCol();
	}

	/**
	 * Get as bitmap
	 *
	 * @return col
	 */
	public int getColumns() {
		int col = 0;
		if (bEnableEntryName) {
			col += 1;
		}
		if (bEnableAlgorithm) {
			col += 2;
		}
		if (bEnableKeySize) {
			col += 4;
		}
		if (bEnableCertificateExpiry) {
			col += 8;
		}
		if (bEnableLastModified) {
			col += 0x10;
		}
		if (bEnableSKI) {
			col += 0x20;
		}
		if (bEnableAKI) {
			col += 0x40;
		}
		if (bEnableIssuerDN) {
			col += 0x80;
		}
		if (bEnableSubjectDN) {
			col += 0x100;
		}
		if (bEnableCurve) {
			col += 0x200;
		}
		if (bEnableIssuerCN) {
			col += 0x400;
		}
		if (bEnableSubjectCN) {
			col += 0x800;
		}
		if (bEnableIssuerO) {
			col += 0x1000;
		}
		if (bEnableSubjectO) {
			col += 0x2000;
		}
		if (bEnableSerialNumberHex) {
			col += 0x4000;
		}
		if (bEnableSerialNumberDec) {
			col += 0x8000;
		}
		return col;
	}

	/**
	 * Get number of columns selected. The actual table has 3 columns more, as the first 3 are fixed.
	 *
	 * @return number of columns selected
	 */
	public int getNofColumns() {
		int col = 0;
		if (bEnableEntryName) {
			col++;
		}
		if (bEnableAlgorithm) {
			col++;
		}
		if (bEnableKeySize) {
			col++;
		}
		if (bEnableCertificateExpiry) {
			col++;
		}
		if (bEnableLastModified) {
			col++;
		}
		if (bEnableSKI) {
			col++;
		}
		if (bEnableAKI) {
			col++;
		}
		if (bEnableIssuerDN) {
			col++;
		}
		if (bEnableSubjectDN) {
			col++;
		}
		if (bEnableCurve) {
			col++;
		}
		if (bEnableIssuerCN) {
			col++;
		}
		if (bEnableSubjectCN) {
			col++;
		}
		if (bEnableIssuerO) {
			col++;
		}
		if (bEnableSubjectO) {
			col++;
		}
		if (bEnableSerialNumberHex) {
			col++;
		}
		if (bEnableSerialNumberDec) {
			col++;
		}
		return col;
	}

	public boolean getEnableEntryName() {
		return bEnableEntryName;
	}

	public boolean getEnableAlgorithm() {
		return bEnableAlgorithm;
	}

	public boolean getEnableKeySize() {
		return bEnableKeySize;
	}

	public boolean getEnableCertificateExpiry() {
		return bEnableCertificateExpiry;
	}

	public boolean getEnableLastModified() {
		return bEnableLastModified;
	}

	public boolean getEnableSKI() {
		return bEnableSKI;
	}

	public boolean getEnableAKI() {
		return bEnableAKI;
	}

	public boolean getEnableCurve() {
		return bEnableCurve;
	}

	public boolean getEnableIssuerDN() {
		return bEnableIssuerDN;
	}

	public boolean getEnableSubjectDN() {
		return bEnableSubjectDN;
	}

	public boolean getEnableIssuerCN() {
		return bEnableIssuerCN;
	}

	public boolean getEnableSubjectCN() {
		return bEnableSubjectCN;
	}

	public boolean getEnableIssuerO() {
		return bEnableIssuerO;
	}

	public boolean getEnableSubjectO() {
		return bEnableSubjectO;
	}

	public boolean getbEnableSerialNumberHex() {
		return bEnableSerialNumberHex;
	}

	public boolean getbEnableSerialNumberDec() {
		return bEnableSerialNumberDec;
	}

	public int getExpiryWarnDays() {
		return expiryWarnDays;
	}

	public void setExpiryWarnDays(int expiryWarnDays) {
		this.expiryWarnDays = expiryWarnDays;
	}

	public int colEntryName() {
		return iNameColumn;
	}

	public int colAlgorithm() {
		return iAlgorithmColumn;
	}

	public int colKeySize() {
		return iKeySizeColumn;
	}

	public int colCertificateExpiry() {
		return iCertExpiryColumn;
	}

	public int colLastModified() {
		return iLastModifiedColumn;
	}

	public int colSKI() {
		return iSKIColumn;
	}

	public int colAKI() {
		return iAKIColumn;
	}

	public int colCurve() {
		return iCurveColumn;
	}

	public int colIssuerDN() {
		return iIssuerDNColumn;
	}

	public int colSubjectDN() {
		return iSubjectDNColumn;
	}

	public int colIssuerCN() {
		return iIssuerCNColumn;
	}

	public int colSubjectCN() {
		return iSubjectCNColumn;
	}

	public int colIssuerO() {
		return iIssuerOColumn;
	}

	public int colSubjectO() {
		return iSubjectOColumn;
	}

	public int colSerialNumberHex() {
		return iSerialNumberHexColumn;
	}

	public int colSerialNumberDec() {
		return iSerialNumberDecColumn;
	}
}
