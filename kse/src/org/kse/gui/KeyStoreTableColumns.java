/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
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
 * POJO class to configure the cells shown in the KeyStore table of KeyStore
 * Explorer.
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
	// set to previous layout
	public KeyStoreTableColumns() {
 expiryWarnDays = 0;
 bEnableEntryName = true;
 bEnableAlgorithm = true;
 bEnableKeySize = true;
 bEnableCertificateExpiry =true;
 bEnableLastModified = true;
 bEnableSKI = false;
 bEnableAKI = false;
 bEnableIssuerDN = false;
 bEnableSubjectDN = false;
 bEnableCurve = false;
 bEnableIssuerCN= false;
 bEnableSubjectCN= false;
 bEnableIssuerO= false;
 bEnableSubjectO= false;
	}
	public KeyStoreTableColumns(boolean p1,boolean p2,boolean p3,boolean p4,boolean p5,boolean p6,boolean p7,boolean p8,boolean p9,boolean p10,boolean p11,boolean p12,boolean p13,boolean p14, int p15  ) {
		 bEnableEntryName = p1;
		 bEnableAlgorithm = p2;
		 bEnableKeySize = p3;
		 bEnableCertificateExpiry =p4;
		 bEnableLastModified = p5;
		 bEnableSKI = p6;
		 bEnableAKI = p7;
		 bEnableIssuerDN = p8;
		 bEnableSubjectDN = p9;
			bEnableIssuerCN = p10;
			bEnableSubjectCN = p11;
			bEnableIssuerO = p12;
			bEnableSubjectO = p13;
			bEnableCurve = p14;
			expiryWarnDays = p15;
		 
	}	
	
	public void setColumns(boolean p1,boolean p2,boolean p3,boolean p4,boolean p5,boolean p6,boolean p7,boolean p8,boolean p9,boolean p10,boolean p11,boolean p12,boolean p13,boolean p14, int p15 ) {
		 bEnableEntryName = p1;
		 bEnableAlgorithm = p2;
		 bEnableKeySize = p3;
		 bEnableCertificateExpiry =p4;
		 bEnableLastModified = p5;
		 bEnableSKI = p6;
		 bEnableAKI = p7;
		 bEnableIssuerDN = p8;
		 bEnableSubjectDN = p9;
			bEnableIssuerCN = p10;
			bEnableSubjectCN = p11;
			bEnableIssuerO = p12;
			bEnableSubjectO = p13;
			bEnableCurve = p14;
			expiryWarnDays = p15;

	}
	/**
	 * Restore from bitmap
	 * @param col
	 */
	public void setColumns(int col) {

		 bEnableEntryName = ((col & 1)!=0);
		 bEnableAlgorithm = ((col & 2)!=0);
		 bEnableKeySize =((col & 4)!=0);
		 bEnableCertificateExpiry =((col & 8)!=0);
		 bEnableLastModified = ((col & 0x10)!=0);
		 bEnableSKI = ((col & 0x20)!=0);
		 bEnableAKI = ((col & 0x40)!=0);
		 bEnableIssuerDN =((col & 0x80)!=0);
		 bEnableSubjectDN = ((col & 0x100)!=0);
		 bEnableCurve = ((col & 0x200)!=0);
		 bEnableIssuerCN= ((col & 0x400)!=0);
		 bEnableSubjectCN= ((col & 0x800)!=0);
		 bEnableIssuerO= ((col & 0x1000)!=0);
		 bEnableSubjectO= ((col & 0x2000)!=0);
	}
	/**
	 * Get as bitmap
	 * @return col
	 */
	public int getColumns() {
		 int col= 0;
		 if (bEnableEntryName) col+=1;
		 if (bEnableAlgorithm) col+=2;
		 if (bEnableKeySize) col+=4;
		 if (bEnableCertificateExpiry) col+=8;
		 if (bEnableLastModified) col+=0x10;
		 if (bEnableSKI) col+=0x20;
		 if (bEnableAKI) col+=0x40;
		 if (bEnableIssuerDN) col+=0x80;
		 if (bEnableSubjectDN) col+=0x100;
		 if (bEnableCurve) col+=0x200;
		 if (bEnableIssuerCN) col+=0x400;
		 if (bEnableSubjectCN) col+=0x800;
		 if (bEnableIssuerO) col+=0x1000;
		 if (bEnableSubjectO) col+=0x2000;
		 return col;
	}
	/**
	 * Get number of columns selected
	 * @return number of columns selected
	 */
	public int getNofColumns() {
		 int col= 0;
		 if (bEnableEntryName) col++;
		 if (bEnableAlgorithm) col++;
		 if (bEnableKeySize) col++;
		 if (bEnableCertificateExpiry) col++;
		 if (bEnableLastModified) col++;
		 if (bEnableSKI) col++;
		 if (bEnableAKI) col++;
		 if (bEnableIssuerDN) col++;
		 if (bEnableSubjectDN) col++;
		 if (bEnableCurve) col++;
		 if (bEnableIssuerCN) col++;
		 if (bEnableSubjectCN) col++;
		 if (bEnableIssuerO)  col++;
		 if (bEnableSubjectO) col++;
		 return col;
	}

	public boolean getEnableEntryName()
	{
		return bEnableEntryName; 
	}
	public boolean getEnableAlgorithm ()
	{
		return bEnableAlgorithm ; 
	}
	public boolean getEnableKeySize ()
	{
		return bEnableKeySize ; 
	}
	public boolean getEnableCertificateExpiry ()
	{
		return bEnableCertificateExpiry ; 
	}
	public boolean getEnableLastModified ()
	{
		return bEnableLastModified ; 
	}
	public boolean getEnableSKI ()
	{
		return bEnableSKI ; 
	}
	public boolean getEnableAKI ()
	{
		return bEnableAKI ; 
	}
	public boolean getEnableCurve ()
	{
		return bEnableCurve ; 
	}
	public boolean getEnableIssuerDN ()
	{
		return bEnableIssuerDN ; 
	}
	public boolean getEnableSubjectDN ()
	{
		return bEnableSubjectDN ; 
	}
	public boolean getEnableIssuerCN ()
	{
		return bEnableIssuerCN ; 
	}
	public boolean getEnableSubjectCN ()
	{
		return bEnableSubjectCN ; 
	}
	public boolean getEnableIssuerO ()
	{
		return bEnableIssuerO ; 
	}
	public boolean getEnableSubjectO ()
	{
		return bEnableSubjectO ; 
	}
	public int getExpiryWarnDays ()
	{
		return expiryWarnDays ; 
	}
	public void setExpiryWarnDays (int expiryWarnDays)
	{
		this.expiryWarnDays = expiryWarnDays ; 
	}

}
