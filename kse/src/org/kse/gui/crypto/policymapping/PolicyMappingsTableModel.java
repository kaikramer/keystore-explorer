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
package org.kse.gui.crypto.policymapping;

import java.util.Arrays;
import java.util.Comparator;
import java.util.ResourceBundle;

import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.kse.crypto.x509.PolicyMapping;
import org.kse.utilities.oid.ObjectIdComparator;

/**
 * The table model used to display policy mappings.
 *
 */
public class PolicyMappingsTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/crypto/policymapping/resources");
	private static ObjectIdComparator objectIdComparator = new ObjectIdComparator();

	private String[] columnNames;
	private Object[][] data;

	/**
	 * Construct a new PolicyMappingsTableModel.
	 */
	public PolicyMappingsTableModel() {
		columnNames = new String[2];
		columnNames[0] = res.getString("PolicyMappingsTableModel.IssuerDomainPolicyColumn");
		columnNames[1] = res.getString("PolicyMappingsTableModel.SubjectDomainPolicyColumn");

		data = new Object[0][0];
	}

	/**
	 * Load the PolicyMappingsTableModel with policy mappings.
	 *
	 * @param policyMappings
	 *            The policy mappings
	 */
	public void load(PolicyMappings policyMappings) {

		ASN1Sequence policyMappingsSeq = (ASN1Sequence) policyMappings.toASN1Primitive();

		// convert and sort
		ASN1Encodable[] asn1EncArray = policyMappingsSeq.toArray();
		PolicyMapping[] policyMappingsArray = new PolicyMapping[asn1EncArray.length];
		for (int i = 0; i < asn1EncArray.length; i++) {
			policyMappingsArray[i] = PolicyMapping.getInstance(asn1EncArray[i]);
		}
		Arrays.sort(policyMappingsArray, new IssuerDomainPolicyComparator());

		data = new Object[policyMappingsArray.length][2];

		int i = 0;
		for (PolicyMapping policyMapping : policyMappingsArray) {
			data[i][0] = policyMapping;
			data[i][1] = policyMapping;
			i++;
		}

		fireTableDataChanged();
	}

	/**
	 * Get the number of columns in the table.
	 *
	 * @return The number of columns
	 */
	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	/**
	 * Get the number of rows in the table.
	 *
	 * @return The number of rows
	 */
	@Override
	public int getRowCount() {
		return data.length;
	}

	/**
	 * Get the name of the column at the given position.
	 *
	 * @param col
	 *            The column position
	 * @return The column name
	 */
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}

	/**
	 * Get the cell value at the given row and column position.
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return The cell value
	 */
	@Override
	public Object getValueAt(int row, int col) {
		return data[row][col];
	}

	/**
	 * Get the class at of the cells at the given column position.
	 *
	 * @param col
	 *            The column position
	 * @return The column cells' class
	 */
	@Override
	public Class<?> getColumnClass(int col) {
		return PolicyMappings.class;
	}

	/**
	 * Is the cell at the given row and column position editable?
	 *
	 * @param row
	 *            The row position
	 * @param col
	 *            The column position
	 * @return True if the cell is editable, false otherwise
	 */
	@Override
	public boolean isCellEditable(int row, int col) {
		return false;
	}

	static class IssuerDomainPolicyComparator implements Comparator<PolicyMapping> {
		@Override
		public int compare(PolicyMapping mapping1, PolicyMapping mapping2) {
			return objectIdComparator.compare(mapping1.getIssuerDomainPolicy(), mapping2.getIssuerDomainPolicy());
		}
	}

	static class SubjectDomainPolicyComparator implements Comparator<PolicyMapping> {
		@Override
		public int compare(PolicyMapping mapping1, PolicyMapping mapping2) {
			return objectIdComparator.compare(mapping1.getSubjectDomainPolicy(), mapping2
					.getSubjectDomainPolicy());
		}
	}
}
