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
package org.kse.gui.dnchooser;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.kse.crypto.x509.KseX500NameStyle;
import org.kse.utilities.StringUtils;

/**
 * GUI item for RDN.
 *
 */
public class RdnPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JComboBox<?> comboBox;
	private JLabel label;
	private JTextField textField;
	private static final String[] DEFAULT_COMBO_ENTRIES = OidDisplayNameMapping.getDisplayNames();

	public RdnPanel(RDN rdn) {
		this(new JComboBox<Object>(DEFAULT_COMBO_ENTRIES), DEFAULT_COMBO_ENTRIES[0], "", true);
		setRDN(rdn);
	}

	public RdnPanel(JComboBox<?> comboBox, String selectedItem, String textFieldText, boolean editable) {
		this.comboBox = comboBox;
		if (editable) {
			this.comboBox.setSelectedItem(selectedItem);
			this.comboBox.setEditable(false);
			add(this.comboBox);
		} else {
			this.label = new JLabel(selectedItem);
			add(this.label);
		}

		this.textField = new JTextField(30);
		this.textField.setText(textFieldText);
		this.textField.setEditable(editable);
		add(this.textField);
	}

	public void setRDN(RDN rdn) {
		if (rdn == null || rdn.getFirst() == null) {
			return;
		}
		comboBox.setSelectedItem(OidDisplayNameMapping.getDisplayNameForOid(rdn.getFirst().getType().toString()));
		textField.setText(rdn.getFirst().getValue().toString());
	}

	public JComboBox<?> getComboBox() {
		return comboBox;
	}

	public String getAttributeName() {
		return comboBox.getSelectedItem().toString();
	}

	public String getAttributeValue() {
		return textField.getText();
	}

	public boolean isEditable() {
		return this.textField.isEditable();
	}
	
	public RDN getRDN(boolean noEmptyRdns) {
		ASN1ObjectIdentifier attrType = OidDisplayNameMapping.getOidForDisplayName(getAttributeName());
		if (noEmptyRdns && StringUtils.trimAndConvertEmptyToNull(getAttributeValue()) == null) {
			return null;
		}
		ASN1Encodable attrValue = KseX500NameStyle.INSTANCE.stringToValue(attrType, getAttributeValue());
		return new RDN(new AttributeTypeAndValue(attrType, attrValue));
		
	}
	
	public static String toString(RDN value) {
		if (value == null || value.getFirst() == null) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for(AttributeTypeAndValue typeAndValue : value.getTypesAndValues()) {
			builder
				.append(OidDisplayNameMapping.getDisplayNameForOid(typeAndValue.getType().toString()))
				.append(typeAndValue.getValue().toString())
				.append(",");
		}
		builder.setLength(builder.length()-1);
		return builder.toString();
	}
}