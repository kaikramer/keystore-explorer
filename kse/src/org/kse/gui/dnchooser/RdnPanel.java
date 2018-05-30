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
package org.kse.gui.dnchooser;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * GUI item for RDN.
 *
 */
public class RdnPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JComboBox<?> comboBox;
	private JLabel label;
	private JTextField textField;
	private JButton plus;
	private JButton minus;
	private RdnPanelList parent;

	public RdnPanel(JComboBox<?> comboBox, String selectedItem, String textFieldText, RdnPanelList list, boolean editable) {

		this.comboBox = comboBox;
		if (editable) {
			this.comboBox.setSelectedItem(selectedItem);
			this.comboBox.setEditable(false);
			add(this.comboBox);
		} else {
			this.label = new JLabel(selectedItem);
			add(this.label);
		}

		this.parent = list;

		this.textField = new JTextField(30);
		this.textField.setText(textFieldText);
		this.textField.setEditable(editable);
		add(this.textField);

		if (editable) {
			this.plus = new JButton(new AddEntryAction());
			add(this.plus);

			this.minus = new JButton(new RemoveEntryAction());
			add(this.minus);
		}
	}

	public JComboBox<?> getComboBox() {
		return comboBox;
	}

	public class AddEntryAction extends AbstractAction {

		private static final long serialVersionUID = 1L;

		public AddEntryAction() {
			super("+");
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			parent.cloneEntry(RdnPanel.this);
		}

	}

	public class RemoveEntryAction extends AbstractAction {

		private static final long serialVersionUID = 1L;

		public RemoveEntryAction() {
			super("-");
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			parent.removeItem(RdnPanel.this);
		}
	}

	public void enableAdd(boolean enabled) {
		if (this.plus != null) {
			this.plus.setEnabled(enabled);
		}
	}

	public void enableMinus(boolean enabled) {
		if (this.minus != null) {
			this.minus.setEnabled(enabled);
		}
	}

	public String getAttributeName() {
		return comboBox.getSelectedItem().toString();
	}

	public String getAttributeValue() {
		return textField.getText();
	}
}