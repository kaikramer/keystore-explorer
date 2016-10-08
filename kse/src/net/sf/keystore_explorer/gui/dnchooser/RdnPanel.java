/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package net.sf.keystore_explorer.gui.dnchooser;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class RdnPanel extends JPanel {

	private JComboBox comboBox;
	private JLabel label;
	private JTextField textField;
	private JButton plus;
	private JButton minus;
	private RdnPanelList parent;

	public RdnPanel(JComboBox comboBox, String selectedItem, String textFieldText, RdnPanelList list, boolean editable) {

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

	public JComboBox getComboBox() {
		return comboBox;
	}

	public class AddEntryAction extends AbstractAction {

		public AddEntryAction() {
			super("+");
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			parent.cloneEntry(RdnPanel.this);
		}

	}

	public class RemoveEntryAction extends AbstractAction {

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