package org.kse.gui.crypto;

import java.util.BitSet;

import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

import org.bouncycastle.asn1.DERBitString;

public class JBitFlag extends JPanel {
	private static final long serialVersionUID = 7123999039756742119L;

	private JCheckBox[] flags;
	private String[] flagNames;
	private JPanel[] columns;
	
	public JBitFlag(int columnLength, String... flagNames) {
		this.columns = new JPanel[columnLength];
		this.flagNames = flagNames;
		initComponent();
	}
	
	public JBitFlag(int columnLength, byte[] value, String... flagNames) {
		this(columnLength, flagNames);
		prepopulateWithValue(value);
	}

	private void initComponent() {
		for (int i = 0; i < columns.length; i++) {
			columns[i] = new JPanel();
			columns[i].setLayout(new BoxLayout(columns[i], BoxLayout.Y_AXIS));
			this.add(columns[i]);
		}

		flags = new JCheckBox[flagNames.length];
		int rowNumber = 0;
		for (int i = 0; i < flagNames.length; i++) {
			flags[i] = new JCheckBox(flagNames[i]);
			columns[rowNumber].add(flags[i]);
			rowNumber =  ++rowNumber < columns.length? rowNumber: 0;
		}

		this.setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
	}

	private void prepopulateWithValue(byte[] value) {
		DERBitString bitString = new DERBitString(value);
		this.setFlags(bitString);
	}
	
	public DERBitString getObject() {
		BitSet bitSet = new BitSet(flags.length);
		for (int i = 0; i < flags.length; i++) {
			bitSet.set(i, flags[i].isSelected());
		}
		
		return new DERBitString(bitSet.toByteArray());
	}

	public void setFlags(DERBitString bitString) {
		BitSet bitSet = BitSet.valueOf(bitString.getOctets());
		for (int i = 0; i < flags.length; i++) {
			flags[i].setSelected(bitSet.get(i));
		}
	}
}
