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
package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;

/**
 * Displays the fields of a asymmetric key.
 *
 */
public class DViewAsymmetricKeyFields extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpFields;
	private JPanel jpFieldsList;
	private JLabel jlFields;
	private JList<Field> jltFields;
	private JPanel jpFieldValue;
	private JLabel jlFieldValue;
	private JPanel jpFieldValueTextArea;
	private JScrollPane jspFieldValue;
	private JTextArea jtaFieldValue;
	private JPanel jpOK;
	private JButton jbOK;

	private Key key;

	/**
	 * Creates new DViewAsymmetricKeyFields dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param rsaPublicKey
	 *            RSA public key to display fields of
	 */
	public DViewAsymmetricKeyFields(JDialog parent, String title, RSAPublicKey rsaPublicKey) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		key = rsaPublicKey;
		initFields();
	}

	/**
	 * Creates new DViewAsymmetricKeyFields dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param dsaPublicKey
	 *            DSA public key to display fields of
	 */
	public DViewAsymmetricKeyFields(JDialog parent, String title, DSAPublicKey dsaPublicKey) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		key = dsaPublicKey;
		initFields();
	}

	/**
	 * Creates new DViewAsymmetricKeyFields dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param rsaPrivateKey
	 *            RSA private key to display fields of
	 */
	public DViewAsymmetricKeyFields(JDialog parent, String title, RSAPrivateKey rsaPrivateKey) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		key = rsaPrivateKey;
		initFields();
	}

	/**
	 * Creates new DViewAsymmetricKeyFields dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param dsaPrivateKey
	 *            DSA private key to display fields of
	 */
	public DViewAsymmetricKeyFields(JDialog parent, String title, DSAPrivateKey dsaPrivateKey) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		key = dsaPrivateKey;
		initFields();
	}

	private void initFields() {
		jlFields = new JLabel(res.getString("DViewAsymmetricKeyFields.jlFields.text"));

		jltFields = new JList<Field>();
		jltFields.setToolTipText(res.getString("DViewAsymmetricKeyFields.jltFields.tooltip"));
		jltFields.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		jltFields.setBorder(new EtchedBorder());

		jltFields.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewAsymmetricKeyFields.this);
					updateFieldValue();
				} finally {
					CursorUtil.setCursorFree(DViewAsymmetricKeyFields.this);
				}
			}
		});

		jpFieldsList = new JPanel(new BorderLayout(5, 5));
		jpFieldsList.add(jlFields, BorderLayout.NORTH);
		jpFieldsList.add(jltFields, BorderLayout.CENTER);

		jpFieldValue = new JPanel(new BorderLayout(5, 5));

		jlFieldValue = new JLabel(res.getString("DViewAsymmetricKeyFields.jlFieldValue.text"));

		jpFieldValue.add(jlFieldValue, BorderLayout.NORTH);

		jtaFieldValue = new JTextArea();
		jtaFieldValue.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		jtaFieldValue.setEditable(false);
		jtaFieldValue.setToolTipText(res.getString("DViewAsymmetricKeyFields.jtaFieldValue.tooltip"));
		// JGoodies - keep uneditable color same as editable
		jtaFieldValue.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);

		jspFieldValue = PlatformUtil.createScrollPane(jtaFieldValue, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		jpFieldValueTextArea = new JPanel(new BorderLayout(10, 10));
		jpFieldValueTextArea.setPreferredSize(new Dimension(275, 200));
		jpFieldValueTextArea.add(jspFieldValue, BorderLayout.CENTER);

		jpFieldValue.add(jpFieldValueTextArea, BorderLayout.CENTER);

		jpFields = new JPanel(new BorderLayout(5, 5));
		jpFields.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jpFields.add(jpFieldsList, BorderLayout.WEST);
		jpFields.add(jpFieldValue, BorderLayout.CENTER);

		jbOK = new JButton(res.getString("DViewAsymmetricKeyFields.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		populateFields();

		getContentPane().add(jpFields, BorderLayout.CENTER);
		getContentPane().add(jpOK, BorderLayout.SOUTH);

		setResizable(false);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				jbOK.requestFocus();
			}
		});
	}

	private void populateFields() {
		Field[] fields = null;

		if (key instanceof RSAPublicKey) {
			RSAPublicKey rsaPub = (RSAPublicKey) key;

			fields = new Field[] {
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaPublicExponent.text"),
							rsaPub.getPublicExponent()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubRsaModulus.text"),
							rsaPub.getModulus()) };
		} else if (key instanceof DSAPublicKey) {
			DSAPublicKey dsaPub = (DSAPublicKey) key;
			DSAParams dsaParams = dsaPub.getParams();

			fields = new Field[] {
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeModulusP.text"),
							dsaParams.getP()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPrimeQ.text"), dsaParams.getQ()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaGeneratorG.text"),
							dsaParams.getG()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PubDsaPublicKeyY.text"), dsaPub.getY()) };
		} else if (key instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsaPvk = (RSAPrivateCrtKey) key;

			fields = new Field[] {
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPublicExponent.text"),
							rsaPvk.getPublicExponent()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"),
							rsaPvk.getModulus()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeP.text"),
							rsaPvk.getPrimeP()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeQ.text"),
							rsaPvk.getPrimeQ()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentP.text"),
							rsaPvk.getPrimeExponentP()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrimeExponentQ.text"),
							rsaPvk.getPrimeExponentQ()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaCrtCoefficient.text"),
							rsaPvk.getCrtCoefficient()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"),
							rsaPvk.getPrivateExponent()) };
		} else if (key instanceof RSAPrivateKey) {
			RSAPrivateKey rsaPvk = (RSAPrivateKey) key;

			fields = new Field[] {
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaModulus.text"),
							rsaPvk.getModulus()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivRsaPrivateExponent.text"),
							rsaPvk.getPrivateExponent()) };
		} else if (key instanceof DSAPrivateKey) {
			DSAPrivateKey dsaPvk = (DSAPrivateKey) key;
			DSAParams dsaParams = dsaPvk.getParams();

			fields = new Field[] {
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeModulusP.text"),
							dsaParams.getP()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaPrimeQ.text"), dsaParams.getQ()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaGeneratorG.text"),
							dsaParams.getG()),
					new Field(res.getString("DViewAsymmetricKeyFields.jltFields.PrivDsaSecretExponentX.text"),
							dsaPvk.getX()) };
		}

		if (fields != null) {
			jltFields.setListData(fields);
			jltFields.setSelectedIndex(0);
		}
	}

	private void updateFieldValue() {
		int selectedRow = jltFields.getSelectedIndex();

		if (selectedRow == -1) {
			jtaFieldValue.setText("");
		} else {
			Field field = jltFields.getSelectedValue();

			jtaFieldValue.setText(field.getFormattedValue());
			jtaFieldValue.setCaretPosition(0);
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private class Field {
		private static final int FORMATTED_FIELD_LINE_MAX_LENGTH = 32;

		private String name;
		private BigInteger value;

		public Field(String name, BigInteger value) {
			this.name = name;
			this.value = value;
		}

		public String getName() {
			return name;
		}

		public BigInteger getValue() {
			return value;
		}

		public String getFormattedValue() {
			/*
			 * Get formatted field value, interface Hex pre-fixed with '0x'
			 * divided over lines of length FORMATTED_FIELD_LINE_LENGTH
			 */
			String value = "0x" + getValue().toString(16).toUpperCase();

			StringBuffer sb = new StringBuffer();

			for (int i = 0; i < value.length(); i++) {
				sb.append(value.charAt(i));

				if ((i + 1) % FORMATTED_FIELD_LINE_MAX_LENGTH == 0) {
					sb.append('\n');
				}
			}

			return sb.toString();
		}

		@Override
		public String toString() {
			return getName();
		}
	}
}
