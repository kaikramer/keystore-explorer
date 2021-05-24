/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
package org.kse.gui.dialogs.extensions;

import java.awt.Container;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.oid.JObjectId;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a secret key.
 *
 */
public class DCustomExtension extends DExtension {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

	private JLabel jlCustomOID;
	private JObjectId joidCustomOID;

//	private JLabel jlValueType;
//	private JComboBox<String> jcbValueType;

	private JLabel jlEncodedHexValue;
	private JTextArea jtaEncodedHexValue;
	private JScrollPane jspEncodedHexValue;
	private JButton jbCancel;
	private JButton jbOK;

	byte[] value;

	/**
	 * Creates new DCustomExtension dialog where the parent is a dialog.
	 *
	 * @param parent Parent dialog
	 */
	public DCustomExtension(JDialog parent) {
		super(parent);
		setTitle(res.getString("DCustomExtension.Title"));
		initComponents();
	}

	private void initComponents() {

		jlCustomOID = new JLabel(res.getString("DCustomExtension.jlCustomOID.text"));

		joidCustomOID = new JObjectId("DCustomExtension.joidCustomOID.title");
		joidCustomOID.setToolTipText(res.getString("DCustomExtension.joidCustomOID.tooltip"));

//		jlValueType = new JLabel(res.getString("DCustomExtension.jlValueType.text"));
//
//		jcbValueType = new JComboBox<>();
//		jcbValueType.setModel(new DefaultComboBoxModel<>(getValueTypeOptions()));
//		jcbValueType.setToolTipText(res.getString("DGenerateKeyPair.jcbECCurveSet.tooltip"));

		jlEncodedHexValue = new JLabel(res.getString("DCustomExtension.jlEncodedHexValue.text"));

		jtaEncodedHexValue = new JTextArea();
		jtaEncodedHexValue.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		jtaEncodedHexValue.setLineWrap(true);
		jtaEncodedHexValue.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtaEncodedHexValue.setToolTipText(res.getString("DCustomExtension.jtaEncodedHexValue.tooltip"));

		jspEncodedHexValue = PlatformUtil.createScrollPane(jtaEncodedHexValue,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		//jspEncodedHexValue.setBorder(jtfOID.getBorder());

		jbCancel = new JButton(res.getString("DCustomExtension.jbCancel.text"));
		jbOK = new JButton(res.getString("DCustomExtension.jbOK.text"));

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlCustomOID, "");
		pane.add(joidCustomOID, "growx, pushx, wrap");
		pane.add(jlEncodedHexValue, "");
		pane.add(jspEncodedHexValue, "growx, pushx, height 80lp:80lp:80lp, wrap");
		//pane.add(jspEncodedHexValue, "width 260lp:260lp:260lp, height 50lp:50lp:50lp, wrap"); // sp determines dialog size
		pane.add(new JSeparator(), "spanx, growx, wrap rel:push");
		pane.add(jbCancel, "spanx, split 2, tag cancel");
		pane.add(jbOK, "tag ok");

		jbOK.addActionListener(evt -> okPressed());

		jbCancel.addActionListener(evt -> cancelPressed());

		setResizable(false);

		jtaEncodedHexValue.setCaretPosition(0);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getRootPane().setDefaultButton(jbOK);

		pack();

		SwingUtilities.invokeLater(() -> jbOK.requestFocus());
	}

//	private String[] getValueTypeOptions() {
//		return new String[] {
//				res.getString("DCustomExtension.jcbValueType.options.empty"),
//				res.getString("DCustomExtension.jcbValueType.options.string"),
//				res.getString("DCustomExtension.jcbValueType.options.hex")
//		};
//	}

	private void cancelPressed() {
		closeDialog();
	}

	private void okPressed() {
		String text = jtaEncodedHexValue.getText();

		// TODO check for empty OID or maybe better: include OID editor

		byte[] extValue;
		try {
			// empty extension value is possible, e.g. for id-pkix-ocsp-nocheck from RFC 6960
			extValue = Hex.decode(text.replace(':', ' '));
		} catch (DecoderException e) {
			JOptionPane.showMessageDialog(this, res.getString("DCustomExtension.NotAValidHexString.message"),
					getTitle(), JOptionPane.ERROR_MESSAGE);
			return;
		}

		value = extValue;

		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	@Override
	public byte[] getValue() {
		return value;
	}

	@Override
	public String getOid() {
		return joidCustomOID.getObjectId().getId();
	}

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		DialogViewer.prepare();
		DCustomExtension dialog = new DCustomExtension(new JEscDialog());
		DialogViewer.run(dialog);
	}
}
