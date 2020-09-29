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
package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.kse.crypto.CryptoException;
import org.kse.crypto.KeyInfo;
import org.kse.crypto.secretkey.SecretKeyType;
import org.kse.crypto.secretkey.SecretKeyUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Displays the details of a secret key.
 *
 */
public class DViewSecretKey extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JLabel jlAlgorithm;
	private JTextField jtfAlgorithm;
	private JLabel jlKeySize;
	private JTextField jtfKeySize;
	private JLabel jlFormat;
	private JTextField jtfFormat;
	private JLabel jlEncoded;
	private JTextArea jtaEncoded;
	private JScrollPane jspEncoded;
	private JButton jbCancel;
	private JButton jbOK;

	private SecretKey secretKey;

	private boolean editable;
	private boolean keyHasChanged = false;

	/**
	 * Creates a new DViewSecretKey dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param secretKey
	 *            Secret key to display
	 * @param editable
	 *            Secret key can be edited/replaced
	 */
	public DViewSecretKey(JFrame parent, String title, SecretKey secretKey, boolean editable) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.secretKey = secretKey;
		this.editable = editable;
		initComponents();
	}

	/**
	 * Creates new DViewSecretKey dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param modality
	 *            Dialog modality
	 * @param secretKey
	 *            Secret key to display
	 * @param editable
	 *            Secret key can be edited/replaced
	 * @throws CryptoException
	 *             A problem was encountered getting the secret key's details
	 */
	public DViewSecretKey(JDialog parent, String title, ModalityType modality, SecretKey secretKey, boolean editable)
			throws CryptoException {
		super(parent, title, modality);
		this.secretKey = secretKey;
		this.editable = editable;
		initComponents();
	}

	private void initComponents() {

		jlAlgorithm = new JLabel(res.getString("DViewSecretKey.jlAlgorithm.text"));

		jtfAlgorithm = new JTextField();
		jtfAlgorithm.setEditable(false);
		jtfAlgorithm.setToolTipText(res.getString("DViewSecretKey.jtfAlgorithm.tooltip"));

		jlKeySize = new JLabel(res.getString("DViewSecretKey.jlKeySize.text"));

		jtfKeySize = new JTextField();
		jtfKeySize.setEditable(false);
		jtfKeySize.setToolTipText(res.getString("DViewSecretKey.jtfKeySize.tooltip"));

		jlFormat = new JLabel(res.getString("DViewSecretKey.jlFormat.text"));

		jtfFormat = new JTextField();
		jtfFormat.setEditable(false);
		jtfFormat.setToolTipText(res.getString("DViewSecretKey.jtfFormat.tooltip"));

		jlEncoded = new JLabel(res.getString("DViewSecretKey.jlEncoded.text"));

		jtaEncoded = new JTextArea();
		jtaEncoded.setFont(new Font(Font.MONOSPACED, Font.PLAIN, LnfUtil.getDefaultFontSize()));
		if (!editable) {
			jtaEncoded.setBackground(jtfFormat.getBackground());
		}
		jtaEncoded.setEditable(editable);
		jtaEncoded.setLineWrap(true);
		jtaEncoded.putClientProperty("JTextArea.infoBackground", Boolean.TRUE);
		jtaEncoded.setToolTipText(res.getString("DViewSecretKey.jtfEncoded.tooltip"));

		jspEncoded = PlatformUtil.createScrollPane(jtaEncoded,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspEncoded.setBorder(jtfFormat.getBorder());

		jbCancel = new JButton(res.getString("DViewSecretKey.jbCancel.text"));
		jbOK = new JButton(res.getString("DViewSecretKey.jbOK.text"));

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[]unrel[]"));
		pane.add(jlAlgorithm, "");
		pane.add(jtfAlgorithm, "growx, pushx, wrap");
		pane.add(jlKeySize, "");
		pane.add(jtfKeySize, "growx, pushx, wrap");
		pane.add(jlFormat, "");
		pane.add(jtfFormat, "growx, pushx, wrap");
		pane.add(jlEncoded, "");
		pane.add(jspEncoded, "width 260lp:260lp:260lp, height 50lp:50lp:50lp, wrap"); // sp determines dialog size
		pane.add(new JSeparator(), "spanx, growx, wrap rel:push");
		if (editable) {
			pane.add(jbCancel, "spanx, split 2, tag cancel");
			pane.add(jbOK, "tag ok");
		} else {
			pane.add(jbOK, "spanx, tag ok");
		}

		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		setResizable(false);

		populateDialog();

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

	private void populateDialog() {
		KeyInfo keyInfo = SecretKeyUtil.getKeyInfo(secretKey);

		String algorithm = keyInfo.getAlgorithm();

		// Try and get friendly algorithm name
		SecretKeyType secretKeyType = SecretKeyType.resolveJce(algorithm);

		if (secretKeyType != null) {
			algorithm = secretKeyType.friendly();
		}

		jtfAlgorithm.setText(algorithm);

		Integer keyLength = keyInfo.getSize();

		if (keyLength != null) {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewSecretKey.jtfKeySize.text"), "" + keyLength));
		} else {
			jtfKeySize.setText(MessageFormat.format(res.getString("DViewSecretKey.jtfKeySize.text"), "?"));
		}

		jtfFormat.setText(secretKey.getFormat());

		jtaEncoded.setText(new BigInteger(1, secretKey.getEncoded()).toString(16).toUpperCase());
		jtaEncoded.setCaretPosition(0);
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void okPressed() {

		if (editable) {
			String text = jtaEncoded.getText();
			try {
				byte[] newKeyRaw = Hex.decode(text.replace(':', ' '));
				SecretKey newKey = new SecretKeySpec(newKeyRaw, 0, newKeyRaw.length, secretKey.getAlgorithm());
				this.secretKey = newKey;
				this.keyHasChanged = true;
			} catch (DecoderException e) {
				JOptionPane.showMessageDialog(this, res.getString("DViewSecretKey.NotAValidHexString.message"),
						getTitle(), JOptionPane.ERROR_MESSAGE);
				return;
			} catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
				JOptionPane.showMessageDialog(this, res.getString("DViewSecretKey.NotAValidKey.message"),
						getTitle(), JOptionPane.ERROR_MESSAGE);
				return;
			}
		}

		closeDialog();
	}

	public boolean keyHasChanged() {
		return keyHasChanged;
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		final SecretKey secretKey = SecretKeyUtil.generateSecretKey(SecretKeyType.AES, 256);
		DViewSecretKey dialog = new DViewSecretKey(new JFrame(), "Generate Secret Key", secretKey, true);
		DialogViewer.run(dialog);
	}
}
