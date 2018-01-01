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
package org.kse.gui.crypto;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UIManager;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.kse.ApplicationSettings;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.dnchooser.DistinguishedNameChooser;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to view or edit a distinguished name.
 *
 */
public class DDistinguishedNameChooser extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private DistinguishedNameChooser distinguishedNameChooser;
	private JButton jbOK;
	private JButton jbCancel;
	private JPanel jpButtons;

	private boolean editable;
	private X500Name distinguishedName;

	private ApplicationSettings applicationSettings = ApplicationSettings.getInstance();

	/**
	 * Creates a new DDistinguishedNameChooser dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param distinguishedName
	 *            The distinguished name
	 * @param editable
	 *            Is dialog editable?
	 */
	public DDistinguishedNameChooser(JFrame parent, String title, X500Name distinguishedName, boolean editable) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.distinguishedName = distinguishedName;
		this.editable = editable;
		initComponents();
	}

	/**
	 * Creates a new DDistinguishedNameChooser dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param distinguishedName
	 *            The distinguished name
	 * @param editable
	 *            Is dialog editable?
	 */
	public DDistinguishedNameChooser(JDialog parent, String title, X500Name distinguishedName, boolean editable) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.distinguishedName = distinguishedName;
		this.editable = editable;
		initComponents();
	}

	private void initComponents() {

		String defaultDN = applicationSettings.getDefaultDN();

		jbOK = new JButton(res.getString("DDistinguishedNameChooser.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		if (editable) {
			distinguishedNameChooser = new DistinguishedNameChooser(distinguishedName, true, defaultDN);

			jbCancel = new JButton(res.getString("DDistinguishedNameChooser.jbCancel.text"));
			jbCancel.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					cancelPressed();
				}
			});
			jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
					CANCEL_KEY);
			jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
				private static final long serialVersionUID = 1L;

				@Override
				public void actionPerformed(ActionEvent evt) {
					cancelPressed();
				}
			});

			jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);
		} else {

			distinguishedNameChooser = new DistinguishedNameChooser(distinguishedName, false, defaultDN);
			jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, false);
		}

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]"));
		pane.add(distinguishedNameChooser, "left, spanx, wrap para");
		pane.add(new JSeparator(), "spanx, growx, wrap");
		pane.add(jpButtons, "right, spanx");

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				okPressed();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Get selected distinguished name.
	 *
	 * @return Distinguished name, or null if none
	 */
	public X500Name getDistinguishedName() {
		return distinguishedName;
	}

	private void okPressed() {
		if (editable) {

			X500Name dn = distinguishedNameChooser.getDN();

			if (dn == null) {
				return;
			}

			if (dn.toString().isEmpty()) {
				JOptionPane.showMessageDialog(this,
						res.getString("DDistinguishedNameChooser.ValueReqAtLeastOneField.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}

			for (RDN rdn : dn.getRDNs(BCStyle.C)) {
				String countryCode = rdn.getFirst().getValue().toString();
				if ((countryCode != null) && (countryCode.length() != 2)) {
					JOptionPane.showMessageDialog(this,
							res.getString("DDistinguishedNameChooser.CountryCodeTwoChars.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
					return;
				}
			}

			distinguishedName = dn;
		}

		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DDistinguishedNameChooser dialog = new DDistinguishedNameChooser(new javax.swing.JFrame(), "DN Chooser",
							new X500Name("CN=test, OU=Development, OU=Software, O=ACME Ltd., C=UK, E=test@example.com"),
							true);
					dialog.addWindowListener(new java.awt.event.WindowAdapter() {
						@Override
						public void windowClosing(java.awt.event.WindowEvent e) {
							System.exit(0);
						}

						@Override
						public void windowDeactivated(java.awt.event.WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
