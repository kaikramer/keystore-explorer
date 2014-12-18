/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2014 Kai Kramer
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
package net.sf.keystore_explorer.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Provider;
import java.security.Security;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

/**
 * Dialog used to retrieve the type to use in the creation of a new KeyStore.
 *
 */
public class DOpenPkcs11KeyStore extends JEscDialog {
	private static final long serialVersionUID = 3188619209680032281L;

	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JRadioButton jrbUseExisting;
	private JLabel jlSelectProvider;
	private JComboBox<String> jcbPkcs11Provider;

	private JRadioButton jrbCreateNew;
	private JLabel jlP11Library;
	private JTextField jtfP11Library;
	private JButton jbP11LibraryBrowse;
	private JLabel jlSlotListIndex;
	private JSpinner jspSlotListIndex;
	
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private Provider selectedProvider;

	/**
	 * Creates a new DOpenPkcs11KeyStore dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DOpenPkcs11KeyStore(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DOpenPkcs11KeyStore.Title"));
		initComponents();
	}

	private void initComponents() {
		
		jrbUseExisting = new JRadioButton(res.getString("DOpenPkcs11KeyStore.jrbUseExisting.text"), false);
		PlatformUtil.setMnemonic(jrbUseExisting, res.getString("DOpenPkcs11KeyStore.jrbUseExisting.mnemonic").charAt(0));
		
		jlSelectProvider = new JLabel(res.getString("DOpenPkcs11KeyStore.jlSelectProvider.text"));
		
		jcbPkcs11Provider = new JComboBox<String>(new DefaultComboBoxModel<String>(getPkcs11Provider()));
		jcbPkcs11Provider.setToolTipText(res.getString("DOpenPkcs11KeyStore.jcbPkcs11Provider.tooltip"));
		
		jrbCreateNew = new JRadioButton(res.getString("DOpenPkcs11KeyStore.jrbCreateNew.text"), false);
		PlatformUtil.setMnemonic(jrbCreateNew, res.getString("DOpenPkcs11KeyStore.jrbCreateNew.mnemonic").charAt(0));
		
		jlP11Library = new JLabel(res.getString("DOpenPkcs11KeyStore.jlP11Library.text"));
		
		jtfP11Library = new JTextField(30);
		jtfP11Library.setToolTipText(res.getString("DOpenPkcs11KeyStore.jtfP11Library.tooltip"));
		
		jbP11LibraryBrowse = new JButton();
		jbP11LibraryBrowse.setIcon(new ImageIcon(getClass().getResource(res.getString("DOpenPkcs11KeyStore.jbP11LibraryBrowse.image"))));
		jbP11LibraryBrowse.setToolTipText(res.getString("DOpenPkcs11KeyStore.jbP11LibraryBrowse.tooltip"));

		jlSlotListIndex = new JLabel(res.getString("DOpenPkcs11KeyStore.jlSlotListIndex.text"));

		jspSlotListIndex = new JSpinner();
		jspSlotListIndex.setModel(new SpinnerNumberModel(0, 0, 65000, 1));
		jspSlotListIndex.setToolTipText(res.getString("DOpenPkcs11KeyStore.jspSlotListIndex.tooltip"));
		
		jbOK = new JButton(res.getString("DOpenPkcs11KeyStore.jbOK.text"));

		jbCancel = new JButton(res.getString("DOpenPkcs11KeyStore.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[para]rel[]rel[grow][]", ""));
        pane.add(jrbUseExisting, "spanx, wrap");
        pane.add(jlSelectProvider, "skip");
        pane.add(jcbPkcs11Provider, "growx, wrap unrel");
        pane.add(jrbCreateNew, "spanx, wrap");
        pane.add(jlP11Library, "skip");
        pane.add(jtfP11Library, "");
        pane.add(jbP11LibraryBrowse, "wrap");
        pane.add(jlSlotListIndex, "skip");
        pane.add(jspSlotListIndex, "wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private String[] getPkcs11Provider() {
		
		Provider[] providers = Security.getProviders("KeyStore.PKCS11");
		String[] providerNames = new String[providers.length];
		
		for (int i = 0; i < providers.length; i++) {
			providerNames[i] = providers[i].getName();
		}
		
		return providerNames;
	}

	private void okPressed() {
		
		String providerName = (String) jcbPkcs11Provider.getSelectedItem();
		selectedProvider = Security.getProvider(providerName);
		
		if (selectedProvider == null) {
			JOptionPane.showMessageDialog(this,
					res.getString("DOpenPkcs11KeyStore.providerNotInstalled.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
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
	
	public Provider getSelectedProvider() {
		return this.selectedProvider;
	}
}
