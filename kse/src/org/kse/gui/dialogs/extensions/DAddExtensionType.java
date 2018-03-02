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
package org.kse.gui.dialogs.extensions;

import static org.kse.crypto.x509.X509ExtensionType.AUTHORITY_INFORMATION_ACCESS;
import static org.kse.crypto.x509.X509ExtensionType.AUTHORITY_KEY_IDENTIFIER;
import static org.kse.crypto.x509.X509ExtensionType.BASIC_CONSTRAINTS;
import static org.kse.crypto.x509.X509ExtensionType.CERTIFICATE_POLICIES;
import static org.kse.crypto.x509.X509ExtensionType.EXTENDED_KEY_USAGE;
import static org.kse.crypto.x509.X509ExtensionType.INHIBIT_ANY_POLICY;
import static org.kse.crypto.x509.X509ExtensionType.ISSUER_ALTERNATIVE_NAME;
import static org.kse.crypto.x509.X509ExtensionType.KEY_USAGE;
import static org.kse.crypto.x509.X509ExtensionType.NAME_CONSTRAINTS;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_BASE_URL;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_CA_POLICY_URL;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_CA_REVOCATION_URL;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_CERTIFICATE_RENEWAL_URL;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_CERTIFICATE_TYPE;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_COMMENT;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_REVOCATION_URL;
import static org.kse.crypto.x509.X509ExtensionType.NETSCAPE_SSL_SERVER_NAME;
import static org.kse.crypto.x509.X509ExtensionType.POLICY_CONSTRAINTS;
import static org.kse.crypto.x509.X509ExtensionType.POLICY_MAPPINGS;
import static org.kse.crypto.x509.X509ExtensionType.PRIVATE_KEY_USAGE_PERIOD;
import static org.kse.crypto.x509.X509ExtensionType.SUBJECT_ALTERNATIVE_NAME;
import static org.kse.crypto.x509.X509ExtensionType.SUBJECT_INFORMATION_ACCESS;
import static org.kse.crypto.x509.X509ExtensionType.SUBJECT_KEY_IDENTIFIER;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;

/**
 * Dialog used to retrieve the type to use in the addition of a new extension.
 *
 */
public class DAddExtensionType extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";
	private static final X509ExtensionType[] SUPPORTED_EXTENSIONS = { AUTHORITY_INFORMATION_ACCESS,
			AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, CERTIFICATE_POLICIES, EXTENDED_KEY_USAGE, INHIBIT_ANY_POLICY,
			ISSUER_ALTERNATIVE_NAME, KEY_USAGE, NAME_CONSTRAINTS, NETSCAPE_BASE_URL, NETSCAPE_CA_POLICY_URL,
			NETSCAPE_CA_REVOCATION_URL, NETSCAPE_CERTIFICATE_RENEWAL_URL, NETSCAPE_CERTIFICATE_TYPE, NETSCAPE_COMMENT,
			NETSCAPE_REVOCATION_URL, NETSCAPE_SSL_SERVER_NAME, POLICY_CONSTRAINTS, POLICY_MAPPINGS,
			PRIVATE_KEY_USAGE_PERIOD, SUBJECT_ALTERNATIVE_NAME, SUBJECT_INFORMATION_ACCESS, SUBJECT_KEY_IDENTIFIER };

	private JPanel jpExtensionTypes;
	private JLabel jlExtensionTypes;
	private JList<X509ExtensionType> jltExtensionTypes;
	private JScrollPane jspExtensionTypes;
	private JCheckBox jcbCriticalExtension;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private X509Extension extensions;
	private X509ExtensionType extension;
	private boolean isCritical;

	/**
	 * Creates new DAddExtensionType dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param extensions
	 *            Current set of extensions
	 */
	public DAddExtensionType(JDialog parent, X509Extension extensions) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DAddExtensionType.Title"));
		this.extensions = extensions;
		initComponents();
	}

	private void initComponents() {
		jpExtensionTypes = new JPanel(new BorderLayout(5, 5));
		jpExtensionTypes.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(
				new EtchedBorder(), new EmptyBorder(5, 5, 5, 5))));

		jlExtensionTypes = new JLabel(res.getString("DAddExtensionType.jlExtensionTypes.text"));

		jltExtensionTypes = new JList<X509ExtensionType>();
		// Longest name to define constant width
		jltExtensionTypes.setPrototypeCellValue(NETSCAPE_CERTIFICATE_RENEWAL_URL);
		jltExtensionTypes.setToolTipText(res.getString("DAddExtensionType.jltExtensionTypes.tooltip"));
		jltExtensionTypes.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		jltExtensionTypes.setBorder(new EtchedBorder());

		jltExtensionTypes.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeAddExtension(evt);
			}
		});

		jspExtensionTypes = new JScrollPane(jltExtensionTypes);

		jcbCriticalExtension = new JCheckBox(res.getString("DAddExtensionType.jcbCriticalExtension.text"));
		jcbCriticalExtension.setMnemonic(res.getString("DAddExtensionType.jcbCriticalExtension.mnemonic").charAt(0));
		jcbCriticalExtension.setToolTipText(res.getString("DAddExtensionType.jcbCriticalExtension.tooltip"));

		jpExtensionTypes.add(jlExtensionTypes, BorderLayout.NORTH);
		jpExtensionTypes.add(jspExtensionTypes, BorderLayout.CENTER);
		jpExtensionTypes.add(jcbCriticalExtension, BorderLayout.SOUTH);

		jbOK = new JButton(res.getString("DAddExtensionType.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DAddExtensionType.jbCancel.text"));
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

		populateExtensionTypes();

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpExtensionTypes, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populateExtensionTypes() {
		// Population is the supported set minus those already added
		ArrayList<X509ExtensionType> availableExtensions = new ArrayList<X509ExtensionType>();

		for (X509ExtensionType extentionType : SUPPORTED_EXTENSIONS) {
			if (extensions.getExtensionValue(extentionType.oid()) == null) {
				availableExtensions.add(extentionType);
			}
		}

		jltExtensionTypes.setListData(availableExtensions.toArray(new X509ExtensionType[availableExtensions.size()]));

		if (availableExtensions.size() > 0) {
			jltExtensionTypes.setSelectedIndex(0);
		}
	}

	/**
	 * Get chosen extension type.
	 *
	 * @return Extension type of null if dialog cancelled
	 */
	public X509ExtensionType getExtensionType() {
		return extension;
	}

	/**
	 * Is extension critical?
	 *
	 * @return True if is, false otherwise
	 */
	public boolean isExtensionCritical() {
		return isCritical;
	}

	private void okPressed() {
		if (jltExtensionTypes.getSelectedIndex() == -1) {
			JOptionPane.showMessageDialog(this, res.getString("DAddExtensionType.ExtensionSelectionReq.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		extension = jltExtensionTypes.getSelectedValue();
		isCritical = jcbCriticalExtension.isSelected();

		closeDialog();
	}

	private void maybeAddExtension(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			int index = jltExtensionTypes.locationToIndex(evt.getPoint());
			extension = jltExtensionTypes.getModel().getElementAt(index);
			isCritical = jcbCriticalExtension.isSelected();
			closeDialog();
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
