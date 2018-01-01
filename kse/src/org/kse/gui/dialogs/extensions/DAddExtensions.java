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

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.kse.crypto.x509.X509ExtensionSet;
import org.kse.crypto.x509.X509ExtensionSetLoadException;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.oid.ObjectIdComparator;
import org.kse.utilities.os.OperatingSystem;

/**
 * Allows selection of X.509 Extensions to add to a certificate.
 *
 */
public class DAddExtensions extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle
			.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpExtensions;
	private JPanel jpExtensionButtons;
	private JButton jbAdd;
	private JButton jbEdit;
	private JButton jbToggleCriticality;
	private JButton jbRemove;
	private JScrollPane jspExtensionsTable;
	private JKseTable jtExtensions;
	private JPanel jpLoadSaveTemplate;
	private JButton jbLoadTemplate;
	private JButton jbSaveTemplate;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private X509ExtensionSet extensions = new X509ExtensionSet();
	private PublicKey authorityPublicKey;
	private X500Name authorityCertName;
	private BigInteger authorityCertSerialNumber;
	private PublicKey subjectPublicKey;

	/**
	 * Creates a new DAddExtensions dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param extensions
	 *            Extensions to add to
	 * @param authorityPublicKey
	 *            Authority public key
	 * @param authorityCertName
	 *            Authority certificate name
	 * @param authorityCertSerialNumber
	 *            Authority certificate serial number
	 * @param subjectPublicKey
	 *            Subject public key
	 */
	public DAddExtensions(JFrame parent, String title, X509ExtensionSet extensions, PublicKey authorityPublicKey,
			X500Name authorityCertName, BigInteger authorityCertSerialNumber, PublicKey subjectPublicKey) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DAddExtensions.Title"));
		this.extensions = extensions;
		this.authorityPublicKey = authorityPublicKey;
		this.authorityCertName = authorityCertName;
		this.authorityCertSerialNumber = authorityCertSerialNumber;
		this.subjectPublicKey = subjectPublicKey;
		initComponents();
	}

	/**
	 * Creates new DAddExtensions dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param extensions
	 *            Extensions to add to
	 * @param authorityPublicKey
	 *            Authority public key
	 * @param authorityCertName
	 *            Authority certificate name
	 * @param authorityCertSerialNumber
	 *            Authority certificate serial number
	 * @param subjectPublicKey
	 *            Subject public key
	 */
	public DAddExtensions(JDialog parent, X509ExtensionSet extensions, PublicKey authorityPublicKey,
			X500Name authorityCertName, BigInteger authorityCertSerialNumber, PublicKey subjectPublicKey) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DAddExtensions.Title"));
		this.extensions = (X509ExtensionSet) extensions.clone();
		this.authorityPublicKey = authorityPublicKey;
		this.authorityCertName = authorityCertName;
		this.authorityCertSerialNumber = authorityCertSerialNumber;
		this.subjectPublicKey = subjectPublicKey;
		initComponents();
	}

	private void initComponents() {
		jbAdd = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DAddExtensions.jbAdd.image")))));
		jbAdd.setMargin(new Insets(2, 2, 0, 0));
		jbAdd.setToolTipText(res.getString("DAddExtensions.jbAdd.tooltip"));
		jbAdd.setMnemonic(res.getString("DAddExtensions.jbAdd.mnemonic").charAt(0));

		jbAdd.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					addPressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jbEdit = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DAddExtensions.jbEdit.image")))));
		jbEdit.setMargin(new Insets(2, 2, 0, 0));
		jbEdit.setToolTipText(res.getString("DAddExtensions.jbEdit.tooltip"));
		jbEdit.setMnemonic(res.getString("DAddExtensions.jbEdit.mnemonic").charAt(0));

		jbEdit.setEnabled(false);

		jbEdit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					editPressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jbToggleCriticality = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DAddExtensions.jbToggleCriticality.image")))));
		jbToggleCriticality.setMargin(new Insets(2, 2, 0, 0));
		jbToggleCriticality.setToolTipText(res.getString("DAddExtensions.jbToggleCriticality.tooltip"));
		jbToggleCriticality.setMnemonic(res.getString("DAddExtensions.jbToggleCriticality.mnemonic").charAt(0));

		jbToggleCriticality.setEnabled(false);

		jbToggleCriticality.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					toggleCriticalityPressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jbRemove = new JButton(new ImageIcon(Toolkit.getDefaultToolkit().createImage(
				getClass().getResource(res.getString("DAddExtensions.jbRemove.image")))));
		jbRemove.setMargin(new Insets(2, 2, 0, 0));
		jbRemove.setToolTipText(res.getString("DAddExtensions.jbRemove.tooltip"));
		jbRemove.setMnemonic(res.getString("DAddExtensions.jbRemove.mnemonic").charAt(0));

		jbRemove.setEnabled(false);

		jbRemove.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					removePressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jpExtensionButtons = new JPanel();
		jpExtensionButtons.setLayout(new BoxLayout(jpExtensionButtons, BoxLayout.Y_AXIS));
		jpExtensionButtons.add(Box.createVerticalGlue());
		jpExtensionButtons.add(jbAdd);
		jpExtensionButtons.add(Box.createVerticalStrut(3));
		jpExtensionButtons.add(jbEdit);
		jpExtensionButtons.add(Box.createVerticalStrut(3));
		jpExtensionButtons.add(jbToggleCriticality);
		jpExtensionButtons.add(Box.createVerticalStrut(3));
		jpExtensionButtons.add(jbRemove);
		jpExtensionButtons.add(Box.createVerticalGlue());

		ExtensionsTableModel extensionsTableModel = new ExtensionsTableModel();
		jtExtensions = new JKseTable(extensionsTableModel);

		TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(extensionsTableModel);
		sorter.setComparator(2, new ObjectIdComparator());
		jtExtensions.setRowSorter(sorter);

		jtExtensions.setShowGrid(false);
		jtExtensions.setRowMargin(0);
		jtExtensions.getColumnModel().setColumnMargin(0);
		jtExtensions.getTableHeader().setReorderingAllowed(false);
		jtExtensions.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);
		jtExtensions.setRowHeight(Math.max(18, jtExtensions.getRowHeight()));

		for (int i = 0; i < jtExtensions.getColumnCount(); i++) {
			TableColumn column = jtExtensions.getColumnModel().getColumn(i);
			column.setHeaderRenderer(new ExtensionsTableHeadRend(jtExtensions.getTableHeader().getDefaultRenderer()));
			column.setCellRenderer(new ExtensionsTableCellRend());
		}

		TableColumn criticalCol = jtExtensions.getColumnModel().getColumn(0);
		criticalCol.setResizable(false);
		criticalCol.setMinWidth(28);
		criticalCol.setMaxWidth(28);
		criticalCol.setPreferredWidth(28);

		ListSelectionModel selectionModel = jtExtensions.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) {
					try {
						CursorUtil.setCursorBusy(DAddExtensions.this);
						updateButtonControls();
					} finally {
						CursorUtil.setCursorFree(DAddExtensions.this);
					}

				}
			}
		});

		jtExtensions.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeEditExtension(evt);
			}
		});

		jtExtensions.addKeyListener(new KeyAdapter() {
			boolean deleteLastPressed = false;

			@Override
			public void keyPressed(KeyEvent evt) {
				// Record delete pressed on non-Macs
				if (!OperatingSystem.isMacOs()) {
					deleteLastPressed = evt.getKeyCode() == KeyEvent.VK_DELETE;
				}
			}

			@Override
			public void keyReleased(KeyEvent evt) {
				// Delete on non-Mac if delete was pressed and is now released
				if (!OperatingSystem.isMacOs() && deleteLastPressed && evt.getKeyCode() == KeyEvent.VK_DELETE) {
					try {
						CursorUtil.setCursorBusy(DAddExtensions.this);
						deleteLastPressed = false;
						removeSelectedExtension();
					} finally {
						CursorUtil.setCursorFree(DAddExtensions.this);
					}
				}
			}

			@Override
			public void keyTyped(KeyEvent evt) {
				// Delete on Mac if back space typed
				if (OperatingSystem.isMacOs() && evt.getKeyChar() == 0x08) {
					try {
						CursorUtil.setCursorBusy(DAddExtensions.this);
						removeSelectedExtension();
					} finally {
						CursorUtil.setCursorFree(DAddExtensions.this);
					}
				}
			}
		});

		jspExtensionsTable = PlatformUtil.createScrollPane(jtExtensions,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspExtensionsTable.getViewport().setBackground(jtExtensions.getBackground());

		jbLoadTemplate = new JButton(res.getString("DAddExtensions.jbLoadTemplate.text"));
		jbLoadTemplate.setMnemonic(res.getString("DAddExtensions.jbLoadTemplate.mnemonic").charAt(0));
		jbLoadTemplate.setToolTipText(res.getString("DAddExtensions.jbLoadTemplate.tooltip"));

		jbLoadTemplate.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					loadTemplatePressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jbSaveTemplate = new JButton(res.getString("DAddExtensions.jbSaveTemplate.text"));
		jbSaveTemplate.setMnemonic(res.getString("DAddExtensions.jbSaveTemplate.mnemonic").charAt(0));
		jbSaveTemplate.setToolTipText(res.getString("DAddExtensions.jbSaveTemplate.tooltip"));

		jbSaveTemplate.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					saveTemplatePressed();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		});

		jpLoadSaveTemplate = new JPanel();
		jpLoadSaveTemplate.setLayout(new BoxLayout(jpLoadSaveTemplate, BoxLayout.X_AXIS));
		jpLoadSaveTemplate.add(Box.createHorizontalGlue());
		jpLoadSaveTemplate.add(jbLoadTemplate);
		jpLoadSaveTemplate.add(Box.createHorizontalStrut(5));
		jpLoadSaveTemplate.add(jbSaveTemplate);

		jpExtensions = new JPanel(new BorderLayout(5, 5));
		jpExtensions.setPreferredSize(new Dimension(450, 200));
		jpExtensions.add(jspExtensionsTable, BorderLayout.CENTER);
		jpExtensions.add(jpExtensionButtons, BorderLayout.EAST);
		jpExtensions.add(jpLoadSaveTemplate, BorderLayout.SOUTH);

		jpExtensions.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new CompoundBorder(new EtchedBorder(),
				new EmptyBorder(5, 5, 5, 5))));

		jbOK = new JButton(res.getString("DAddExtensions.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DAddExtensions.jbCancel.text"));
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

		reloadExtensionsTable();
		selectFirstExtensionInTable();
		updateButtonControls();

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpExtensions, BorderLayout.CENTER);
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

	private void addPressed() {
		DAddExtensionType dAddExtensionType = new DAddExtensionType(this, extensions);
		dAddExtensionType.setLocationRelativeTo(this);
		dAddExtensionType.setVisible(true);

		X509ExtensionType extensionTypeToAdd = dAddExtensionType.getExtensionType();

		if (extensionTypeToAdd == null) {
			return;
		}

		boolean isCritical = dAddExtensionType.isExtensionCritical();
		byte[] extensionValue = null;

		DExtension dExtension = null;

		switch (extensionTypeToAdd) {
		case AUTHORITY_INFORMATION_ACCESS: {
			dExtension = new DAuthorityInformationAccess(this);
			break;
		}
		case AUTHORITY_KEY_IDENTIFIER: {
			dExtension = new DAuthorityKeyIdentifier(this, authorityPublicKey, authorityCertName,
					authorityCertSerialNumber);
			break;
		}
		case BASIC_CONSTRAINTS: {
			dExtension = new DBasicConstraints(this);
			break;
		}
		case CERTIFICATE_POLICIES: {
			dExtension = new DCertificatePolicies(this);
			break;
		}
		case EXTENDED_KEY_USAGE: {
			dExtension = new DExtendedKeyUsage(this);
			break;
		}
		case INHIBIT_ANY_POLICY: {
			dExtension = new DInhibitAnyPolicy(this);
			break;
		}
		case ISSUER_ALTERNATIVE_NAME: {
			dExtension = new DIssuerAlternativeName(this);
			break;
		}
		case KEY_USAGE: {
			dExtension = new DKeyUsage(this);
			break;
		}
		case NAME_CONSTRAINTS: {
			dExtension = new DNameConstraints(this);
			break;
		}
		case NETSCAPE_BASE_URL: {
			dExtension = new DNetscapeBaseUrl(this);
			break;
		}
		case NETSCAPE_CA_POLICY_URL: {
			dExtension = new DNetscapeCaPolicyUrl(this);
			break;
		}
		case NETSCAPE_CA_REVOCATION_URL: {
			dExtension = new DNetscapeCaRevocationUrl(this);
			break;
		}
		case NETSCAPE_CERTIFICATE_RENEWAL_URL: {
			dExtension = new DNetscapeCertificateRenewalUrl(this);
			break;
		}
		case NETSCAPE_CERTIFICATE_TYPE: {
			dExtension = new DNetscapeCertificateType(this);
			break;
		}
		case NETSCAPE_COMMENT: {
			dExtension = new DNetscapeComment(this);
			break;
		}
		case NETSCAPE_REVOCATION_URL: {
			dExtension = new DNetscapeRevocationUrl(this);
			break;
		}
		case NETSCAPE_SSL_SERVER_NAME: {
			dExtension = new DNetscapeSslServerName(this);
			break;
		}
		case POLICY_CONSTRAINTS: {
			dExtension = new DPolicyConstraints(this);
			break;
		}
		case POLICY_MAPPINGS: {
			dExtension = new DPolicyMappings(this);
			break;
		}
		case PRIVATE_KEY_USAGE_PERIOD: {
			dExtension = new DPrivateKeyUsagePeriod(this);
			break;
		}
		case SUBJECT_ALTERNATIVE_NAME: {
			dExtension = new DSubjectAlternativeName(this);
			break;
		}
		case SUBJECT_INFORMATION_ACCESS: {
			dExtension = new DSubjectInformationAccess(this);
			break;
		}
		case SUBJECT_KEY_IDENTIFIER: {
			dExtension = new DSubjectKeyIdentifier(this, subjectPublicKey);
			break;
		}
		default: {
			return;
		}
		}

		dExtension.setLocationRelativeTo(this);
		dExtension.setVisible(true);
		extensionValue = dExtension.getValue();

		if (extensionValue == null) {
			return;
		}

		extensions.addExtension(extensionTypeToAdd.oid(), isCritical, extensionValue);

		reloadExtensionsTable();
		selectExtensionInTable(extensionTypeToAdd.oid());
		updateButtonControls();
	}

	private void editPressed() {
		editSelectedExtension();
	}

	private void maybeEditExtension(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtExtensions.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(DAddExtensions.this);
					jtExtensions.setRowSelectionInterval(row, row);
					editSelectedExtension();
				} finally {
					CursorUtil.setCursorFree(DAddExtensions.this);
				}
			}
		}
	}

	private void editSelectedExtension() {
		try {
			int selectedRow = jtExtensions.getSelectedRow();

			if (selectedRow != -1) {
				String oid = ((ASN1ObjectIdentifier) jtExtensions.getValueAt(selectedRow, 2)).getId();
				X509ExtensionType extensionType = X509ExtensionType.resolveOid(oid);

				byte[] extensionValue = extensions.getExtensionValue(oid);
				boolean isCritical = extensions.getCriticalExtensionOIDs().contains(oid);

				byte[] newExtensionValue = null;

				DExtension dExtension = null;

				switch (extensionType) {
				case AUTHORITY_INFORMATION_ACCESS: {
					dExtension = new DAuthorityInformationAccess(this, extensionValue);
					break;
				}
				case AUTHORITY_KEY_IDENTIFIER: {
					dExtension = new DAuthorityKeyIdentifier(this, extensionValue, authorityPublicKey);
					break;
				}
				case BASIC_CONSTRAINTS: {
					dExtension = new DBasicConstraints(this, extensionValue);
					break;
				}
				case CERTIFICATE_POLICIES: {
					dExtension = new DCertificatePolicies(this, extensionValue);
					break;
				}
				case EXTENDED_KEY_USAGE: {
					dExtension = new DExtendedKeyUsage(this, extensionValue);
					break;
				}
				case INHIBIT_ANY_POLICY: {
					dExtension = new DInhibitAnyPolicy(this, extensionValue);
					break;
				}
				case ISSUER_ALTERNATIVE_NAME: {
					dExtension = new DIssuerAlternativeName(this, extensionValue);
					break;
				}
				case KEY_USAGE: {
					dExtension = new DKeyUsage(this, extensionValue);
					break;
				}
				case NAME_CONSTRAINTS: {
					dExtension = new DNameConstraints(this, extensionValue);
					break;
				}
				case NETSCAPE_BASE_URL: {
					dExtension = new DNetscapeBaseUrl(this, extensionValue);
					break;
				}
				case NETSCAPE_CERTIFICATE_RENEWAL_URL: {
					dExtension = new DNetscapeCertificateRenewalUrl(this, extensionValue);
					break;
				}
				case NETSCAPE_CA_POLICY_URL: {
					dExtension = new DNetscapeCaPolicyUrl(this, extensionValue);
					break;
				}
				case NETSCAPE_CA_REVOCATION_URL: {
					dExtension = new DNetscapeCaRevocationUrl(this, extensionValue);
					break;
				}
				case NETSCAPE_CERTIFICATE_TYPE: {
					dExtension = new DNetscapeCertificateType(this, extensionValue);
					break;
				}
				case NETSCAPE_COMMENT: {
					dExtension = new DNetscapeComment(this, extensionValue);
					break;
				}
				case NETSCAPE_REVOCATION_URL: {
					dExtension = new DNetscapeRevocationUrl(this, extensionValue);
					break;
				}
				case NETSCAPE_SSL_SERVER_NAME: {
					dExtension = new DNetscapeSslServerName(this, extensionValue);
					break;
				}
				case POLICY_CONSTRAINTS: {
					dExtension = new DPolicyConstraints(this, extensionValue);
					break;
				}
				case POLICY_MAPPINGS: {
					dExtension = new DPolicyMappings(this, extensionValue);
					break;
				}
				case PRIVATE_KEY_USAGE_PERIOD: {
					dExtension = new DPrivateKeyUsagePeriod(this, extensionValue);
					break;
				}
				case SUBJECT_ALTERNATIVE_NAME: {
					dExtension = new DSubjectAlternativeName(this, extensionValue);
					break;
				}
				case SUBJECT_INFORMATION_ACCESS: {
					dExtension = new DSubjectInformationAccess(this, extensionValue);
					break;
				}
				case SUBJECT_KEY_IDENTIFIER: {
					dExtension = new DSubjectKeyIdentifier(this, extensionValue, subjectPublicKey);
					break;
				}
				default: {
					return;
				}
				}

				dExtension.setLocationRelativeTo(this);
				dExtension.setVisible(true);
				newExtensionValue = dExtension.getValue();

				if (newExtensionValue == null) {
					return;
				}

				extensions.addExtension(oid, isCritical, newExtensionValue);

				reloadExtensionsTable();
				selectExtensionInTable(oid);
				updateButtonControls();
			}
		} catch (IOException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void toggleCriticalityPressed() {
		int selectedRow = jtExtensions.getSelectedRow();

		if (selectedRow != -1) {
			String oid = ((ASN1ObjectIdentifier) jtExtensions.getValueAt(selectedRow, 2)).getId();

			extensions.toggleExtensionCriticality(oid);

			reloadExtensionsTable();
			selectFirstExtensionInTable();
			updateButtonControls();
		}
	}

	private void removePressed() {
		removeSelectedExtension();
	}

	private void removeSelectedExtension() {
		int selectedRow = jtExtensions.getSelectedRow();

		if (selectedRow != -1) {
			String oid = ((ASN1ObjectIdentifier) jtExtensions.getValueAt(selectedRow, 2)).getId();

			extensions.removeExtension(oid);

			reloadExtensionsTable();
			selectFirstExtensionInTable();
			updateButtonControls();
		}
	}

	private ExtensionsTableModel getExtensionsTableModel() {
		return (ExtensionsTableModel) jtExtensions.getModel();
	}

	private void selectFirstExtensionInTable() {
		if (getExtensionsTableModel().getRowCount() > 0) {
			jtExtensions.changeSelection(0, 0, false, false);
		}
	}

	private void selectExtensionInTable(String oid) {
		for (int i = 0; i < jtExtensions.getRowCount(); i++) {
			if (oid.equals(((ASN1ObjectIdentifier) jtExtensions.getValueAt(i, 2)).getId())) {
				jtExtensions.changeSelection(i, 0, false, false);
				return;
			}
		}
	}

	private void reloadExtensionsTable() {
		getExtensionsTableModel().load(extensions);
	}

	private void updateButtonControls() {
		int selectedRow = jtExtensions.getSelectedRow();

		if (selectedRow == -1) {
			jbEdit.setEnabled(false);
			jbToggleCriticality.setEnabled(false);
			jbRemove.setEnabled(false);
		} else {
			jbEdit.setEnabled(true);
			jbToggleCriticality.setEnabled(true);
			jbRemove.setEnabled(true);
		}
	}

	private void loadTemplatePressed() {
		JFileChooser chooser = FileChooserFactory.getCetFileChooser();

		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("DAddExtensions.LoadCet.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DAddExtensions.CetLoad.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File loadFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(loadFile);

			try {
				extensions = X509ExtensionSet.load(new FileInputStream(loadFile));

				reloadExtensionsTable();
				selectFirstExtensionInTable();
				updateButtonControls();
			} catch (X509ExtensionSetLoadException ex) {
				JOptionPane.showMessageDialog(this,
						MessageFormat.format(res.getString("DAddExtensions.InvalidCetFile.message"), loadFile),
						res.getString("DAddExtensions.LoadCet.Title"), JOptionPane.WARNING_MESSAGE);
			} catch (FileNotFoundException ex) {
				JOptionPane.showMessageDialog(this,
						MessageFormat.format(res.getString("DAddExtensions.NoReadFile.message"), loadFile),
						res.getString("DAddExtensions.LoadCet.Title"), JOptionPane.WARNING_MESSAGE);
			} catch (IOException ex) {
				DError.displayError(this, ex);
			}
		}
	}

	private void saveTemplatePressed() {
		JFileChooser chooser = FileChooserFactory.getCetFileChooser();

		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("DAddExtensions.SaveCet.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showSaveDialog(this);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File saveFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(saveFile);

			if (saveFile.isFile()) {
				String message = MessageFormat.format(res.getString("DAddExtensions.OverWriteFile.message"), saveFile);

				int selected = JOptionPane.showConfirmDialog(this, message,
						res.getString("DAddExtensions.SaveCet.Title"), JOptionPane.YES_NO_OPTION);
				if (selected != JOptionPane.YES_OPTION) {
					return;
				}
			}

			try {
				extensions.save(new FileOutputStream(saveFile));
			} catch (FileNotFoundException ex) {
				JOptionPane.showMessageDialog(this,
						MessageFormat.format(res.getString("DAddExtensions.NoWriteFile.message"), saveFile),
						res.getString("DAddExtensions.SaveCet.Title"), JOptionPane.WARNING_MESSAGE);
			} catch (IOException ex) {
				DError.displayError(this, ex);
			}
		}
	}

	/**
	 * Get chosen certficate extensions.
	 *
	 * @return Certificate extensions or null if dialog cancelled.
	 */
	public X509ExtensionSet getExtensions() {
		return extensions;
	}

	private void okPressed() {
		closeDialog();
	}

	private void cancelPressed() {
		extensions = null;
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
