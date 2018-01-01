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
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.text.MessageFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.kse.crypto.x509.X500NameUtils;
import org.kse.gui.CursorUtil;
import org.kse.gui.JEscDialog;
import org.kse.gui.JKseTable;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.dialogs.extensions.DViewExtensions;
import org.kse.gui.error.DError;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Exception;

/**
 * Displays the details of a Certificate Revocation List (CRL).
 *
 */
public class DViewCrl extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JPanel jpOK;
	private JButton jbOK;
	private JPanel jpCRL;
	private JLabel jlVersion;
	private JTextField jtfVersion;
	private JLabel jlIssuer;
	private JDistinguishedName jdnIssuer;
	private JLabel jlEffectiveDate;
	private JTextField jtfEffectiveDate;
	private JLabel jlNextUpdate;
	private JTextField jtfNextUpdate;
	private JLabel jlSignatureAlgorithm;
	private JTextField jtfSignatureAlgorithm;
	private JPanel jpCrlButtons;
	private JButton jbCrlExtensions;
	private JButton jbCrlAsn1;
	private JPanel jpRevokedCertsTable;
	private JLabel jlRevokedCerts;
	private JScrollPane jspRevokedCertsTable;
	private JKseTable jtRevokedCerts;
	private JPanel jpCrlEntryExtensions;
	private JButton jbCrlEntryExtensions;

	private X509CRL crl;

	/**
	 * Creates a new DViewCrl dialog.
	 *
	 * @param parent
	 *            Parent frame
	 * @param title
	 *            The dialog title
	 * @param crl
	 *            CRL to display
	 */
	public DViewCrl(JFrame parent, String title, X509CRL crl) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.crl = crl;
		initComponents();
	}

	/**
	 * Creates new DViewCrl dialog where the parent is a dialog.
	 *
	 * @param parent
	 *            Parent dialog
	 * @param title
	 *            The dialog title
	 * @param modality
	 *            Dialog modality
	 * @param crl
	 *            CRL to display
	 */
	public DViewCrl(JDialog parent, String title, Dialog.ModalityType modality, X509CRL crl) {
		super(parent, title, modality);
		this.crl = crl;
		initComponents();
	}

	private void initComponents() {
		GridBagConstraints gbcLbl = new GridBagConstraints();
		gbcLbl.gridx = 0;
		gbcLbl.gridwidth = 1;
		gbcLbl.gridheight = 1;
		gbcLbl.insets = new Insets(5, 5, 5, 5);
		gbcLbl.anchor = GridBagConstraints.EAST;

		GridBagConstraints gbcCtrl = new GridBagConstraints();
		gbcCtrl.gridx = 1;
		gbcCtrl.gridwidth = 1;
		gbcCtrl.gridheight = 1;
		gbcCtrl.insets = new Insets(5, 5, 5, 5);
		gbcCtrl.anchor = GridBagConstraints.WEST;

		jlVersion = new JLabel(res.getString("DViewCrl.jlVersion.text"));
		GridBagConstraints gbc_jlVersion = (GridBagConstraints) gbcLbl.clone();
		gbc_jlVersion.gridy = 0;

		jtfVersion = new JTextField(3);
		jtfVersion.setEditable(false);
		jtfVersion.setToolTipText(res.getString("DViewCrl.jtfVersion.tooltip"));
		GridBagConstraints gbc_jtfVersion = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfVersion.gridy = 0;

		jlIssuer = new JLabel(res.getString("DViewCrl.jlIssuer.text"));
		GridBagConstraints gbc_jlIssuer = (GridBagConstraints) gbcLbl.clone();
		gbc_jlIssuer.gridy = 1;

		jdnIssuer = new JDistinguishedName(res.getString("DViewCrl.Issuer.Title"), 30, false);
		jdnIssuer.setToolTipText(res.getString("DViewCrl.jdnIssuer.tooltip"));
		GridBagConstraints gbc_jdnIssuer = (GridBagConstraints) gbcCtrl.clone();
		gbc_jdnIssuer.gridy = 1;

		jlEffectiveDate = new JLabel(res.getString("DViewCrl.jlEffectiveDate.text"));
		GridBagConstraints gbc_jlEffectiveDate = (GridBagConstraints) gbcLbl.clone();
		gbc_jlEffectiveDate.gridy = 2;

		jtfEffectiveDate = new JTextField(30);
		jtfEffectiveDate.setEditable(false);
		jtfEffectiveDate.setToolTipText(res.getString("DViewCrl.jtfEffectiveDate.tooltip"));
		GridBagConstraints gbc_jtfEffectiveDate = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfEffectiveDate.gridy = 2;

		jlNextUpdate = new JLabel(res.getString("DViewCrl.jlNextUpdate.text"));
		GridBagConstraints gbc_jlNextUpdate = (GridBagConstraints) gbcLbl.clone();
		gbc_jlNextUpdate.gridy = 3;

		jtfNextUpdate = new JTextField(30);
		jtfNextUpdate.setEditable(false);
		jtfNextUpdate.setToolTipText(res.getString("DViewCrl.jtfNextUpdate.tooltip"));
		GridBagConstraints gbc_jtfNextUpdate = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfNextUpdate.gridy = 3;

		jlSignatureAlgorithm = new JLabel(res.getString("DViewCrl.jlSignatureAlgorithm.text"));
		GridBagConstraints gbc_jlSignatureAlgorithm = (GridBagConstraints) gbcLbl.clone();
		gbc_jlSignatureAlgorithm.gridy = 4;

		jtfSignatureAlgorithm = new JTextField(15);
		jtfSignatureAlgorithm.setEditable(false);
		jtfSignatureAlgorithm.setToolTipText(res.getString("DViewCrl.jtfSignatureAlgorithm.tooltip"));
		GridBagConstraints gbc_jtfSignatureAlgorithm = (GridBagConstraints) gbcCtrl.clone();
		gbc_jtfSignatureAlgorithm.gridy = 4;

		jbCrlExtensions = new JButton(res.getString("DViewCrl.jbCrlExtensions.text"));

		PlatformUtil.setMnemonic(jbCrlExtensions, res.getString("DViewCrl.jbCrlExtensions.mnemonic").charAt(0));
		jbCrlExtensions.setToolTipText(res.getString("DViewCrl.jbCrlExtensions.tooltip"));
		jbCrlExtensions.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCrl.this);
					crlExtensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCrl.this);
				}
			}
		});

		jbCrlAsn1 = new JButton(res.getString("DViewCrl.jbCrlAsn1.text"));

		PlatformUtil.setMnemonic(jbCrlAsn1, res.getString("DViewCrl.jbCrlAsn1.mnemonic").charAt(0));
		jbCrlAsn1.setToolTipText(res.getString("DViewCrl.jbCrlAsn1.tooltip"));
		jbCrlAsn1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCrl.this);
					asn1DumpPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCrl.this);
				}
			}
		});

		jpCrlButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
		jpCrlButtons.add(jbCrlExtensions);
		jpCrlButtons.add(jbCrlAsn1);

		GridBagConstraints gbc_jpCrlButtons = new GridBagConstraints();
		gbc_jpCrlButtons.gridx = 0;
		gbc_jpCrlButtons.gridy = 5;
		gbc_jpCrlButtons.gridwidth = 2;
		gbc_jpCrlButtons.gridheight = 1;
		gbc_jpCrlButtons.insets = new Insets(5, 0, 5, 0);
		gbc_jpCrlButtons.anchor = GridBagConstraints.EAST;

		jlRevokedCerts = new JLabel(res.getString("DViewCrl.jlRevokedCerts.text"));

		RevokedCertsTableModel rcModel = new RevokedCertsTableModel();

		jtRevokedCerts = new JKseTable(rcModel);

		RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(rcModel);
		jtRevokedCerts.setRowSorter(sorter);

		jtRevokedCerts.setShowGrid(false);
		jtRevokedCerts.setRowMargin(0);
		jtRevokedCerts.getColumnModel().setColumnMargin(0);
		jtRevokedCerts.getTableHeader().setReorderingAllowed(false);
		jtRevokedCerts.setAutoResizeMode(JKseTable.AUTO_RESIZE_ALL_COLUMNS);

		for (int i = 0; i < jtRevokedCerts.getColumnCount(); i++) {
			TableColumn column = jtRevokedCerts.getColumnModel().getColumn(i);

			if (i == 0) {
				column.setPreferredWidth(100);
			}

			column.setHeaderRenderer(new RevokedCertsTableHeadRend(jtRevokedCerts.getTableHeader().getDefaultRenderer()));
			column.setCellRenderer(new RevokedCertsTableCellRend());
		}

		ListSelectionModel listSelectionModel = jtRevokedCerts.getSelectionModel();
		listSelectionModel.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent evt) {
				if (!evt.getValueIsAdjusting()) // Ignore spurious
					// events
				{
					try {
						CursorUtil.setCursorBusy(DViewCrl.this);
						crlEntrySelection();
					} finally {
						CursorUtil.setCursorFree(DViewCrl.this);
					}
				}
			}
		});

		jtRevokedCerts.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				maybeDisplayCrlEntryExtensions(evt);
			}
		});

		jspRevokedCertsTable = PlatformUtil.createScrollPane(jtRevokedCerts,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		jspRevokedCertsTable.getViewport().setBackground(jtRevokedCerts.getBackground());

		jpRevokedCertsTable = new JPanel(new BorderLayout(10, 10));
		jpRevokedCertsTable.setPreferredSize(new Dimension(100, 200));
		jpRevokedCertsTable.add(jlRevokedCerts, BorderLayout.NORTH);
		jpRevokedCertsTable.add(jspRevokedCertsTable, BorderLayout.CENTER);
		jpRevokedCertsTable.setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5)));

		jbCrlEntryExtensions = new JButton(res.getString("DViewCrl.jbCrlEntryExtensions.text"));

		PlatformUtil.setMnemonic(jbCrlEntryExtensions, res.getString("DViewCrl.jbCrlEntryExtensions.mnemonic")
				.charAt(0));
		jbCrlEntryExtensions.setToolTipText(res.getString("DViewCrl.jbCrlEntryExtensions.tooltip"));
		jbCrlEntryExtensions.setEnabled(false);
		jbCrlEntryExtensions.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DViewCrl.this);
					crlEntryExtensionsPressed();
				} finally {
					CursorUtil.setCursorFree(DViewCrl.this);
				}
			}
		});

		jpCrlEntryExtensions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		jpCrlEntryExtensions.add(jbCrlEntryExtensions);

		jpRevokedCertsTable.add(jpCrlEntryExtensions, BorderLayout.SOUTH);

		GridBagConstraints gbc_jpRevokedCertsTable = new GridBagConstraints();
		gbc_jpRevokedCertsTable.gridx = 0;
		gbc_jpRevokedCertsTable.gridy = 6;
		gbc_jpRevokedCertsTable.gridwidth = 2;
		gbc_jpRevokedCertsTable.gridheight = 1;
		gbc_jpRevokedCertsTable.insets = new Insets(5, 5, 5, 5);
		gbc_jpRevokedCertsTable.fill = GridBagConstraints.BOTH;
		gbc_jpRevokedCertsTable.anchor = GridBagConstraints.CENTER;

		jpCRL = new JPanel(new GridBagLayout());
		jpCRL.setBorder(new CompoundBorder(new EmptyBorder(10, 10, 10, 10), new EtchedBorder()));

		jpCRL.add(jlVersion, gbc_jlVersion);
		jpCRL.add(jtfVersion, gbc_jtfVersion);
		jpCRL.add(jlIssuer, gbc_jlIssuer);
		jpCRL.add(jdnIssuer, gbc_jdnIssuer);
		jpCRL.add(jlEffectiveDate, gbc_jlEffectiveDate);
		jpCRL.add(jtfEffectiveDate, gbc_jtfEffectiveDate);
		jpCRL.add(jlNextUpdate, gbc_jlNextUpdate);
		jpCRL.add(jtfNextUpdate, gbc_jtfNextUpdate);
		jpCRL.add(jlSignatureAlgorithm, gbc_jlSignatureAlgorithm);
		jpCRL.add(jtfSignatureAlgorithm, gbc_jtfSignatureAlgorithm);
		jpCRL.add(jpCrlButtons, gbc_jpCrlButtons);
		jpCRL.add(jpRevokedCertsTable, gbc_jpRevokedCertsTable);

		populateDialog();

		jbOK = new JButton(res.getString("DViewCrl.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jpOK = PlatformUtil.createDialogButtonPanel(jbOK, false);

		getContentPane().add(jpCRL, BorderLayout.CENTER);
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

	private void populateDialog() {
		Date currentDate = new Date();

		Date effectiveDate = crl.getThisUpdate();
		Date updateDate = crl.getNextUpdate();

		boolean effective = currentDate.before(effectiveDate);

		boolean updateAvailable = false;

		if (updateDate != null) {
			updateAvailable = currentDate.after(updateDate);
		}

		jtfVersion.setText(Integer.toString(crl.getVersion()));
		jtfVersion.setCaretPosition(0);

		jdnIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(crl.getIssuerX500Principal()));

		jtfEffectiveDate.setText(StringUtils.formatDate(effectiveDate));

		if (effective) {
			jtfEffectiveDate.setText(MessageFormat.format(res.getString("DViewCrl.jtfEffectiveDate.noteffective.text"),
					jtfEffectiveDate.getText()));
			jtfEffectiveDate.setForeground(Color.red);
		} else {
			jtfEffectiveDate.setForeground(jtfVersion.getForeground());
		}
		jtfEffectiveDate.setCaretPosition(0);

		if (updateDate != null) {
			jtfNextUpdate.setText(StringUtils.formatDate(updateDate));
		} else {
			jtfNextUpdate.setText(res.getString("DViewCrl.jtfNextUpdate.none.text"));
		}

		if (updateAvailable) {
			jtfNextUpdate.setText(MessageFormat.format(res.getString("DViewCrl.jtfNextUpdate.updateavailable.text"),
					jtfNextUpdate.getText()));
			jtfNextUpdate.setForeground(Color.red);
		} else {
			jtfNextUpdate.setForeground(jtfVersion.getForeground());
		}
		jtfNextUpdate.setCaretPosition(0);

		jtfSignatureAlgorithm.setText(crl.getSigAlgName());
		jtfSignatureAlgorithm.setCaretPosition(0);

		Set<?> critExts = crl.getCriticalExtensionOIDs();
		Set<?> nonCritExts = crl.getNonCriticalExtensionOIDs();

		if (critExts != null && critExts.size() != 0 || nonCritExts != null && nonCritExts.size() != 0) {
			jbCrlExtensions.setEnabled(true);
		} else {
			jbCrlExtensions.setEnabled(false);
		}

		Set<? extends X509CRLEntry> revokedCertsSet = crl.getRevokedCertificates();
		if (revokedCertsSet == null) {
			revokedCertsSet = new HashSet<X509CRLEntry>();
		}
		X509CRLEntry[] revokedCerts = revokedCertsSet.toArray(new X509CRLEntry[revokedCertsSet.size()]);
		RevokedCertsTableModel revokedCertsTableModel = (RevokedCertsTableModel) jtRevokedCerts.getModel();
		revokedCertsTableModel.load(revokedCerts);

		if (revokedCertsTableModel.getRowCount() > 0) {
			jtRevokedCerts.changeSelection(0, 0, false, false);
		}
	}

	private void crlEntrySelection() {
		int row = jtRevokedCerts.getSelectedRow();

		if (row != -1) {
			BigInteger serialNumber = (BigInteger) jtRevokedCerts.getValueAt(row, 0);

			Set<?> revokedCertsSet = crl.getRevokedCertificates();

			X509CRLEntry x509CrlEntry = null;

			for (Iterator<?> itr = revokedCertsSet.iterator(); itr.hasNext();) {
				X509CRLEntry entry = (X509CRLEntry) itr.next();
				if (serialNumber.equals(entry.getSerialNumber())) {
					x509CrlEntry = entry;
					break;
				}
			}

			if (x509CrlEntry.hasExtensions()) {
				jbCrlEntryExtensions.setEnabled(true);
				return;
			}
		}

		jbCrlEntryExtensions.setEnabled(false);
	}

	private void crlExtensionsPressed() {
		DViewExtensions dViewExtensions = new DViewExtensions(this, res.getString("DViewCrl.Extensions.Title"), crl);
		dViewExtensions.setLocationRelativeTo(this);
		dViewExtensions.setVisible(true);
	}

	private void asn1DumpPressed() {
		try {
			DViewAsn1Dump dViewAsn1Dump = new DViewAsn1Dump(this, crl);
			dViewAsn1Dump.setLocationRelativeTo(this);
			dViewAsn1Dump.setVisible(true);
		} catch (Asn1Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		} catch (IOException ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
		}
	}

	private void crlEntryExtensionsPressed() {
		displayCrlEntryExtensions();
	}

	private void maybeDisplayCrlEntryExtensions(MouseEvent evt) {
		if (evt.getClickCount() > 1) {
			Point point = new Point(evt.getX(), evt.getY());
			int row = jtRevokedCerts.rowAtPoint(point);

			if (row != -1) {
				try {
					CursorUtil.setCursorBusy(DViewCrl.this);
					jtRevokedCerts.setRowSelectionInterval(row, row);
					displayCrlEntryExtensions();
				} finally {
					CursorUtil.setCursorFree(DViewCrl.this);
				}
			}
		}
	}

	private void displayCrlEntryExtensions() {
		int row = jtRevokedCerts.getSelectedRow();

		if (row != -1) {
			BigInteger serialNumber = (BigInteger) jtRevokedCerts.getValueAt(row, 0);

			Set<?> revokedCertsSet = crl.getRevokedCertificates();

			X509CRLEntry x509CrlEntry = null;

			for (Iterator<?> itr = revokedCertsSet.iterator(); itr.hasNext();) {
				X509CRLEntry entry = (X509CRLEntry) itr.next();
				if (serialNumber.equals(entry.getSerialNumber())) {
					x509CrlEntry = entry;
					break;
				}
			}

			if (x509CrlEntry.hasExtensions()) {
				DViewExtensions dViewExtensions = new DViewExtensions(this,
						res.getString("DViewCrl.EntryExtensions.Title"), x509CrlEntry);
				dViewExtensions.setLocationRelativeTo(this);
				dViewExtensions.setVisible(true);
			}
		}
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
