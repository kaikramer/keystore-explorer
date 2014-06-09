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
package net.sf.keystore_explorer.gui.crypto;

import static net.sf.keystore_explorer.crypto.jcepolicy.JcePolicy.LOCAL_POLICY;
import static net.sf.keystore_explorer.crypto.jcepolicy.JcePolicy.US_EXPORT_POLICY;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import net.sf.keystore_explorer.crypto.jcepolicy.JcePolicyUtil;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.error.DError;
import net.sf.keystore_explorer.utilities.io.CopyUtil;

/**
 * Dialog to upgrade cyptography strength.
 * 
 */
public class DUpgradeCryptoStrength extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/crypto/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpUpgrade;
	private JPanel jpUpgradeInstructions;
	private JLabel jlUpgradeInstructions;
	private JPanel jpDownloadPolicy;
	private JLabel jlDownloadPolicyInstructions;
	private JPanel jpDownloadPolicyButton;
	private JButton jbDownloadPolicy;
	private JPanel jpDropPolicy;
	private JLabel jlDropPolicyInstructions;
	private JPanel jpPolicyZipDropTargetLabel;
	private PolicyZipDropTarget policyZipDropTarget;
	private JPanel jpBrowsePolicyButton;
	private JButton jbBrowsePolicy;
	private JPanel jpButtons;
	private JButton jbUpgrade;
	private JButton jbCancel;

	private byte[] localPolicyJarContents;
	private byte[] usExportPolicyJarContents;

	private boolean cryptoStrengthUpgraded = false;
	private boolean cryptoStrengthUpgradeFailed = false;

	/**
	 * Creates a new DUpgradeCryptoStrength dialog.
	 * 
	 * @param parent
	 *            Parent
	 */
	public DUpgradeCryptoStrength(JFrame parent) {
		super(parent, res.getString("DUpgradeCryptoStrength.Title"), Dialog.ModalityType.DOCUMENT_MODAL);

		initComponents();
	}

	private void initComponents() {
		jlUpgradeInstructions = new JLabel(res.getString("DUpgradeCryptoStrength.jlUpgradeInstructions.text"));

		jpUpgradeInstructions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
		jpUpgradeInstructions.add(jlUpgradeInstructions);

		jlDownloadPolicyInstructions = new JLabel(
				res.getString("DUpgradeCryptoStrength.jlDownloadPolicyInstructions.text"));

		jbDownloadPolicy = new JButton(res.getString("DUpgradeCryptoStrength.jbDownloadPolicy.text"));
		PlatformUtil.setMnemonic(jbDownloadPolicy, res.getString("DUpgradeCryptoStrength.jbDownloadPolicy.mnemonic")
				.charAt(0));
		jbDownloadPolicy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DUpgradeCryptoStrength.this);
					downloadPolicyPressed();
				} finally {
					CursorUtil.setCursorFree(DUpgradeCryptoStrength.this);
				}
			}
		});

		jpDownloadPolicyButton = new JPanel();
		jpDownloadPolicyButton.add(jbDownloadPolicy);

		jpDownloadPolicy = new JPanel(new BorderLayout(5, 5));
		jpDownloadPolicy.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpDownloadPolicy.add(jlDownloadPolicyInstructions, BorderLayout.NORTH);
		jpDownloadPolicy.add(jpDownloadPolicyButton, BorderLayout.CENTER);

		jlDropPolicyInstructions = new JLabel(res.getString("DUpgradeCryptoStrength.jlDropPolicyInstructions.text"));

		policyZipDropTarget = new PolicyZipDropTarget();

		jpPolicyZipDropTargetLabel = new JPanel();
		jpPolicyZipDropTargetLabel.add(policyZipDropTarget);

		jbBrowsePolicy = new JButton(res.getString("DUpgradeCryptoStrength.jbBrowsePolicy.text"));
		PlatformUtil.setMnemonic(jbBrowsePolicy, res.getString("DUpgradeCryptoStrength.jbBrowsePolicy.mnemonic")
				.charAt(0));
		jbBrowsePolicy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DUpgradeCryptoStrength.this);
					browsePolicyPressed();
				} finally {
					CursorUtil.setCursorFree(DUpgradeCryptoStrength.this);
				}
			}
		});

		jpBrowsePolicyButton = new JPanel();
		jpBrowsePolicyButton.add(jbBrowsePolicy);

		jpDropPolicy = new JPanel(new BorderLayout(5, 5));
		jpDropPolicy.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpDropPolicy.add(jlDropPolicyInstructions, BorderLayout.WEST);
		jpDropPolicy.add(jpPolicyZipDropTargetLabel, BorderLayout.CENTER);
		jpDropPolicy.add(jpBrowsePolicyButton, BorderLayout.SOUTH);

		jpUpgrade = new JPanel(new BorderLayout());
		jpUpgrade.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpUpgrade.add(jpUpgradeInstructions, BorderLayout.NORTH);
		jpUpgrade.add(jpDownloadPolicy, BorderLayout.CENTER);
		jpUpgrade.add(jpDropPolicy, BorderLayout.SOUTH);

		jbUpgrade = new JButton(res.getString("DUpgradeCryptoStrength.jbUpgrade.text"));
		PlatformUtil.setMnemonic(jbUpgrade, res.getString("DUpgradeCryptoStrength.jbUpgrade.mnemonic").charAt(0));
		jbUpgrade.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				upgradePressed();
			}
		});
		jbUpgrade.setEnabled(false);

		jbCancel = new JButton(res.getString("DUpgradeCryptoStrength.jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbUpgrade, jbCancel, false);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpUpgrade, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbUpgrade);

		pack();
	}

	private void upgradePressed() {
		try {
			CursorUtil.setCursorBusy(this);

			// Backup Local Policy JAR
			File localPolicyJar = JcePolicyUtil.getJarFile(LOCAL_POLICY);
			File localPolicyJarBkp = new File(localPolicyJar.getPath() + ".bkp");

			// Backup US Export Policy JAR
			File usExportPolicyJar = JcePolicyUtil.getJarFile(US_EXPORT_POLICY);
			File usExportPolicyJarBkp = new File(usExportPolicyJar.getPath() + ".bkp");

			CopyUtil.copyClose(new FileInputStream(localPolicyJar), new FileOutputStream(localPolicyJarBkp));

			CopyUtil.copyClose(new FileInputStream(usExportPolicyJar), new FileOutputStream(usExportPolicyJarBkp));

			// Overwrite local and US Export JARs with new unlimited strength
			// versions
			CopyUtil.copyClose(new ByteArrayInputStream(localPolicyJarContents), new FileOutputStream(localPolicyJar));

			CopyUtil.copyClose(new ByteArrayInputStream(usExportPolicyJarContents), new FileOutputStream(
					usExportPolicyJar));

			cryptoStrengthUpgraded = true;
		} catch (IOException ex) {
			upgradeFailedShowManualInstructions();
		} finally {
			CursorUtil.setCursorFree(this);
		}

		closeDialog();
	}

	private void upgradeFailedShowManualInstructions() {
		cryptoStrengthUpgradeFailed = true;

		JOptionPane.showMessageDialog(this, res.getString("DUpgradeCryptoStrength.NoUpdatePolicy.message"), getTitle(),
				JOptionPane.WARNING_MESSAGE);

		String javaHome = System.getProperty("java.home");
		String fileSeparator = System.getProperty("file.separator");

		String manualInstructions = MessageFormat.format(
				res.getString("DUpgradeCryptoStrength.ManualInstructions.message"), javaHome, fileSeparator);

		JOptionPane.showMessageDialog(this, manualInstructions, getTitle(), JOptionPane.INFORMATION_MESSAGE);
	}

	/**
	 * Has the crypto strength been upgraded?
	 * 
	 * @return True if has, false otherwise
	 */
	public boolean hasCryptoStrengthBeenUpgraded() {
		return cryptoStrengthUpgraded;
	}

	/**
	 * Has the crypto strength upgrade failed?
	 * 
	 * @return True if has, false otherwise
	 */
	public boolean hasCryptoStrengthUpgradeFailed() {
		return cryptoStrengthUpgradeFailed;
	}

	private void downloadPolicyPressed() {
		String websiteAddress = JcePolicyUtil.getJcePolicyDownloadUrl();

		try {
			Desktop.getDesktop().browse(URI.create(websiteAddress));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this, MessageFormat.format(
					res.getString("DUpgradeCryptoStrength.NoLaunchBrowser.message"), websiteAddress), getTitle(),
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void browsePolicyPressed() {
		JFileChooser chooser = FileChooserFactory.getZipFileChooser();

		chooser.setCurrentDirectory(CurrentDirectory.get());

		chooser.setDialogTitle(res.getString("DUpgradeCryptoStrength.Title.ChoosePolicyZip.Title"));

		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DUpgradeCryptoStrength.Title.PolicyZipChooser.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();

			if (!chosenFile.isFile()) {
				JOptionPane.showMessageDialog(DUpgradeCryptoStrength.this,
						res.getString("DUpgradeCryptoStrength.NotPolicyZip.message"),
						res.getString("DUpgradeCryptoStrength.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}

			processPolicyZipFile(chosenFile);
		}
	}

	private void processPolicyZipFile(File droppedFile) {
		/*
		 * Process the supplied drop file as a policy zip. If it is a valid
		 * policy zip store the policy jar contents
		 */
		try {
			ZipFile zip = null;

			try {
				zip = new ZipFile(droppedFile);
			} catch (ZipException ex) {
				return;
			}

			Enumeration<? extends ZipEntry> zipEntries = zip.entries();

			while (zipEntries.hasMoreElements()) {
				ZipEntry zipEntry = zipEntries.nextElement();

				if (!zipEntry.isDirectory()) {
					if (zipEntry.getName().endsWith(LOCAL_POLICY.jar())) {
						ByteArrayOutputStream localPolicyJarBaos = new ByteArrayOutputStream();
						CopyUtil.copyClose(zip.getInputStream(zipEntry), localPolicyJarBaos);
						localPolicyJarContents = localPolicyJarBaos.toByteArray();
					} else if (zipEntry.getName().endsWith(US_EXPORT_POLICY.jar())) {
						ByteArrayOutputStream usExportPolicyJarBaos = new ByteArrayOutputStream();
						CopyUtil.copyClose(zip.getInputStream(zipEntry), usExportPolicyJarBaos);
						usExportPolicyJarContents = usExportPolicyJarBaos.toByteArray();
					}
				}
			}

			if (localPolicyJarContents != null && usExportPolicyJarContents != null) {
				jbDownloadPolicy.setEnabled(false);
				jbBrowsePolicy.setEnabled(false);
				policyZipDropTarget.policyZipAccepted();
				jbUpgrade.setEnabled(true);
			} else {
				JOptionPane.showMessageDialog(DUpgradeCryptoStrength.this,
						res.getString("DUpgradeCryptoStrength.NotPolicyZip.message"),
						res.getString("DUpgradeCryptoStrength.Title"), JOptionPane.WARNING_MESSAGE);
			}
		} catch (IOException ex) {
			DError.displayError(DUpgradeCryptoStrength.this, ex);
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private class PolicyZipDropTarget extends JLabel implements DropTargetListener {
		private boolean policyZipAccepted;

		public PolicyZipDropTarget() {
			policyZipAccepted = false;
			ImageIcon icon = new ImageIcon(getClass().getResource("images/drag_policy_here.png"));
			setIcon(icon);
			setBorder(new CompoundBorder(new EtchedBorder(), new EmptyBorder(5, 5, 5, 5)));
			setOpaque(true);
			setBackground(Color.WHITE);

			// Make this label a drop target and its own listener
			new DropTarget(this, this);
		}

		public void drop(DropTargetDropEvent evt) {
			if (policyZipAccepted) {
				evt.rejectDrop();
				return;
			}

			// Checks policy zip is valid and if so allows policy upgrade to
			// proceed
			try {
				evt.acceptDrop(DnDConstants.ACTION_MOVE);

				Transferable trans = evt.getTransferable();

				if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
					List droppedFiles = (List) trans.getTransferData(DataFlavor.javaFileListFlavor);

					if (droppedFiles.size() == 1) {
						File droppedFile = (File) droppedFiles.get(0);
						processPolicyZipFile(droppedFile);
					}
				}
			} catch (IOException ex) {
				DError.displayError(DUpgradeCryptoStrength.this, ex);
			} catch (UnsupportedFlavorException ex) {
				DError.displayError(DUpgradeCryptoStrength.this, ex);
			}
		}

		public void dragEnter(DropTargetDragEvent evt) {
		}

		public void dragExit(DropTargetEvent evt) {
		}

		public void dragOver(DropTargetDragEvent evt) {
		}

		public void dropActionChanged(DropTargetDragEvent evt) {
		}

		public void policyZipAccepted() {
			policyZipAccepted = true;
			ImageIcon icon = new ImageIcon(getClass().getResource("images/dragged_policy.png"));
			setIcon(icon);
		}
	}
}
