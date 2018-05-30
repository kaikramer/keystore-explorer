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

import static org.kse.crypto.jcepolicy.JcePolicy.LOCAL_POLICY;
import static org.kse.crypto.jcepolicy.JcePolicy.US_EXPORT_POLICY;

import java.awt.Color;
import java.awt.Container;
import java.awt.Desktop;
import java.awt.Dialog;
import java.awt.EventQueue;
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
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.UIManager;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.kse.crypto.jcepolicy.JcePolicyUtil;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.CursorUtil;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.io.CopyUtil;
import org.kse.utilities.io.IOUtils;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog to upgrade cyptography strength.
 *
 */
public class DUpgradeCryptoStrength extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/crypto/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlUpgradeInstructions;
	private JLabel jlDownloadPolicyInstructions;
	private JButton jbDownloadPolicy;
	private JLabel jlDropPolicyInstructions;
	private PolicyZipDropTarget policyZipDropTarget;
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
		jlDownloadPolicyInstructions = new JLabel(
				res.getString("DUpgradeCryptoStrength.jlDownloadPolicyInstructions.text"));
		jbDownloadPolicy = new JButton(res.getString("DUpgradeCryptoStrength.jbDownloadPolicy.text"));
		PlatformUtil.setMnemonic(jbDownloadPolicy, res.getString("DUpgradeCryptoStrength.jbDownloadPolicy.mnemonic")
				.charAt(0));

		jlDropPolicyInstructions = new JLabel(res.getString("DUpgradeCryptoStrength.jlDropPolicyInstructions.text"));
		policyZipDropTarget = new PolicyZipDropTarget();
		jbBrowsePolicy = new JButton(res.getString("DUpgradeCryptoStrength.jbBrowsePolicy.text"));
		PlatformUtil.setMnemonic(jbBrowsePolicy, res.getString("DUpgradeCryptoStrength.jbBrowsePolicy.mnemonic")
				.charAt(0));

		jbUpgrade = new JButton(res.getString("DUpgradeCryptoStrength.jbUpgrade.text"));
		PlatformUtil.setMnemonic(jbUpgrade, res.getString("DUpgradeCryptoStrength.jbUpgrade.mnemonic").charAt(0));
		jbUpgrade.setEnabled(false);

		jbCancel = new JButton(res.getString("DUpgradeCryptoStrength.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbUpgrade, jbCancel);

		// layout
		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "", "[]para[]"));
		pane.add(jlUpgradeInstructions, "wrap");
		pane.add(jlDownloadPolicyInstructions, "wrap");
		pane.add(jbDownloadPolicy, "wrap");
		pane.add(jlDropPolicyInstructions, "split");
		pane.add(policyZipDropTarget, "gap para, pad para, wrap");
		pane.add(jbBrowsePolicy, "wrap");
		pane.add(new JSeparator(), "spanx, growx, wrap para");
		pane.add(jpButtons, "right, spanx");

		// actions
		jbDownloadPolicy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DUpgradeCryptoStrength.this);
					downloadPolicyPressed();
				} finally {
					CursorUtil.setCursorFree(DUpgradeCryptoStrength.this);
				}
			}
		});
		jbUpgrade.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				upgradePressed();
			}
		});
		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbBrowsePolicy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DUpgradeCryptoStrength.this);
					browsePolicyPressed();
				} finally {
					CursorUtil.setCursorFree(DUpgradeCryptoStrength.this);
				}
			}
		});
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});


		addWindowListener(new WindowAdapter() {
			@Override
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

			// Overwrite local and US Export JARs with new unlimited strength versions
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
		// Process the supplied drop file as a policy zip. If it is a valid policy zip store the policy jar contents
		try {
			ZipFile zip = null;

			try {
				zip = new ZipFile(droppedFile);
			} catch (ZipException ex) {
				return;
			} finally {
				IOUtils.closeQuietly(zip);
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
		private static final long serialVersionUID = 1L;
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

		@Override
		public void drop(DropTargetDropEvent evt) {
			if (policyZipAccepted) {
				evt.rejectDrop();
				return;
			}

			// Checks policy zip is valid and if so allows policy upgrade to proceed
			try {
				evt.acceptDrop(DnDConstants.ACTION_MOVE);

				Transferable trans = evt.getTransferable();

				if (trans.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
					List<?> droppedFiles = (List<?>) trans.getTransferData(DataFlavor.javaFileListFlavor);

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

		@Override
		public void dragEnter(DropTargetDragEvent evt) {
		}

		@Override
		public void dragExit(DropTargetEvent evt) {
		}

		@Override
		public void dragOver(DropTargetDragEvent evt) {
		}

		@Override
		public void dropActionChanged(DropTargetDragEvent evt) {
		}

		public void policyZipAccepted() {
			policyZipAccepted = true;
			ImageIcon icon = new ImageIcon(getClass().getResource("images/dragged_policy.png"));
			setIcon(icon);
		}
	}

	public static void main(String[] args) throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DUpgradeCryptoStrength dialog = new DUpgradeCryptoStrength(new JFrame());
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
