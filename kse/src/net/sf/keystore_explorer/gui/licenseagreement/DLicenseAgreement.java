/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
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
package net.sf.keystore_explorer.gui.licenseagreement;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;

import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;

/**
 * Dialog to display a license agreement for the user to agree or reject.
 * 
 */
public class DLicenseAgreement extends JEscDialog {
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/licenseagreement/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpHeading;
	private JLabel jlHeading;
	private JLabel jlSubHeading;
	private JLabel jlHeadingImage;
	private JPanel jpAgreement;
	private JScrollPane jspAgreement;
	private JEditorPane jepAgreement;
	private JRadioButton jrbAcceptLicense;
	private JRadioButton jrbRejectLicense;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private boolean agreed;

	/**
	 * Creates a new instance of DLicenseAgreement.
	 * 
	 * @param parent
	 *            Parent frame
	 * @param subject
	 *            Subject of the license agreement
	 * @param bannerIcon
	 *            Banner icon
	 * @param licenseAgreementUrl
	 *            License agreement URL
	 * @throws IOException
	 *             If the license URL is null or cannot be accessed
	 */
	public DLicenseAgreement(JFrame parent, String subject, Icon bannerIcon, URL licenseAgreementUrl)
			throws IOException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);

		initComponents(subject, bannerIcon, licenseAgreementUrl);
	}

	private void initComponents(String subject, Icon bannerIcon, URL licenseAgreementUrl) throws IOException {
		jpHeading = new JPanel(new GridBagLayout());
		jpHeading.setBackground(Color.WHITE);
		jpHeading.setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, Color.WHITE), new CompoundBorder(
				new MatteBorder(0, 0, 1, 0, Color.GRAY), new EmptyBorder(10, 10, 10, 10))));

		jlHeading = new JLabel(res.getString("DLicenseAgreement.jlHeading.text"), SwingConstants.LEFT);
		jlHeading.setFont(jlHeading.getFont().deriveFont(Font.BOLD));
		GridBagConstraints gbc_jlHeading = new GridBagConstraints();
		gbc_jlHeading.gridx = 0;
		gbc_jlHeading.gridy = 0;
		gbc_jlHeading.gridheight = 1;
		gbc_jlHeading.anchor = GridBagConstraints.WEST;
		gbc_jlHeading.fill = GridBagConstraints.HORIZONTAL;
		gbc_jlHeading.weightx = 1;

		jlSubHeading = new JLabel(res.getString("DLicenseAgreement.jlSubHeading.text"), SwingConstants.LEFT);
		GridBagConstraints gbc_jlSubHeading = new GridBagConstraints();
		gbc_jlSubHeading.gridx = 0;
		gbc_jlSubHeading.gridy = 1;
		gbc_jlSubHeading.gridheight = 1;
		gbc_jlSubHeading.anchor = GridBagConstraints.WEST;
		gbc_jlSubHeading.fill = GridBagConstraints.HORIZONTAL;
		gbc_jlSubHeading.insets = new Insets(5, 10, 0, 0);

		jlHeadingImage = new JLabel(bannerIcon, SwingConstants.RIGHT);
		GridBagConstraints gbc_jlHeadingImage = new GridBagConstraints();
		gbc_jlHeadingImage.gridx = 1;
		gbc_jlHeadingImage.gridy = 0;
		gbc_jlHeadingImage.gridheight = 3;
		gbc_jlHeadingImage.anchor = GridBagConstraints.NORTHEAST;
		gbc_jlHeadingImage.insets = new Insets(0, 10, 0, 0);

		jpHeading.add(jlHeading, gbc_jlHeading);
		jpHeading.add(jlSubHeading, gbc_jlSubHeading);
		jpHeading.add(jlHeadingImage, gbc_jlHeadingImage);

		jpAgreement = new JPanel(new GridBagLayout());
		jpAgreement.setBorder(new CompoundBorder(new MatteBorder(0, 0, 1, 0, Color.WHITE), new CompoundBorder(
				new MatteBorder(0, 0, 1, 0, Color.GRAY), new EmptyBorder(20, 20, 10, 20))));

		jepAgreement = new JEditorPane(licenseAgreementUrl);
		jepAgreement.setEditable(false);

		jspAgreement = PlatformUtil.createScrollPane(jepAgreement, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspAgreement.setPreferredSize(new Dimension(550, 250));
		GridBagConstraints gbc_jspReport = new GridBagConstraints();
		gbc_jspReport.gridx = 0;
		gbc_jspReport.gridy = 0;
		gbc_jspReport.anchor = GridBagConstraints.WEST;

		jpAgreement.add(jspAgreement, gbc_jspReport);

		jrbAcceptLicense = new JRadioButton(res.getString("DLicenseAgreement.jrbAcceptLicense.text"));
		GridBagConstraints gbc_jrbAcceptLicense = new GridBagConstraints();
		gbc_jrbAcceptLicense.gridx = 0;
		gbc_jrbAcceptLicense.gridy = 1;
		gbc_jrbAcceptLicense.anchor = GridBagConstraints.WEST;
		gbc_jrbAcceptLicense.insets = new Insets(10, 10, 0, 0);

		jrbRejectLicense = new JRadioButton(res.getString("DLicenseAgreement.jrbRejectLicense.text"));
		GridBagConstraints gbc_jrbRejectLicense = new GridBagConstraints();
		gbc_jrbRejectLicense.gridx = 0;
		gbc_jrbRejectLicense.gridy = 2;
		gbc_jrbRejectLicense.anchor = GridBagConstraints.WEST;
		gbc_jrbRejectLicense.insets = new Insets(0, 10, 0, 0);

		ButtonGroup bgAccept = new ButtonGroup();
		bgAccept.add(jrbAcceptLicense);
		bgAccept.add(jrbRejectLicense);

		jpAgreement.add(jrbAcceptLicense, gbc_jrbAcceptLicense);
		jpAgreement.add(jrbRejectLicense, gbc_jrbRejectLicense);

		jbOK = new JButton(res.getString("DLicenseAgreement.jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString("DLicenseAgreement.jbCancel.text"));
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

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpHeading, BorderLayout.NORTH);
		getContentPane().add(jpAgreement, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(jbOK);

		setTitle(MessageFormat.format(res.getString("DLicenseAgreement.Title"), subject));

		setResizable(false);

		pack();
	}

	/**
	 * Has license been agreed?
	 * 
	 * @return True if it has
	 */
	public boolean agreed() {
		return agreed;
	}

	private void okPressed() {
		if (jrbAcceptLicense.isSelected()) {
			agreed = true;
		} else if (jrbRejectLicense.isSelected()) {
			agreed = false;
		} else {
			JOptionPane.showMessageDialog(this, res.getString("DLicenseAgreement.MustAcceptOrReject.message"),
					getTitle(), JOptionPane.WARNING_MESSAGE);
			return;
		}

		closeDialog();
	}

	private void cancelPressed() {
		agreed = false;

		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
