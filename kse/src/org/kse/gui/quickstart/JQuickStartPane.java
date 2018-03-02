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
package org.kse.gui.quickstart;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.util.ResourceBundle;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JPanel;

import org.kse.gui.KseFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.actions.ExamineFileAction;
import org.kse.gui.actions.HelpAction;
import org.kse.gui.actions.NewAction;
import org.kse.gui.actions.OpenAction;
import org.kse.gui.actions.OpenCaCertificatesAction;
import org.kse.gui.actions.OpenDefaultAction;
import org.kse.gui.dnd.DroppedFileHandler;
import org.kse.gui.gradient.JGradientPanel;

/**
 * KSE Quick Start pane. Displays quick start buttons for common start functions
 * of the application. Also a drop target for opening KeyStore files.
 *
 */
public class JQuickStartPane extends JGradientPanel implements DropTargetListener {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/quickstart/resources");

	// set dark or light colors (depending on active LaF)
	private static final boolean IS_DARK_LAF = LnfUtil.isDarkLnf();
	private static final Color GRADIENT_COLOR_1 = IS_DARK_LAF ? new Color(85, 85, 85) : Color.WHITE;
	private static final Color GRADIENT_COLOR_2 = IS_DARK_LAF ? new Color(60, 63, 65) : Color.LIGHT_GRAY;
	private static final Color TEXT_COLOR = IS_DARK_LAF ? new Color(116, 131, 141) : new Color(0, 134, 201);
	private static final Color TEXT_ROLLOVER_COLOR = IS_DARK_LAF ? new Color(141, 141, 124) : new Color(135, 31, 120);

	private KseFrame kseFrame;

	private JPanel jpQuickStart;
	private JQuickStartLabel jqslHeading;
	private JQuickStartButton jqsbNewKeyStore;
	private JQuickStartButton jqsbOpenKeyStore;
	private JQuickStartButton jqsbOpenDefaultKeyStore;
	private JQuickStartButton jqsbOpenCaCertificatesKeyStore;
	private JQuickStartButton jqsbExamineCertificate;
	private JQuickStartButton jqsbHelp;
	private JPanel jpNonResizeCenterHorizontally;

	/**
	 * Construct Quick Start pane.
	 *
	 * @param kseFrame
	 *            KSE frame
	 */
	public JQuickStartPane(KseFrame kseFrame) {
		super(GRADIENT_COLOR_1, GRADIENT_COLOR_2);

		this.kseFrame = kseFrame;

		// Make this pane a drop target and its own listener
		new DropTarget(this, this);

		initComponents();
	}

	private void initComponents() {
		jqslHeading = new JQuickStartLabel(res.getString("JQuickStartPane.jqslHeading.text"));
		jqslHeading.setForeground(TEXT_COLOR);
		jqslHeading.setFont(jqslHeading.getFont().deriveFont(20f));

		Toolkit toolKit = Toolkit.getDefaultToolkit();

		ImageIcon newImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbNewKeyStore.image"))));
		ImageIcon newImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbNewKeyStore.rollover.image"))));
		jqsbNewKeyStore = new JQuickStartButton(new NewAction(kseFrame),
				res.getString("JQuickStartPane.jqsbNewKeyStore.text"), newImage, newImageRollOver, TEXT_COLOR,
				TEXT_ROLLOVER_COLOR);
		jqsbNewKeyStore.setOpaque(false);

		ImageIcon openImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenKeyStore.image"))));
		ImageIcon openImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenKeyStore.rollover.image"))));
		jqsbOpenKeyStore = new JQuickStartButton(new OpenAction(kseFrame),
				res.getString("JQuickStartPane.jqsbOpenKeyStore.text"), openImage, openImageRollOver, TEXT_COLOR,
				TEXT_ROLLOVER_COLOR);
		jqsbOpenKeyStore.setOpaque(false);

		ImageIcon openDefaultImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenDefaultKeyStore.image"))));
		ImageIcon openDefaultImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenDefaultKeyStore.rollover.image"))));
		jqsbOpenDefaultKeyStore = new JQuickStartButton(new OpenDefaultAction(kseFrame),
				res.getString("JQuickStartPane.jqsbOpenDefaultKeyStore.text"), openDefaultImage,
				openDefaultImageRollOver, TEXT_COLOR, TEXT_ROLLOVER_COLOR);
		jqsbOpenDefaultKeyStore.setOpaque(false);

		ImageIcon openCaCertificatesImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenCaCertificatesKeyStore.image"))));
		ImageIcon openCaCertificatesImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbOpenCaCertificatesKeyStore.rollover.image"))));
		jqsbOpenCaCertificatesKeyStore = new JQuickStartButton(new OpenCaCertificatesAction(kseFrame),
				res.getString("JQuickStartPane.jqsbOpenCaCertificatesKeyStore.text"), openCaCertificatesImage,
				openCaCertificatesImageRollOver, TEXT_COLOR, TEXT_ROLLOVER_COLOR);
		jqsbOpenCaCertificatesKeyStore.setOpaque(false);

		ImageIcon examineCertificateImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbExamineCertificate.image"))));
		ImageIcon examineCertificateImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbExamineCertificate.rollover.image"))));
		jqsbExamineCertificate = new JQuickStartButton(new ExamineFileAction(kseFrame),
				res.getString("JQuickStartPane.jqsbExamineCertificate.text"), examineCertificateImage,
				examineCertificateImageRollOver, TEXT_COLOR, TEXT_ROLLOVER_COLOR);
		jqsbExamineCertificate.setOpaque(false);

		ImageIcon helpImage = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbHelp.image"))));
		ImageIcon helpImageRollOver = new ImageIcon(toolKit.createImage(getClass().getResource(
				res.getString("JQuickStartPane.jqsbHelp.rollover.image"))));
		jqsbHelp = new JQuickStartButton(new HelpAction(kseFrame), res.getString("JQuickStartPane.jqsbHelp.text"),
				helpImage, helpImageRollOver, TEXT_COLOR, TEXT_ROLLOVER_COLOR);
		jqsbHelp.setOpaque(false);

		GridBagConstraints gbc_jqslHeading = new GridBagConstraints();
		gbc_jqslHeading.gridheight = 1;
		gbc_jqslHeading.gridwidth = 3;
		gbc_jqslHeading.gridx = 0;
		gbc_jqslHeading.gridy = 0;
		gbc_jqslHeading.insets = new Insets(0, 0, 20, 0);

		GridBagConstraints gbc_jqsbNewKeyStore = new GridBagConstraints();
		gbc_jqsbNewKeyStore.gridheight = 1;
		gbc_jqsbNewKeyStore.gridwidth = 1;
		gbc_jqsbNewKeyStore.gridx = 0;
		gbc_jqsbNewKeyStore.gridy = 1;
		gbc_jqsbNewKeyStore.insets = new Insets(0, 0, 10, 10);

		GridBagConstraints gbc_jqsbOpenKeyStore = new GridBagConstraints();
		gbc_jqsbOpenKeyStore.gridheight = 1;
		gbc_jqsbOpenKeyStore.gridwidth = 1;
		gbc_jqsbOpenKeyStore.gridx = 1;
		gbc_jqsbOpenKeyStore.gridy = 1;
		gbc_jqsbOpenKeyStore.insets = new Insets(0, 10, 10, 10);

		GridBagConstraints gbc_jqsbOpenDefaultKeyStore = new GridBagConstraints();
		gbc_jqsbOpenDefaultKeyStore.gridheight = 1;
		gbc_jqsbOpenDefaultKeyStore.gridwidth = 1;
		gbc_jqsbOpenDefaultKeyStore.gridx = 2;
		gbc_jqsbOpenDefaultKeyStore.gridy = 1;
		gbc_jqsbOpenDefaultKeyStore.insets = new Insets(0, 10, 10, 10);

		GridBagConstraints gbc_jqsbOpenCaCertificatesKeyStore = new GridBagConstraints();
		gbc_jqsbOpenCaCertificatesKeyStore.gridheight = 1;
		gbc_jqsbOpenCaCertificatesKeyStore.gridwidth = 1;
		gbc_jqsbOpenCaCertificatesKeyStore.gridx = 0;
		gbc_jqsbOpenCaCertificatesKeyStore.gridy = 2;
		gbc_jqsbOpenCaCertificatesKeyStore.insets = new Insets(10, 0, 0, 10);

		GridBagConstraints gbc_jqsbExamineCertificate = new GridBagConstraints();
		gbc_jqsbExamineCertificate.gridheight = 1;
		gbc_jqsbExamineCertificate.gridwidth = 1;
		gbc_jqsbExamineCertificate.gridx = 1;
		gbc_jqsbExamineCertificate.gridy = 2;
		gbc_jqsbExamineCertificate.insets = new Insets(10, 10, 0, 10);

		GridBagConstraints gbc_jqsbHelp = new GridBagConstraints();
		gbc_jqsbHelp.gridheight = 1;
		gbc_jqsbHelp.gridwidth = 1;
		gbc_jqsbHelp.gridx = 2;
		gbc_jqsbHelp.gridy = 2;
		gbc_jqsbHelp.insets = new Insets(10, 10, 0, 0);

		jpQuickStart = new JPanel(new GridBagLayout());
		jpQuickStart.setOpaque(false);

		jpQuickStart.add(jqslHeading, gbc_jqslHeading);
		jpQuickStart.add(jqsbNewKeyStore, gbc_jqsbNewKeyStore);
		jpQuickStart.add(jqsbOpenKeyStore, gbc_jqsbOpenKeyStore);
		jpQuickStart.add(jqsbOpenDefaultKeyStore, gbc_jqsbOpenDefaultKeyStore);
		jpQuickStart.add(jqsbOpenCaCertificatesKeyStore, gbc_jqsbOpenCaCertificatesKeyStore);
		jpQuickStart.add(jqsbExamineCertificate, gbc_jqsbExamineCertificate);
		jpQuickStart.add(jqsbHelp, gbc_jqsbHelp);

		// Put in panel to prevent resize of controls and center them
		// horizontally
		jpNonResizeCenterHorizontally = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
		jpNonResizeCenterHorizontally.setOpaque(false);
		jpNonResizeCenterHorizontally.add(jpQuickStart);

		// Set pane's layout to center controls vertically
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(Box.createVerticalGlue());
		add(jpNonResizeCenterHorizontally);
	}

	@Override
	public void drop(DropTargetDropEvent evt) {
		DroppedFileHandler.drop(evt, kseFrame);
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
}
