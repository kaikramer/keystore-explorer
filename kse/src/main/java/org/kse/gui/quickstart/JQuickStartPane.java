/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2024 Kai Kramer
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
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Graphics;
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
import org.kse.gui.components.JEscFrame;
import org.kse.gui.dnd.DroppedFileHandler;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * KSE Quick Start pane. Displays quick start buttons for common start functions
 * of the application. Also, a drop target for opening KeyStore files.
 */
public class JQuickStartPane extends JGradientPanel implements DropTargetListener {
    private static final long serialVersionUID = 1L;

    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/quickstart/resources");

    // dark or light colors
    private static final Color DARK_GRADIENT_COLOR_1 = new Color(85, 85, 85);
    private static final Color DARK_GRADIENT_COLOR_2 = new Color(60, 63, 65);
    private static final Color DARK_TEXT_COLOR = new Color(116, 131, 141);
    private static final Color DARK_TEXT_ROLLOVER_COLOR = new Color(141, 141, 124);
    private static final Color LIGHT_GRADIENT_COLOR_1 =  Color.WHITE;
    private static final Color LIGHT_GRADIENT_COLOR_2 = Color.LIGHT_GRAY;
    private static final Color LIGHT_TEXT_COLOR = new Color(0, 134, 201);
    private static final Color LIGHT_TEXT_ROLLOVER_COLOR = new Color(135, 31, 120);

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
     * @param kseFrame KSE frame
     */
    public JQuickStartPane(KseFrame kseFrame) {
        super(LIGHT_GRADIENT_COLOR_1, LIGHT_GRADIENT_COLOR_2, DARK_GRADIENT_COLOR_1, DARK_GRADIENT_COLOR_2);

        this.kseFrame = kseFrame;

        // Make this pane a drop target and its own listener
        new DropTarget(this, this);

        initComponents();
    }

    private void initComponents() {
        jqslHeading = new JQuickStartLabel(res.getString("JQuickStartPane.jqslHeading.text"));
        jqslHeading.setForeground(LnfUtil.isDarkLnf() ? DARK_TEXT_COLOR : LIGHT_TEXT_COLOR);
        jqslHeading.setFont(jqslHeading.getFont().deriveFont(20f));

        Toolkit toolKit = Toolkit.getDefaultToolkit();

        ImageIcon newImage = new ImageIcon(toolKit.createImage(getClass().getResource("images/new.png")));
        ImageIcon newImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/new_rollover.png")));
        jqsbNewKeyStore = new JQuickStartButton(new NewAction(kseFrame),
                                                res.getString("JQuickStartPane.jqsbNewKeyStore.text"), newImage,
                                                newImageRollOver, LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                                DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbNewKeyStore.setOpaque(false);

        ImageIcon openImage = new ImageIcon(toolKit.createImage(getClass().getResource("images/open.png")));
        ImageIcon openImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/open_rollover.png")));
        jqsbOpenKeyStore = new JQuickStartButton(new OpenAction(kseFrame),
                                                 res.getString("JQuickStartPane.jqsbOpenKeyStore.text"), openImage,
                                                 openImageRollOver, LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                                 DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbOpenKeyStore.setOpaque(false);

        ImageIcon openDefaultImage = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/opendefault.png")));
        ImageIcon openDefaultImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/opendefault_rollover.png")));
        jqsbOpenDefaultKeyStore = new JQuickStartButton(new OpenDefaultAction(kseFrame),
                                                        res.getString("JQuickStartPane.jqsbOpenDefaultKeyStore.text"),
                                                        openDefaultImage, openDefaultImageRollOver,
                                                        LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                                        DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbOpenDefaultKeyStore.setOpaque(false);

        ImageIcon openCaCertificatesImage = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/opencacerts.png")));
        ImageIcon openCaCertificatesImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/opencacerts_rollover.png")));
        jqsbOpenCaCertificatesKeyStore = new JQuickStartButton(new OpenCaCertificatesAction(kseFrame), res.getString(
                "JQuickStartPane.jqsbOpenCaCertificatesKeyStore.text"), openCaCertificatesImage,
                                                               openCaCertificatesImageRollOver,
                                                               LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                                               DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbOpenCaCertificatesKeyStore.setOpaque(false);

        ImageIcon examineCertificateImage = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/examinecert.png")));
        ImageIcon examineCertificateImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/examinecert_rollover.png")));
        jqsbExamineCertificate = new JQuickStartButton(new ExamineFileAction(kseFrame),
                                                       res.getString("JQuickStartPane.jqsbExamineCertificate.text"),
                                                       examineCertificateImage, examineCertificateImageRollOver,
                                                       LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                                       DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbExamineCertificate.setOpaque(false);

        ImageIcon helpImage = new ImageIcon(toolKit.createImage(getClass().getResource("images/help.png")));
        ImageIcon helpImageRollOver = new ImageIcon(
                toolKit.createImage(getClass().getResource("images/help_rollover.png")));
        jqsbHelp = new JQuickStartButton(new HelpAction(kseFrame), res.getString("JQuickStartPane.jqsbHelp.text"),
                                         helpImage, helpImageRollOver,
                                         LIGHT_TEXT_COLOR, LIGHT_TEXT_ROLLOVER_COLOR,
                                         DARK_TEXT_COLOR, DARK_TEXT_ROLLOVER_COLOR);
        jqsbHelp.setOpaque(false);

        jpQuickStart = new JPanel();
        jpQuickStart.setOpaque(false);
        jpQuickStart.setLayout(new MigLayout("fill", "[center]para[center]", "[]para[]"));
        jpQuickStart.add(jqslHeading, "spanx, wrap");
        jpQuickStart.add(jqsbNewKeyStore);
        jpQuickStart.add(jqsbOpenKeyStore);
        jpQuickStart.add(jqsbOpenDefaultKeyStore, "wrap");
        jpQuickStart.add(jqsbOpenCaCertificatesKeyStore);
        jpQuickStart.add(jqsbExamineCertificate);
        jpQuickStart.add(jqsbHelp);

        // Put in panel to prevent resize of controls and center them horizontally
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

    @Override
    public void paintComponent(Graphics g) {
        super.paintComponent(g);
        jqslHeading.setForeground(LnfUtil.isDarkLnf() ? DARK_TEXT_COLOR : LIGHT_TEXT_COLOR);
    }

    // for quick testing
    public static void main(String[] args) throws Exception {
        DialogViewer.prepare();
        KseFrame kseFrame = new KseFrame();
        JEscFrame frame = new JEscFrame("Test");
        JQuickStartPane jQuickStartPane = new JQuickStartPane(kseFrame);
        frame.add(jQuickStartPane);
        frame.setMinimumSize(new Dimension(800, 600));
        DialogViewer.run(frame);
    }
}
