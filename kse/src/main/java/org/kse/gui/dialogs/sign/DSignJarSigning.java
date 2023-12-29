/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2023 Kai Kramer
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

package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.kse.crypto.digest.DigestType;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.SignatureType;
import org.kse.gui.JEscDialog;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * <h1>Jar Signing</h1> The class initiates jar signing.
 * <p>
 * The user may cancel at any time by pressing the cancel button.
 */
public class DSignJarSigning extends JEscDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");

    private static final String CANCEL_KEY = "CANCEL_KEY";

    private JLabel jlSignJar;
    private JProgressBar jpbSignJar;
    private JButton jbCancel;

    private Map<String, String> fileExceptions;
    private File[] inputJarFiles;
    private List<File> outputJarFiles;
    private PrivateKey privateKey;
    private X509Certificate[] certs;
    private SignatureType signatureType;
    private String signatureName;
    private String signer;
    private DigestType digestType;
    private String tsaUrl;
    private Provider provider;

    private Thread generator;
    private boolean successStatus = true;

    /**
     * Creates a new DSignJarSigning dialog.
     *
     * @param parent  The parent frame
     */
    public DSignJarSigning(JFrame parent, File[] inputJarFiles, List<File> outputJarFiles, PrivateKey privateKey,
                           X509Certificate[] certs, SignatureType signatureType, String signatureName, String signer,
                           DigestType digestType, String tsaUrl, Provider provider) {
        super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
        this.inputJarFiles = inputJarFiles;
        this.outputJarFiles = outputJarFiles;
        this.privateKey = privateKey;
        this.certs = certs;
        this.signatureType = signatureType;
        this.signatureName = signatureName;
        this.signer = signer;
        this.digestType = digestType;
        this.tsaUrl = tsaUrl;
        this.provider = provider;
        initComponents();
    }

    /**
     * Initializes the dialogue panel and associated elements
     */
    private void initComponents() {

        // TODO Create Jar sign icon

        jlSignJar = new JLabel(res.getString("DSignJarSigning.jlSignJar.text"));
		/*
		ImageIcon icon = new ImageIcon(getClass().getResource("images/genkp.png"));
		jlSignJar.setIcon(icon);
		 */

        jpbSignJar = new JProgressBar(0, inputJarFiles.length);
        jpbSignJar.setIndeterminate(false);

        jbCancel = new JButton(res.getString("DSignJarSigning.jbCancel.text"));
        jbCancel.addActionListener(evt -> cancelPressed());
        jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), CANCEL_KEY);
        jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]unrel"));
        pane.add(jlSignJar, "wrap");
        pane.add(jpbSignJar, "growx, wrap");
        pane.add(jbCancel, "tag Cancel");

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent evt) {
                if ((generator != null) && (generator.isAlive())) {
                    generator.interrupt();
                }
                closeDialog();
            }
        });

        setTitle(res.getString("DSignJarSigning.Title"));
        setResizable(false);

        pack();
    }

    /**
     * Start signing in a separate thread.
     */
    public void startDSignJarSigning() {
        generator = new Thread(new signJars());
        generator.setPriority(Thread.MIN_PRIORITY);
        generator.start();
    }

    /**
     * Returns the current success status
     *
     * @return successStatus The success status boolean
     */
    public boolean isSuccessful() {
        return successStatus;
    }

    /**
     * Calls the close dialogue, Sets the success value to false
     */
    private void cancelPressed() {
        if ((generator != null) && (generator.isAlive())) {
            generator.interrupt();
        }
        successStatus = false;
        closeDialog();
    }

    /**
     * Closes the dialogue
     */
    private void closeDialog() {
        setVisible(false);
        dispose();
    }

    /**
     * Get the generated errors during signing.
     *
     * @return Map of the generated signing errors.
     */
    public Map<String, String> getFileExceptions() {
        return fileExceptions;

    }

    /**
     * Generates the Jar signing
     * <p>
     * Signs the jars.
     * <p>
     * Errors generated during the signing are set to the map.
     */
    private class signJars implements Runnable {
        @Override
        public void run() {
            try {
                // set new hashmap
                fileExceptions = new HashMap<>();
                for (int i = 0; i < inputJarFiles.length; i++) {
                    try {
                        if (inputJarFiles[i].equals(outputJarFiles.get(i))) {
                            JarSigner.sign(inputJarFiles[i], privateKey, certs, signatureType, signatureName, signer,
                                           digestType, tsaUrl, provider);
                        } else {
                            JarSigner.sign(inputJarFiles[i], outputJarFiles.get(i), privateKey, certs, signatureType,
                                           signatureName, signer, digestType, tsaUrl, provider);
                        }
                    }
                    // Add any jar sign exceptions to the map
                    catch (Exception e) {
                        fileExceptions.put(inputJarFiles[i].getName(), e.toString());
                    }
                    // update the progress bar
                    jpbSignJar.setValue(i);
                }

                SwingUtilities.invokeLater(() -> {
                    if (DSignJarSigning.this.isShowing()) {
                        closeDialog();
                    }
                });
            } catch (final Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (DSignJarSigning.this.isShowing()) {
                        DError dError = new DError(DSignJarSigning.this, ex);
                        dError.setLocationRelativeTo(DSignJarSigning.this);
                        dError.setVisible(true);
                        closeDialog();
                    }
                });
            }
        }
    }
}
