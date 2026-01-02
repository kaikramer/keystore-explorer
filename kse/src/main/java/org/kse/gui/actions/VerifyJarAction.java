/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
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

package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.kse.crypto.signing.CmsUtil;
import org.kse.crypto.signing.JarSigner;
import org.kse.crypto.signing.KseJarEntry;
import org.kse.crypto.signing.KseSignerInformation;
import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewSignedJar;
import org.kse.gui.error.DError;

/**
 * Action to verify a digitally signed JAR file.
 */
public class VerifyJarAction extends AuthorityCertificatesVerifyAction {
    private static final long serialVersionUID = 1L;

    /**
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public VerifyJarAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke('J',
                Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() + InputEvent.ALT_DOWN_MASK));
        putValue(LONG_DESCRIPTION, res.getString("VerifyJarAction.statusbar"));
        putValue(NAME, res.getString("VerifyJarAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("VerifyJarAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/verifyjar.png"))));
    }

    @Override
    protected void doAction() {
        try {
            File file = chooseJarFile();
            if (file == null) {
                return;
            }

            Set<X509Certificate> allCerts = getTrustedCertificates();

            List<KseJarEntry> entries = new ArrayList<>();
            Map<String, byte[]> signatureFiles = new HashMap<>();
            Map<String, CMSSignedData> signatureBlocks = new HashMap<>();

            // Read the JAR using JarFile since JarInputStream skips MANIFEST.MF.
            try (JarFile jarFile = new JarFile(file, true)) {

                for (Enumeration<JarEntry> jarEntries = jarFile.entries(); jarEntries.hasMoreElements(); ) {
                    JarEntry entry = jarEntries.nextElement();

                    String name = entry.getName();
                    String uname = entry.getName().toUpperCase(Locale.ENGLISH);
                    StringBuilder flags = new StringBuilder();

                    if (isSignatureBlock(uname)) {
                        byte[] signature = readAllBytesAutoClose(jarFile.getInputStream(entry));
                        CMSSignedData signatureBlock = new CMSSignedData(signature);
                        if (signatureBlock.isDetachedSignature()) {
                            byte[] sfFile = signatureFiles.get(name.substring(0, name.lastIndexOf('.')) + ".SF");
                            signatureBlock = new CMSSignedData(new CMSProcessableByteArray(sfFile), signature);
                        }
                        signatureBlocks.put(name, signatureBlock);
                    }

                    // signature file
                    if (uname.startsWith("META-INF/") && uname.endsWith(".SF")) {
                        signatureFiles.put(name, readAllBytesAutoClose(jarFile.getInputStream(entry)));
                    }

                    // Need to read all bytes to populate signers and certs.
                    readAllBytesAutoClose(jarFile.getInputStream(entry));

                    // entry is signed
                    if (!Arrays.isNullOrEmpty(entry.getCodeSigners())) {
                        flags.append(KseJarEntry.FLAG_SIGNED);
                    } else {
                        flags.append(KseJarEntry.FLAG_BLANK);
                    }

                    // entry is in the manifest
                    Attributes attributes = entry.getAttributes();
                    if (attributes != null) {
                        flags.append(KseJarEntry.FLAG_MANIFEST);
                    } else {
                        flags.append(KseJarEntry.FLAG_BLANK);
                    }

                    // entry has at least one certificate in the key store
                    boolean containsCert = false;
                    if (entry.getCertificates() != null) {
                        for (Certificate cert : entry.getCertificates()) {
                            // once true, always true
                            containsCert |= allCerts.contains(cert);
                        }
                    }
                    if (containsCert) {
                        flags.append(KseJarEntry.FLAG_CERT);
                    } else {
                        flags.append(KseJarEntry.FLAG_BLANK);
                    }

                    entries.add(new KseJarEntry(entry, flags.toString()));
                }
            } catch (SecurityException e) {
                JOptionPane.showMessageDialog(frame,
                        MessageFormat.format(res.getString("VerifyJarAction.Invalid.message"),
                                e.toString()),
                        res.getString("VerifyJarAction.VerifyJar.Title"), JOptionPane.ERROR_MESSAGE);

                return;
            }

            if (signatureBlocks.isEmpty()) {
                JOptionPane.showMessageDialog(frame,
                        MessageFormat.format(res.getString("VerifyJarAction.NoSignatures.message"),
                                file.getName()),
                        res.getString("VerifyJarAction.VerifyJar.Title"), JOptionPane.INFORMATION_MESSAGE);

                return;
            }

            @SuppressWarnings("unchecked")
            Store<X509CertificateHolder> trustedCerts = new JcaCertStore(allCerts);

            Map<String, Collection<KseSignerInformation>> jarSigners = new HashMap<>();
            for (Entry<String, CMSSignedData> signatureBlock : signatureBlocks.entrySet()) {
                SignerInformationStore signerInfos = signatureBlock.getValue().getSignerInfos();
                Collection<KseSignerInformation> signers = CmsUtil.convertSignerInformations(signerInfos.getSigners(),
                        trustedCerts, signatureBlock.getValue());
                jarSigners.put(signatureBlock.getKey(), signers);
            }

            DViewSignedJar dViewSignedJar = new DViewSignedJar(frame, MessageFormat
                    .format(res.getString("VerifyJarAction.SignatureDetailsFile.Title"), file.getName()),
                    entries, jarSigners, getTrustedCertsNoPrefs(), kseFrame);
            dViewSignedJar.setLocationRelativeTo(frame);
            dViewSignedJar.setVisible(true);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private byte[] readAllBytesAutoClose(InputStream stream) throws IOException {
        try (InputStream is = stream) {
            return is.readAllBytes();
        }
    }

    private boolean isSignatureBlock(String entryName) {
        return entryName.startsWith("META-INF/") //
                && (entryName.endsWith(JarSigner.RSA_SIG_BLOCK_EXT) //
                || entryName.endsWith(JarSigner.EC_SIG_BLOCK_EXT) //
                || entryName.endsWith(JarSigner.DSA_SIG_BLOCK_EXT));
    }

    private File chooseJarFile() {
        JFileChooser chooser = FileChooserFactory.getArchiveFileChooser();
        chooser.setCurrentDirectory(CurrentDirectory.get());
        chooser.setDialogTitle(res.getString("VerifyJarAction.ChooseJar.Title"));
        chooser.setMultiSelectionEnabled(false);
        chooser.setApproveButtonText(res.getString("VerifyJarAction.ChooseJar.button"));

        int rtnValue = chooser.showOpenDialog(frame);
        if (rtnValue == JFileChooser.APPROVE_OPTION) {
            File importFile = chooser.getSelectedFile();
            CurrentDirectory.updateForFile(importFile);
            return importFile;
        }
        return null;
    }
}
