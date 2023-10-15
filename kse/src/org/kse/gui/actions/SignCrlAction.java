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

package org.kse.gui.actions;

import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.awt.Toolkit;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.importexport.DExportCrl;
import org.kse.gui.dialogs.sign.DSignCrl;
import org.kse.gui.dialogs.sign.RevokedEntry;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;
import org.kse.utilities.pem.PemInfo;
import org.kse.utilities.pem.PemUtil;

/**
 * Action to create a list of revoked certificates CRL.
 */
public class SignCrlAction extends KeyStoreExplorerAction {
    private static final long serialVersionUID = 1L;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SignCrlAction(KseFrame kseFrame) {
        super(kseFrame);

        putValue(LONG_DESCRIPTION, res.getString("SignCrlAction.statusbar"));
        putValue(NAME, res.getString("SignCrlAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SignCrlAction.tooltip"));
        putValue(SMALL_ICON,
                 new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/signcrl.png"))));
    }

    @Override
    protected void doAction() {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStoreState currentState = history.getCurrentState();

            String alias = kseFrame.getSelectedEntryAlias();

            Password password = getEntryPassword(alias, currentState);

            if (password == null) {
                return;
            }
            KeyStore keyStore = currentState.getKeyStore();

            String provider = BOUNCY_CASTLE.jce();
            if (history.getExplicitProvider() != null) {
                provider = history.getExplicitProvider().getName();
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            X509Certificate[] certs = X509CertUtil.orderX509CertChain(
                    X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));

            KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

            File filePrevious = getFilePrevious(certs[0], history);

            X509CRL x509CRL = loadPreviousCrl(filePrevious, certs[0]);

            DSignCrl dSignCrl = new DSignCrl(frame, kseFrame, keyPairType, privateKey, certs[0], x509CRL);
            dSignCrl.setLocationRelativeTo(frame);
            dSignCrl.setVisible(true);
            Date effectiveDate = dSignCrl.getEffectiveDate();
            if (effectiveDate != null) {
                Date nextUpdate = dSignCrl.getNextUpdate();
                BigInteger crlNumber = dSignCrl.getCrlNumber();
                String signatureAlgorithm = dSignCrl.getSignatureType().jce();
                Map<BigInteger, RevokedEntry> mapRevoked = dSignCrl.getMapRevokedEntry();

                x509CRL = signCrl(crlNumber, effectiveDate, nextUpdate, certs[0], privateKey, signatureAlgorithm,
                                  mapRevoked, provider);
                String newFileName = X509CertUtil.getShortName(certs[0]).toLowerCase();
                DExportCrl dExportCrl = new DExportCrl(frame, newFileName);
                dExportCrl.setLocationRelativeTo(frame);
                dExportCrl.setVisible(true);
                if (dExportCrl.exportSelected()) {
                    exportFile(x509CRL, filePrevious, false);// export CRL .db
                    exportFile(x509CRL, dExportCrl.getExportFile(), dExportCrl.pemEncode());// export file .crl
                    JOptionPane.showMessageDialog(frame, res.getString("SignCrlAction.SignCrlSuccessful.message"),
                                                  res.getString("SignCrlAction.SignCrl.Title"),
                                                  JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private File getFilePrevious(X509Certificate caCert, KeyStoreHistory history) {
        String serial = caCert.getSerialNumber().toString(16);
        String pathFile = history.getPath();
        File fileParent = new File(pathFile);
        if (fileParent.getParentFile() == null) {
            return null;
        }
        String path = fileParent.getParentFile().getAbsolutePath();
        String newPath = path + File.separator + serial + ".db";
        File filePrevious = new File(newPath);
        return filePrevious;
    }

    private X509CRL loadPreviousCrl(File filePrevious, X509Certificate caCert) {
        if (filePrevious == null) {
            return null;
        }
        try (FileInputStream is = new FileInputStream(filePrevious)) {
            X509CRL crl = X509CertUtil.loadCRL(IOUtils.toByteArray(is));
            crl.verify(caCert.getPublicKey());
            return crl;
        } catch (InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | IOException | CryptoException e) {
            // ignore
        }
        return null;
    }

    private X509CRL signCrl(BigInteger number, Date effectiveDate, Date nextUpdate, X509Certificate caCert,
                            PrivateKey caPrivateKey, String signatureAlgorithm,
                            Map<BigInteger, RevokedEntry> mapRevokedCertificate, String provider)
            throws NoSuchAlgorithmException, OperatorCreationException, CRLException, IOException {

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), effectiveDate);
        crlGen.setNextUpdate(nextUpdate);

        if (mapRevokedCertificate != null) {

            for (Map.Entry<BigInteger, RevokedEntry> pair : mapRevokedCertificate.entrySet()) {
                RevokedEntry entry = pair.getValue();
                crlGen.addCRLEntry(entry.getUserCertificateSerial(), entry.getRevocationDate(), entry.getReason());
            }
        }
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(number));

        X509CRLHolder crl = crlGen.build(
                new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(caPrivateKey));
        return new JcaX509CRLConverter().setProvider(KSE.BC).getCRL(crl);
    }

    private void exportFile(X509CRL x509CRL, File fileExported, boolean pemEncode)
            throws FileNotFoundException, IOException, CRLException {

        if (fileExported == null) {
            return;
        }
        byte[] data = null;
        if (pemEncode) {
            PemInfo pemInfo = new PemInfo("X509 CRL", null, x509CRL.getEncoded());
            data = PemUtil.encode(pemInfo).getBytes();
        } else {
            data = x509CRL.getEncoded();
        }
        try (InputStream in = new ByteArrayInputStream(data)) {
            int length;
            byte[] buffer = new byte[1024];
            try (FileOutputStream fileOutputStream = new FileOutputStream(fileExported)) {
                while ((length = in.read(buffer)) != -1) {
                    fileOutputStream.write(buffer, 0, length);
                }
            }
        }
    }
}
