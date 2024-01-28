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

package org.kse.gui.actions;

import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.kse.KSE;
import org.kse.crypto.CryptoException;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DVerifyCertificate;
import org.kse.gui.dialogs.DVerifyCertificate.VerifyOptions;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.utilities.StringUtils;
import org.kse.utilities.history.KeyStoreHistory;

public class VerifyCertificateAction extends KeyStoreExplorerAction {

    private static final long serialVersionUID = 1L;
    private X509Certificate certificateEval;
    private X509Certificate[] keyCertChain;

    public VerifyCertificateAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(LONG_DESCRIPTION, res.getString("VerifyCertificateAction.statusbar"));
        putValue(NAME, res.getString("VerifyCertificateAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("VerifyCertificateAction.tooltip"));
        putValue(SMALL_ICON, new ImageIcon(
                Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/verifycert.png"))));
    }

    public VerifyCertificateAction(KseFrame kseFrame, X509Certificate cert, X509Certificate[] keyCertChain) {
        super(kseFrame);
        this.certificateEval = cert;
        this.keyCertChain = keyCertChain;
    }

    @Override
    protected void doAction() {

        String alias = "";
        try {
            if (certificateEval == null) {
                alias = kseFrame.getSelectedEntryAlias();
                certificateEval = getCertificate(alias);
                keyCertChain = getCertificateChain(alias);
            } else {
                alias = X509CertUtil.getCertificateAlias(certificateEval);
            }
            // if the certificate is expired it should not be evaluated
            Date now = new Date(System.currentTimeMillis());
            if (certificateEval.getNotAfter().before(now)) {
                JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.certExpired.message"),
                                              MessageFormat.format(
                                                      res.getString("VerifyCertificateAction.Verify.Title"), alias),
                                              JOptionPane.WARNING_MESSAGE);
            } else {
                DVerifyCertificate dVerifyCertificate = new DVerifyCertificate(frame, alias, kseFrame);
                dVerifyCertificate.setLocationRelativeTo(frame);
                dVerifyCertificate.setVisible(true);
                if (dVerifyCertificate.isVerifySelected()) {

                    VerifyOptions verifyOptions = dVerifyCertificate.getVerifyOption();
                    KeyStoreHistory keyStoreHistory = dVerifyCertificate.getKeyStore();
                    if (verifyOptions == VerifyOptions.CRL_DIST) {
                        verifyStatusCrl(keyStoreHistory, alias);
                    } else if (verifyOptions == VerifyOptions.CRL_FILE) {
                        verifyStatusCrlFile(keyStoreHistory, alias, dVerifyCertificate.getCrlFile());
                    } else if (verifyOptions == VerifyOptions.OCSP_AIA) {
                        verifyStatusOCSP(keyStoreHistory, alias);
                    } else if (verifyOptions == VerifyOptions.OCSP_URL) {
                        verifyStatusOcspUrl(keyStoreHistory, alias, dVerifyCertificate.getOcspUrl());
                    } else {
                        verifyChain(keyStoreHistory, alias);
                    }
                }
            }
        } catch (CertPathValidatorException cex) {
            DError.displayError(frame, cex);
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        } finally {
            certificateEval = null;
        }
    }

    private void verifyChain(KeyStoreHistory keyStoreHistory, String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
                   InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException,
                   CryptoException {
        if (verify("false", "false", false, keyStoreHistory, null, alias)) {
            JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.ChainSuccessful.message"),
                                          MessageFormat.format(res.getString("VerifyCertificateAction.Verify.Title"),
                                                               alias), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void verifyStatusOCSP(KeyStoreHistory keyStoreHistory, String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
                   InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException,
                   CryptoException {
        if (verify("false", "true", true, keyStoreHistory, null, alias)) {
            JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.OcspSuccessful.message"),
                                          MessageFormat.format(res.getString("VerifyCertificateAction.Verify.Title"),
                                                               alias), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void verifyStatusOcspUrl(KeyStoreHistory keyStoreHistory, String alias, String ocspUrl)
            throws OperatorCreationException, OCSPException, IOException, HeadlessException, CertPathValidatorException,
                   KeyStoreException, NoSuchAlgorithmException, CertificateException,
                   InvalidAlgorithmParameterException, IllegalStateException, CryptoException {

        if (verify("false", "false", false, keyStoreHistory, null, alias)) {
            // search issuer
            X509Certificate issuer = null;

            if (keyCertChain == null || keyCertChain.length == 1) {
                KeyStore trustStore = getKeyStore(keyStoreHistory);
                Enumeration<String> enumeration = trustStore.aliases();
                while (enumeration.hasMoreElements()) {
                    String tempAlias = enumeration.nextElement();
                    X509Certificate cert = (X509Certificate) trustStore.getCertificate(tempAlias);
                    try {
                        certificateEval.verify(cert.getPublicKey());
                        issuer = cert;
                        break;
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        // ignore
                    }
                }
            } else {
                issuer = keyCertChain[1];
            }
            if (issuer == null) {
                throw new CertPathValidatorException(res.getString("VerifyCertificateAction.trustStoreEmpty.message"));
            }
            OCSPReq request = makeOcspRequest(issuer, certificateEval);
            OCSPResp response = requestOCSPResponse(ocspUrl, request);
            if (isGoodCertificate(response)) {
                JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.OcspSuccessful.message"),
                                              MessageFormat.format(
                                                      res.getString("VerifyCertificateAction.Verify.Title"), alias),
                                              JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private static OCSPReq makeOcspRequest(X509Certificate caCert, X509Certificate certToCheck)
            throws OCSPException, OperatorCreationException, CertificateEncodingException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(KSE.BC)
                                                                                       .build();

        CertificateID certId = new JcaCertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCert,
                                                    certToCheck.getSerialNumber());

        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(certId);
        return gen.build();
    }

    private OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq) throws IOException {
        byte[] ocspReqData = ocspReq.getEncoded();

        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        try {
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setUseCaches(false);
            try (OutputStream out = con.getOutputStream()) {
                IOUtils.write(ocspReqData, out);
                out.flush();
            }
            byte[] responseBytes = IOUtils.toByteArray(con.getInputStream());
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            return ocspResp;
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }

    private boolean isGoodCertificate(OCSPResp ocspResp) throws OCSPException, CertPathValidatorException {

        if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
            throw new CertPathValidatorException(getMessageStatus(ocspResp.getStatus()));
        }
        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        SingleResp first = basicResponse.getResponses()[0];

        CertificateStatus certStatus = first.getCertStatus();

        if (certStatus != CertificateStatus.GOOD) {
            if (certStatus instanceof RevokedStatus) {
                RevokedStatus status = (RevokedStatus) certStatus;
                int reason;
                try {
                    reason = status.getRevocationReason();
                } catch (IllegalStateException ex) {
                    reason = -1;
                }
                Date revocationTime = status.getRevocationTime();
                throw new CertPathValidatorException(
                        MessageFormat.format(res.getString("VerifyCertificateAction.revokedStatus.message"), reason,
                                             StringUtils.formatDate(revocationTime)));
            } else {
                throw new CertPathValidatorException(
                        MessageFormat.format(res.getString("VerifyCertificateAction.certStatus.message"), certStatus));
            }
        }
        BigInteger certSerial = certificateEval.getSerialNumber();
        BigInteger ocspSerial = first.getCertID().getSerialNumber();
        if (!certSerial.equals(ocspSerial)) {
            throw new CertPathValidatorException(
                    MessageFormat.format(res.getString("VerifyCertificateAction.badSerials.message"), certSerial,
                                         ocspSerial));
        }
        return true;
    }

    private String getMessageStatus(int status) {
        if (status == OCSPResp.MALFORMED_REQUEST) {
            return res.getString("VerifyCertificateAction.malformedRequest.message");
        }
        if (status == OCSPResp.INTERNAL_ERROR) {
            return res.getString("VerifyCertificateAction.internalError.message");
        }
        if (status == OCSPResp.TRY_LATER) {
            return res.getString("VerifyCertificateAction.tryLater.message");
        }
        if (status == OCSPResp.SIG_REQUIRED) {
            return res.getString("VerifyCertificateAction.sigRequired.message");
        }
        if (status == OCSPResp.UNAUTHORIZED) {
            return res.getString("VerifyCertificateAction.unauthorized.message");
        }
        return MessageFormat.format(res.getString("VerifyCertificateAction.unknownStatus.message"), status);
    }

    private void verifyStatusCrlFile(KeyStoreHistory keyStoreHistory, String alias, String crlFile)
            throws HeadlessException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
                   InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException, IOException,
                   CryptoException {
        File file = new File(crlFile);
        X509CRL crl = null;
        try {
            byte[] data = FileUtils.readFileToByteArray(file);
            crl = X509CertUtil.loadCRL(data);
        } catch (Exception ex) {
            String problemStr = MessageFormat.format(res.getString("ExamineFileAction.NoOpenCrl.Problem"),
                                                     file.getName());

            String[] causes = new String[] { res.getString("ExamineFileAction.NotCrl.Cause"),
                                             res.getString("ExamineFileAction.CorruptedCrl.Cause") };

            Problem problem = new Problem(problemStr, causes, ex);

            DProblem dProblem = new DProblem(frame, res.getString("ExamineFileAction.ProblemOpeningCrl.Title"),
                                             problem);
            dProblem.setLocationRelativeTo(frame);
            dProblem.setVisible(true);
            return;
        }
        if (verify("true", "false", true, keyStoreHistory, crl, alias)) {
            JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.CrlSuccessful.message"),
                                          MessageFormat.format(res.getString("VerifyCertificateAction.Verify.Title"),
                                                               alias), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void verifyStatusCrl(KeyStoreHistory keyStoreHistory, String alias)
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException,
                   InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException,
                   CryptoException {
        if (verify("true", "false", true, keyStoreHistory, null, alias)) {
            JOptionPane.showMessageDialog(frame, res.getString("VerifyCertificateAction.CrlSuccessful.message"),
                                          MessageFormat.format(res.getString("VerifyCertificateAction.Verify.Title"),
                                                               alias), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private boolean verify(String crl, String ocsp, boolean revocationEnabled, KeyStoreHistory keyStoreHistory,
                           X509CRL xCrl, String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
                   InvalidAlgorithmParameterException, CertPathValidatorException, IllegalStateException,
                   CryptoException {

        KeyStore trustStore = getKeyStore(keyStoreHistory);

        if (trustStore == null) {
            return false;
        }
        if (trustStore.size() == 0) {
            throw new CertPathValidatorException(res.getString("VerifyCertificateAction.trustStoreEmpty.message"));
        }
        System.setProperty("com.sun.net.ssl.checkRevocation", crl);
        System.setProperty("com.sun.security.enableCRLDP", crl);
        Security.setProperty("ocsp.enable", ocsp);

        List<X509Certificate> listCertificates = new ArrayList<>();
        if (revocationEnabled) {
            listCertificates.add(certificateEval);
        } else {
            if (keyCertChain != null) {
                for (int i = keyCertChain.length - 1; i >= 0; i--) {
                    X509Certificate cert = keyCertChain[i];
                    listCertificates.add(0, cert);
                    if (cert.equals(certificateEval)) {
                        break;
                    }
                }
            }
        }

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        CertPath certPath = factory.generateCertPath(listCertificates);
        PKIXParameters params = new PKIXParameters(trustStore);
        if (xCrl != null) {
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(
                    Collections.singletonList(xCrl))));
        }

        // remove some critical extensions that are private to companies and would
        // otherwise cause a validation failure
        PKIXCertPathChecker certPathChecker = new ExtensionRemovingCertPathChecker();
        params.addCertPathChecker(certPathChecker);

        Date now = new Date(System.currentTimeMillis());
        params.setDate(now);
        params.setRevocationEnabled(revocationEnabled);
        validator.validate(certPath, params);
        return true;
    }

    private boolean isCA(X509Certificate cert) {
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) {
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && keyUsage[5]) {
                return true;
            }
        }
        return false;
    }

    private KeyStore getKeyStore(KeyStoreHistory keyStoreHistory)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        KeyStore trustStore = null;
        trustStore = KeyStore.getInstance("JCEKS");
        trustStore.load(null, null);
        if (keyStoreHistory != null) {

            KeyStore tempTrustStore = keyStoreHistory.getCurrentState().getKeyStore();
            Enumeration<String> enumeration = tempTrustStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                if (tempTrustStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class) ||
                    tempTrustStore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
                    X509Certificate cert = (X509Certificate) tempTrustStore.getCertificate(alias);
                    if (isCA(cert)) {
                        trustStore.setCertificateEntry(alias, cert);
                    }
                }
            }
        }
        if (trustStore.size() == 0) {
            if (keyCertChain != null) {
                for (int i = 0; i < keyCertChain.length; i++) {
                    X509Certificate cert = keyCertChain[i];
                    if (isCA(cert)) {
                        String entry = "entry" + i;
                        trustStore.setCertificateEntry(entry, cert);
                    }
                }
            }
        }
        return trustStore;
    }

    private X509Certificate getCertificate(String alias) throws CryptoException {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStore keyStore = history.getCurrentState().getKeyStore();

            return X509CertUtil.convertCertificate(keyStore.getCertificate(alias));
        } catch (KeyStoreException ex) {
            String message = MessageFormat.format(res.getString("VerifyCertificateAction.NoAccessEntry.message"),
                                                  alias);
            throw new CryptoException(message, ex);
        }
    }

    private X509Certificate[] getCertificateChain(String alias) throws CryptoException {
        try {
            KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
            KeyStore keyStore = history.getCurrentState().getKeyStore();
            X509Certificate[] certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias));
            return certs;
        } catch (KeyStoreException ex) {
            String message = MessageFormat.format(res.getString("VerifyCertificateAction.NoAccessEntry.message"),
                                                  alias);
            throw new CryptoException(message, ex);
        }
    }

    static class ExtensionRemovingCertPathChecker extends PKIXCertPathChecker {
        @Override
        public void init(boolean forward) throws CertPathValidatorException {
            // nothing to do here
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return false;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            HashSet<String> hashSet = new HashSet<>();

            // appleCertificateExtensionCodeSigning
            hashSet.add("1.2.840.113635.100.6.1.13");

            return hashSet;
        }

        @Override
        public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
            // remove critical Apple private extension that causes certificate validation to
            // fail
            unresolvedCritExts.remove("1.2.840.113635.100.6.1.13");
        }
    }
}
