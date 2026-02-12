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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

import javax.swing.ImageIcon;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.kse.crypto.ecc.EdDSACurves;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewJwt;
import org.kse.gui.dialogs.sign.CustomClaim;
import org.kse.gui.dialogs.sign.DSignJwt;
import org.kse.gui.error.DError;
import org.kse.gui.passwordmanager.Password;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

/**
 * Action to create a JWT (JSON Web Token)
 */
public class SignJwtAction extends KeyStoreExplorerAction {

    private static final long serialVersionUID = 1L;

    private String tooltip;

    /**
     * Construct action.
     *
     * @param kseFrame KeyStore Explorer frame
     */
    public SignJwtAction(KseFrame kseFrame) {
        super(kseFrame);
        putValue(LONG_DESCRIPTION, res.getString("SignJwtAction.statusbar"));
        putValue(NAME, res.getString("SignJwtAction.text"));
        putValue(SHORT_DESCRIPTION, res.getString("SignJwtAction.tooltip"));
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
            KseKeyStore keyStore = currentState.getKeyStore();

            Provider provider = history.getExplicitProvider();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            Certificate cert = keyStore.getCertificate(alias);
            KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);

            DSignJwt dSignJwt = new DSignJwt(frame, keyPairType, privateKey);
            dSignJwt.setLocationRelativeTo(frame);
            dSignJwt.setVisible(true);
            if (dSignJwt.isOk()) {
                byte[] dataPublic = cert.getPublicKey().getEncoded();
                SignedJWT jwt = signJwt(dSignJwt, privateKey, provider);
                DViewJwt dialog = new DViewJwt(frame, jwt);
                dialog.setPublicKey(Base64.getEncoder().encodeToString(dataPublic));
                dialog.setLocationRelativeTo(frame);
                dialog.setVisible(true);
            }
        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

    private SignedJWT signJwt(DSignJwt dSignJwt, PrivateKey privateKey, Provider provider) throws Exception {

        JWSSigner signer = null;
        JWSAlgorithm signatureAlgorithm = dSignJwt.getAlgorithm();
        if (JWSAlgorithm.Family.RSA.contains(signatureAlgorithm)) {
            signer = new RSASSASigner(privateKey);
        } else if (JWSAlgorithm.Family.EC.contains(signatureAlgorithm)) {
            signer = new ECDSASigner(privateKey, dSignJwt.getCurve());
        } else if (JWSAlgorithm.Ed25519 == signatureAlgorithm) {
            Ed25519PrivateKeyParameters params = (Ed25519PrivateKeyParameters) PrivateKeyFactory
                    .createKey(privateKey.getEncoded());
            OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519,
                    Base64URL.encode(params.generatePublicKey().getEncoded())).d(Base64URL.encode(params.getEncoded()))
                    .build();
            signer = new Ed25519Signer(okp);
        }
        if (provider != null && signer != null) {
            signer.getJCAContext().setProvider(provider);
        }

        Builder builder = new JWTClaimsSet.Builder().jwtID(dSignJwt.getId()).subject(dSignJwt.getSubject())
                .issuer(dSignJwt.getIssuer()).issueTime(dSignJwt.getIssuedAt())
                .notBeforeTime(dSignJwt.getNotBefore())
                .audience(dSignJwt.getAudience())
                .expirationTime(dSignJwt.getExpiration());

        for (CustomClaim claim : dSignJwt.getCustomClaims()) {
            builder.claim(claim.getName(), claim.getValue());
        }
        JWTClaimsSet claimsSet = builder.build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(signatureAlgorithm).keyID(null).build(), claimsSet);
        signedJWT.sign(signer);

        return signedJWT;
    }

    /**
     * Determines if the public key algorithm is supported.
     *
     * @param publicKey The public key of the selected alias.
     * @return True if the selected alias is supported. False, if not.
     */
    public boolean isKeySupported(PublicKey publicKey) {
        tooltip = null;
        boolean isSupported = true;
        if (publicKey instanceof ECPublicKey) {
            // Only the standard EC curves are supported (P-256, P-384, P-521)
            isSupported = Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams()) != null;
        }
        // Nimbus-JOSE does not support signing a JWT with Ed448, ML-DSA, SLH-DSA.
        boolean isEd448 = EdDSACurves.ED448.jce().equals(publicKey.getAlgorithm());
        boolean isMlDSA = KeyPairType.isMlDSA(KeyPairUtil.getKeyPairType(publicKey));
        boolean isSlhDsa = KeyPairType.isSlhDsa(KeyPairUtil.getKeyPairType(publicKey));
        isSupported = isSupported && !isEd448 && !isMlDSA && !isSlhDsa;
        if (!isSupported) {
            tooltip = res.getString("SignJwtAction.NotSupported.message");
        }
        return isSupported;
    }

    /**
     *
     * @return The tool tip to use for the menu item.
     */
    public String getToolTip() {
        return tooltip;
    }
}
