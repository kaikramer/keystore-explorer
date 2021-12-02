package org.kse.gui.actions;

import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import javax.swing.ImageIcon;

import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.sign.DSignJwt;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;

public class SignJwtAction extends KeyStoreExplorerAction{

	private static final long serialVersionUID = 1L;

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
			KeyStore keyStore = currentState.getKeyStore();
			
			String provider = BOUNCY_CASTLE.jce();
			if (history.getExplicitProvider() != null) {
				provider = history.getExplicitProvider().getName();
			}
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);
			
			X509Certificate[] certs = X509CertUtil
					.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));
			
			X509Certificate cert = certs[0];
			DSignJwt dSignJwt = new DSignJwt(frame, kseFrame, keyPairType, privateKey);
			dSignJwt.setLocationRelativeTo(frame);
			dSignJwt.setVisible(true);
			
			Signer signer = RSASigner.newSHA512Signer(privateKey);
			
			JWT jwt = new JWT();
			jwt.issuer = dSignJwt.getIssuer();
			ZonedDateTime d = ZonedDateTime.ofInstant(dSignJwt.getExpiration().toInstant(),
                    ZoneId.systemDefault());
			jwt.expiration = d;
			jwt.subject = dSignJwt.getSubject();
			String encodedJWT = JWT.getEncoder().encode(jwt, signer);
			System.out.println(encodedJWT);
			
			Verifier verifier = RSAVerifier.newVerifier(cert.getPublicKey());
			JWT jwtv = JWT.getDecoder().decode(encodedJWT, verifier);
			System.out.println(jwtv.issuer + " " + jwtv.subject + " " + jwtv.expiration);
		}
		catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

}
