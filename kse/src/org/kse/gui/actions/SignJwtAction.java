package org.kse.gui.actions;

import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import javax.swing.ImageIcon;

import org.kse.crypto.Password;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.keypair.KeyPairUtil;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DViewJwt;
import org.kse.gui.dialogs.sign.DSignJwt;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;
import org.kse.utilities.history.KeyStoreState;

import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.rsa.RSAPSSSigner;
import io.fusionauth.jwt.rsa.RSASigner;

public class SignJwtAction extends KeyStoreExplorerAction {

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
			DSignJwt dSignJwt = new DSignJwt(frame, keyPairType, privateKey);
			dSignJwt.setLocationRelativeTo(frame);
			dSignJwt.setVisible(true);

			if (dSignJwt.isOk()) {
				Signer signer = null;
				SignatureType signatureType = dSignJwt.getSignatureType();
				switch (signatureType) {
				case SHA256_RSA:
					signer = RSASigner.newSHA256Signer(privateKey);
					break;
				case SHA384_RSA:
					signer = RSASigner.newSHA384Signer(privateKey);
					break;
				case SHA512_RSA:
					signer = RSASigner.newSHA512Signer(privateKey);
					break;
				case SHA256WITHRSAANDMGF1:
					signer = RSAPSSSigner.newSHA256Signer(privateKey);
					break;
				case SHA384WITHRSAANDMGF1:
					signer = RSAPSSSigner.newSHA384Signer(privateKey);
					break;
				case SHA512WITHRSAANDMGF1:
					signer = RSAPSSSigner.newSHA512Signer(privateKey);
					break;
				case SHA256_ECDSA:
					signer = ECSigner.newSHA256Signer(privateKey);
					break;
				case SHA384_ECDSA:
					signer = ECSigner.newSHA384Signer(privateKey);
					break;
				case SHA512_ECDSA:
					signer = ECSigner.newSHA512Signer(privateKey);
					break;
				default:
					break;
				}
				if (signer == null) {
					throw new NoSuchAlgorithmException(signatureType + ": " + res.getString("SignJwtAction.signNotAvailable.message"));
				}
				

				JWT jwt = new JWT();
				jwt.issuer = dSignJwt.getIssuer();
				ZonedDateTime isuedAt = DateToZoneDateTime(dSignJwt.getIssuedAt());
				jwt.issuedAt = isuedAt;
				jwt.subject = dSignJwt.getSubject();
				ZonedDateTime notBefore = DateToZoneDateTime(dSignJwt.getNotBefore());
				jwt.notBefore = notBefore;
				ZonedDateTime exp = DateToZoneDateTime(dSignJwt.getExpiration());
				jwt.expiration = exp;
				jwt.audience = dSignJwt.getAudience();

				String encodedJWT = JWT.getEncoder().encode(jwt, signer);
				DViewJwt dialog = new DViewJwt(frame, encodedJWT);
				dialog.setLocationRelativeTo(frame);
				dialog.setVisible(true);
			}
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private ZonedDateTime DateToZoneDateTime(Date date) {
		if (date == null) {
			return null;
		}
		return ZonedDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
	}
}
