package org.kse.gui.dialogs.sign;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.UnsupportedLookAndFeelException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.kse.crypto.CryptoException;
import org.kse.crypto.keypair.KeyPairType;
import org.kse.crypto.signing.SignatureType;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.gui.JEscDialog;
import org.kse.gui.KseFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.JDistinguishedName;
import org.kse.gui.crypto.JValidityPeriod;
import org.kse.gui.datetime.JDateTime;
import org.kse.gui.dialogs.DialogHelper;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog that display the data to create a list of revoked certificates
 *
 */
public class DSignCrl extends JEscDialog {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/sign/resources");
	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlVersion;
	private JTextField jtfVersion;
	private JLabel jlIssuer;
	private JDistinguishedName jdnCrlIssuer;
	private JLabel jlEffectiveDate;
	private JDateTime jdtEffectiveDate;
	private JLabel jlValidityPeriod;
	private JValidityPeriod jvpValidityPeriod;
	private JLabel jlNextUpdate;
	private JDateTime jdtNextUpdate;
	private JLabel jlSignatureAlgorithm;
	private JComboBox<SignatureType> jcbSignatureAlgorithm;
	private JLabel jlCrlNumber;
	private JTextField jtfCrlNumber;

	private JRevokedCerts jpRevokedCertsTable;

	private JButton jbOK;
	private JButton jbCancel;

	private KeyPairType signKeyPairType;
	private PrivateKey signPrivateKey;
	private X509Certificate caCert;
	private X509CRL crlOld;
	private Date effectiveDate;
	private Date nextUpdate;
	private SignatureType signatureType;
	private BigInteger crlNumber;

	private JFrame parent;
	private KseFrame kseFrame;

	/**
	 * Creates a new DSignCrl
	 *
	 * @param parent          The parent frame
	 * @param kseFrame        KeyStore Explorer application frame
	 * @param signKeyPairType Key pair type
	 * @param signPrivateKey  Private key certificate
	 * @param caCert          Public key certificate
	 * @param crlOld          An old crl to copy the information of the revoked
	 *                        certificates.
	 * @throws CryptoException A problem was encountered with the supplied private
	 *                         key
	 */
	public DSignCrl(JFrame parent, KseFrame kseFrame, KeyPairType signKeyPairType, PrivateKey signPrivateKey,
			X509Certificate caCert, X509CRL crlOld) throws CryptoException {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.parent = parent;
		this.kseFrame = kseFrame;
		this.signKeyPairType = signKeyPairType;
		this.signPrivateKey = signPrivateKey;
		this.caCert = caCert;
		this.crlOld = crlOld;
		setTitle(res.getString("DSignCrl.Title"));
		initComponents();
	}

	private void initComponents() throws CryptoException {
		Date now = new Date();

		jlVersion = new JLabel(res.getString("DSignCrl.jlVersion.text"));
		jtfVersion = new JTextField("2", 5);
		jtfVersion.setEditable(false);
		jtfVersion.setToolTipText(res.getString("DSignCrl.jtfVersion.tooltip"));

		jlIssuer = new JLabel(res.getString("DSignCrl.jlIssuer.text"));
		jdnCrlIssuer = new JDistinguishedName(res.getString("DSignCrl.Issuer.Title"), 40, false);

		jlEffectiveDate = new JLabel(res.getString("DSignCrl.jlEffectiveDate.text"));
		jdtEffectiveDate = new JDateTime(res.getString("DSignCrl.jdtEffectiveDate.text"), false);
		jdtEffectiveDate.setDateTime(now);
		jdtEffectiveDate.setToolTipText(res.getString("DSignCrl.jdtEffectiveDate.tooltip"));

		jlValidityPeriod = new JLabel(res.getString("DSignCrl.jlValidityPeriod.text"));

		jvpValidityPeriod = new JValidityPeriod(JValidityPeriod.DAYS);
		jvpValidityPeriod.setToolTipText(res.getString("DSignCrl.jvpValidityPeriod.tooltip"));

		jlNextUpdate = new JLabel(res.getString("DSignCrl.jlNextUpdate.text"));
		jdtNextUpdate = new JDateTime(res.getString("DSignCrl.jdtNextUpdate.text"), false);
		jdtNextUpdate.setDateTime(now);
		jdtNextUpdate.setToolTipText(res.getString("DSignCrl.jdtNextUpdate.tooltip"));

		jlSignatureAlgorithm = new JLabel(res.getString("DSignCrl.jlSignatureAlgorithm.text"));

		jcbSignatureAlgorithm = new JComboBox<>();
		jcbSignatureAlgorithm.setMaximumRowCount(10);
		if (signPrivateKey != null) {
			DialogHelper.populateSigAlgs(signKeyPairType, signPrivateKey, jcbSignatureAlgorithm);
		}
		jcbSignatureAlgorithm.setToolTipText(res.getString("DSignCrl.jcbSignatureAlgorithm.tooltip"));

		jlCrlNumber = new JLabel(res.getString("DSignCrl.jlCrlNumber.text"));
		jtfCrlNumber = new JTextField("1", 5);
		jtfCrlNumber.setToolTipText(res.getString("DSignCrl.jtfCrlNumber.tooltip"));

		jpRevokedCertsTable = new JRevokedCerts(parent, kseFrame, caCert, crlOld);

		jbOK = new JButton(res.getString("DSignCrl.jbOK.text"));
		jbCancel = new JButton(res.getString("DSignCrl.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		JPanel jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("fill", "[right]unrel[]", "[]unrel[]"));

		pane.add(jlVersion, "");
		pane.add(jtfVersion, "wrap");
		pane.add(jlIssuer, "");
		pane.add(jdnCrlIssuer, "wrap");
		pane.add(jlEffectiveDate, "");
		pane.add(jdtEffectiveDate, "wrap");
		pane.add(jlValidityPeriod, "");
		pane.add(jvpValidityPeriod, "wrap");
		pane.add(jlNextUpdate, "");
		pane.add(jdtNextUpdate, "wrap");
		pane.add(jlSignatureAlgorithm, "");
		pane.add(jcbSignatureAlgorithm, "wrap");
		pane.add(jlCrlNumber, "");
		pane.add(jtfCrlNumber, "wrap");

		pane.add(jpRevokedCertsTable, "spanx, growx, wrap");

		pane.add(new JSeparator(), "spanx, growx, wrap");

		pane.add(jpButtons, "right, spanx");

		populateFields();

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());

		jvpValidityPeriod.addApplyActionListener(e -> {
			Date startDate = jdtEffectiveDate.getDateTime();
			if (startDate == null) {
				startDate = new Date();
				jdtEffectiveDate.setDateTime(startDate);
			}
			jdtNextUpdate.setDateTime(jvpValidityPeriod.getValidityEnd(startDate));
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void populateFields() {
		if (caCert != null) {
			jdnCrlIssuer.setDistinguishedName(X500NameUtils.x500PrincipalToX500Name(caCert.getSubjectX500Principal()));
		}

		if (crlOld == null) {
			Date startDate = jdtEffectiveDate.getDateTime();
			jdtNextUpdate.setDateTime(jvpValidityPeriod.getValidityEnd(startDate));
		} else {
			Date firstDate = crlOld.getThisUpdate();
			Date secondDate = crlOld.getNextUpdate();
			long diffInMillies = Math.abs(secondDate.getTime() - firstDate.getTime());
			int diff = (int) TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS);
			jvpValidityPeriod.setValue(diff);
			Date startDate = jdtEffectiveDate.getDateTime();
			jdtNextUpdate.setDateTime(jvpValidityPeriod.getValidityEnd(startDate));

			byte[] crlNumEnc = crlOld.getExtensionValue(Extension.cRLNumber.getId());
			if (crlNumEnc != null) {
				try {
					ASN1Primitive primitive = JcaX509ExtensionUtils.parseExtensionValue(crlNumEnc);
					BigInteger nextCrlNum = CRLNumber.getInstance(primitive).getCRLNumber().add(BigInteger.ONE);
					jtfCrlNumber.setText(nextCrlNum.toString());
				} catch (IOException e) {
					// ignore
				}
			}
		}
	}

	private void cancelPressed() {
		effectiveDate = null;
		nextUpdate = null;
		signatureType = null;
		crlNumber = null;
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	private void okPressed() {

		String crlNumberStr = jtfCrlNumber.getText().trim();
		if (crlNumberStr.length() == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DSignCrl.ValReqCrlNumber.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		try {
			crlNumber = new BigInteger(crlNumberStr);
			if (crlNumber.compareTo(BigInteger.ONE) < 0) {
				JOptionPane.showMessageDialog(this, res.getString("DSignCrl.CrlNumberNonZero.message"), getTitle(),
						JOptionPane.WARNING_MESSAGE);
				return;
			}
		} catch (NumberFormatException ex) {
			JOptionPane.showMessageDialog(this, res.getString("DSignCrl.CrlNumberNotInteger.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}

		effectiveDate = jdtEffectiveDate.getDateTime();
		nextUpdate = jdtNextUpdate.getDateTime();
		signatureType = (SignatureType) jcbSignatureAlgorithm.getSelectedItem();
		closeDialog();
	}

	public Date getEffectiveDate() {
		return effectiveDate;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	public SignatureType getSignatureType() {
		return signatureType;
	}

	public BigInteger getCrlNumber() {
		return crlNumber;
	}

	public Map<BigInteger, RevokedEntry> getMapRevokedEntry() {
		return jpRevokedCertsTable.getMapRevokedEntry();
	}

	public static void main(String[] args) throws HeadlessException, UnsupportedLookAndFeelException, CryptoException {
		DialogViewer.run(new DSignCrl(new JFrame(), null, KeyPairType.RSA, null, null, null));
	}
}
