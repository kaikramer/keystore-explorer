package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509Ext;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.JEscFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Dump;
import org.kse.utilities.asn1.Asn1Exception;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;

import com.github.difflib.text.DiffRow;
import com.github.difflib.text.DiffRowGenerator;

/*
 * Displays the differences of two certificates
 */
public class DCompareCertificates extends JEscFrame {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");
	private static final String NEWLINE = "\n";
	private IndentSequence INDENT = new IndentSequence(IndentChar.SPACE, 4);

	private JEditorPane editorLeft;
	private JEditorPane editorRight;
	private JPanel jpAsn1Dump;
	private JScrollPane jspAsn1Dump;
	private JButton jbOK;
	private JPanel jpButtons;

	/**
	 * Creates a new DCompareCertificates frame.
	 * 
	 * @param listCertificate List of certificate for compare
	 */
	public DCompareCertificates(List<Certificate> listCertificate) {

		super(res.getString("DCompareCertificates.Title"));
		initComponents(listCertificate);
	}

	private void initComponents(List<Certificate> listCertificate) {

		editorLeft = new JEditorPane();
		editorLeft.setContentType("text/html");
		editorLeft.setEditable(false);

		editorRight = new JEditorPane();
		editorRight.setContentType("text/html");
		editorRight.setEditable(false);

		jbOK = new JButton(res.getString("DCompareCertificates.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());
		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null);

		DiffRowGenerator generator = DiffRowGenerator.create().showInlineDiffs(true).inlineDiffByWord(true)
				.oldTag(f -> f ? "<font color='red'><b>" : "</b></font>").newTag(f -> f ? "<font color='red'><b>" : "</b></font>")
				.build();

		try {
			X509Certificate cert1 = (X509Certificate) listCertificate.get(0);
			X509Certificate cert2 = (X509Certificate) listCertificate.get(1);

			String text1 = getCertificateDump(cert1);
			String text2 = getCertificateDump(cert2);

			List<DiffRow> rows = generator.generateDiffRows(getLines(text1), getLines(text2));
			StringBuilder sbuilderLeft = new StringBuilder();
			StringBuilder sbuilderRight = new StringBuilder();
			sbuilderLeft.append("<tt>");
			sbuilderRight.append("<tt>");
			for (DiffRow row : rows) {
				sbuilderLeft.append(row.getOldLine().replace(" ", "&nbsp;"));
				sbuilderLeft.append("<br>");
				sbuilderRight.append(row.getNewLine().replace(" ", "&nbsp;"));
				sbuilderRight.append("<br>");
			}
			sbuilderLeft.append("</tt>");
			editorLeft.setText(sbuilderLeft.toString());
			sbuilderRight.append("</tt>");
			editorRight.setText(sbuilderRight.toString());

			editorLeft.setCaretPosition(0);
		} catch (Asn1Exception | IOException | CertificateEncodingException | CryptoException ex) {
			DError.displayError(this, ex);
		}

		jpAsn1Dump = new JPanel(new BorderLayout());
		jpAsn1Dump.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpAsn1Dump.add(editorLeft, BorderLayout.WEST);
		JSeparator js = new JSeparator();
		js.setOrientation(SwingConstants.VERTICAL);
		jpAsn1Dump.add(js, BorderLayout.CENTER);
		jpAsn1Dump.add(editorRight, BorderLayout.EAST);

		jspAsn1Dump = PlatformUtil.createScrollPane(jpAsn1Dump, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspAsn1Dump.setPreferredSize(new Dimension(1350, 600));

		getContentPane().add(jspAsn1Dump, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setResizable(true);

		pack();
	}

	private String getCertificateDump(X509Certificate certificate)
			throws CertificateEncodingException, CryptoException, Asn1Exception, IOException {
		String shortName1 = X509CertUtil.getShortName(certificate);

		String text = shortName1 + NEWLINE;
		text = text + INDENT.toString(1) + getSubject(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getIssuer(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getSerialNumber(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getValidFrom(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getValidUntil(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getSignatureAlgo(certificate) + NEWLINE;
		text = text + INDENT.toString(1) + getSha1(certificate) + NEWLINE;
		String keyUsage = getKeyUsage(certificate);
		if (keyUsage != null) {
			text = text + INDENT.toString(1) + getKeyUsage(certificate) + NEWLINE;
		}
		Asn1Dump asn1Dump = new Asn1Dump();
		text = text + NEWLINE + asn1Dump.dump(certificate);
		return text;
	}

	private List<String> getLines(String text) {
		String lines[] = text.split(NEWLINE);
		return Arrays.asList(lines);
	}

	private String getKeyUsage(X509Extension extensions) throws IOException {
		byte[] value = extensions.getExtensionValue(X509ExtensionType.KEY_USAGE.oid());
		if (value != null) {
			X509Ext ext = new X509Ext(X509ExtensionType.KEY_USAGE.oid(), value, true);
			String keyUsage = ext.getStringValue();
			String keyUsages [] = keyUsage.split(NEWLINE);
			return MessageFormat.format(res.getString("DCompareCertificates.KeyUsage"), String.join(", ", keyUsages));
		}
		return null;
	}

	private String getSubject(X509Certificate certificate) {
		String subject = MessageFormat.format(res.getString("DProperties.properties.Subject"),
				X500NameUtils.x500PrincipalToX500Name(certificate.getSubjectX500Principal()));
		return subject;
	}

	private String getIssuer(X509Certificate certificate) {
		String issuer = MessageFormat.format(res.getString("DProperties.properties.Issuer"),
				X500NameUtils.x500PrincipalToX500Name(certificate.getIssuerX500Principal()));
		return issuer;
	}

	private String getSerialNumber(X509Certificate certificate) {
		String serialNumber = MessageFormat.format(res.getString("DProperties.properties.SerialNumber"),
				new BigInteger(certificate.getSerialNumber().toByteArray()).toString(16).toUpperCase());
		return serialNumber;
	}

	private String getSha1(X509Certificate certificate) throws CertificateEncodingException, CryptoException {
		byte[] cert = certificate.getEncoded();
		String sha1 = MessageFormat.format(res.getString("DProperties.properties.Sha1Fingerprint"),
				DigestUtil.getFriendlyMessageDigest(cert, DigestType.SHA1));
		return sha1;
	}

	private String getSignatureAlgo(X509Certificate certificate) {
		String signatureAlgorithm = MessageFormat.format(res.getString("DProperties.properties.SignatureAlgorithm"),
				X509CertUtil.getCertificateSignatureAlgorithm(certificate));
		return signatureAlgorithm;

	}

	private String getValidFrom(X509Certificate certificate) {
		Date validFromDate = certificate.getNotBefore();
		String validFrom = MessageFormat.format(res.getString("DProperties.properties.ValidFrom"),
				StringUtils.formatDate(validFromDate));
		return validFrom;
	}

	private String getValidUntil(X509Certificate certificate) {
		Date validUntilDate = certificate.getNotAfter();
		String validUntil = MessageFormat.format(res.getString("DProperties.properties.ValidUntil"),
				StringUtils.formatDate(validUntilDate));
		return validUntil;
	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
