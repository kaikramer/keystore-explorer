package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;

import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.gui.JEscFrame;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.asn1.Asn1Dump;
import org.kse.utilities.asn1.Asn1Exception;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;

import com.github.difflib.text.DiffRow;
import com.github.difflib.text.DiffRowGenerator;

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

		jbOK = new JButton(res.getString("DViewAsn1Dump.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());
		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, null);

		DiffRowGenerator generator = DiffRowGenerator.create().showInlineDiffs(true).inlineDiffByWord(true)
				.oldTag(f -> f ? "<font color='red'>" : "</font>") // introduce html style for
																	// strikethrough
				.newTag(f -> f ? "<font color='green'>" : "</font>") // introduce html style for bold
				.build();

		try {
			Asn1Dump asn1Dump = new Asn1Dump();
			X509Certificate cert1 = (X509Certificate) listCertificate.get(0);
			X509Certificate cert2 = (X509Certificate) listCertificate.get(1);
			String shortName1 = X509CertUtil.getShortName(cert1);

			String text1 = shortName1 + NEWLINE;
			text1 = text1 + INDENT.toString(1) + getSubject(cert1) + NEWLINE;
			text1 = text1 + INDENT.toString(1) + getIssuer(cert1) + NEWLINE;
			text1 = text1 + INDENT.toString(1) + getSerialNumber(cert1) + NEWLINE;
			text1 = text1 + INDENT.toString(1) + getSignatureAlgo(cert1) + NEWLINE;
			text1 = text1 + INDENT.toString(1) + getSha1(cert1) + NEWLINE;
			text1 = text1 + NEWLINE + asn1Dump.dump(cert1);

			String shortName2 = X509CertUtil.getShortName(cert2);
			String text2 = shortName2 + NEWLINE;
			text2 = text2 + INDENT.toString(1) + getSubject(cert2) + NEWLINE;
			text2 = text2 + INDENT.toString(1) + getIssuer(cert2) + NEWLINE;
			text2 = text2 + INDENT.toString(1) + getSerialNumber(cert2) + NEWLINE;
			text2 = text2 + INDENT.toString(1) + getSignatureAlgo(cert2) + NEWLINE;
			text2 = text2 + INDENT.toString(1) + getSha1(cert2) + NEWLINE;
			text2 = text2 + NEWLINE + asn1Dump.dump(cert2);

			List<DiffRow> rows = generator.generateDiffRows(getLines(text1), getLines(text2));
			String text = "";
			for (DiffRow row : rows) {
				text = text + row.getOldLine() + "<br>";
			}
			text = "<tt>" + text + "</tt>";
			text = text.replaceAll(" ", "&nbsp;");
			editorLeft.setText(text);

			text = "";
			for (DiffRow row : rows) {
				text = text + row.getNewLine() + "<br>";
			}
			text = "<tt>" + text + "</tt>";
			text = text.replaceAll(" ", "&nbsp;");
			editorRight.setText(text);
			editorLeft.setCaretPosition(0);
		} catch (Asn1Exception | IOException | CertificateEncodingException | CryptoException ex) {
			DError.displayError(this, ex);
		}

		jpAsn1Dump = new JPanel(new BorderLayout());
		jpAsn1Dump.setBorder(new EmptyBorder(5, 5, 5, 5));
		jpAsn1Dump.add(editorLeft, BorderLayout.WEST);
		jpAsn1Dump.add(editorRight, BorderLayout.EAST);

		jspAsn1Dump = PlatformUtil.createScrollPane(jpAsn1Dump, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		jspAsn1Dump.setPreferredSize(new Dimension(1400, 600));

		getContentPane().add(jspAsn1Dump, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

		setResizable(true);

		pack();
	}

	public List<String> getLines(String text) {
		String lines[] = text.split(NEWLINE);
		return Arrays.asList(lines);
	}

	public String getSubject(X509Certificate certificate) {
		String subject = MessageFormat.format(res.getString("DProperties.properties.Subject"),
				X500NameUtils.x500PrincipalToX500Name(certificate.getSubjectX500Principal()));
		return subject;
	}

	public String getIssuer(X509Certificate certificate) {
		String issuer = MessageFormat.format(res.getString("DProperties.properties.Issuer"),
				X500NameUtils.x500PrincipalToX500Name(certificate.getIssuerX500Principal()));
		return issuer;
	}

	public String getSerialNumber(X509Certificate certificate) {
		String serialNumber = MessageFormat.format(res.getString("DProperties.properties.SerialNumber"),
				new BigInteger(certificate.getSerialNumber().toByteArray()).toString(16).toUpperCase());
		return serialNumber;
	}

	public String getSha1(X509Certificate certificate) throws CertificateEncodingException, CryptoException {
		byte[] cert = certificate.getEncoded();
		String sha1 = MessageFormat.format(res.getString("DProperties.properties.Sha1Fingerprint"),
				DigestUtil.getFriendlyMessageDigest(cert, DigestType.SHA1));
		return sha1;
	}

	public String getSignatureAlgo(X509Certificate certificate) {
		String signatureAlgorithm = MessageFormat.format(res.getString("DProperties.properties.SignatureAlgorithm"),
				X509CertUtil.getCertificateSignatureAlgorithm(certificate));
		return signatureAlgorithm;

	}

	private void okPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
}
