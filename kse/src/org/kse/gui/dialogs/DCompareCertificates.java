package org.kse.gui.dialogs;

import java.awt.BorderLayout;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.kse.gui.JEscFrame;
import org.kse.utilities.asn1.Asn1Dump;
import org.kse.utilities.asn1.Asn1Exception;

import com.github.difflib.text.DiffRow;
import com.github.difflib.text.DiffRowGenerator;

public class DCompareCertificates extends JEscFrame {

	private static final long serialVersionUID = 1L;
	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	public DCompareCertificates(List<Certificate> listCertificate) {

		super(res.getString("DCompareCertificates.Title"));
		initComponents(listCertificate);
	}

	private void initComponents(List<Certificate> listCertificate) {
		Asn1Dump asn1Dump = new Asn1Dump();

		DiffRowGenerator generator = DiffRowGenerator.create().showInlineDiffs(true).inlineDiffByWord(true)
				.oldTag(f -> f ? "<font color='red'>" : "</font>") // introduce html style for
																	// strikethrough
				.newTag(f -> f ? "<font color='green'>" : "</font>") // introduce html style for bold
				.build();

		setLayout(new BorderLayout());
		JEditorPane editorLeft = new JEditorPane();
		editorLeft.setContentType("text/html");
		editorLeft.setEditable(false);

		JEditorPane editorRight = new JEditorPane();
		editorRight.setContentType("text/html");
		editorRight.setEditable(false);

		try {
			String text1 = asn1Dump.dump((X509Certificate) listCertificate.get(0));
			String text2 = asn1Dump.dump((X509Certificate) listCertificate.get(1));
			List<DiffRow> rows = generator.generateDiffRows(text1.lines().toList(), text2.lines().toList());
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
		} catch (Asn1Exception | IOException e) {
			System.out.println(e.getMessage());
		}

		JPanel pContainer = new JPanel();
		pContainer.add(editorLeft);
		pContainer.add(editorRight);

		JScrollPane scrollPane = new JScrollPane(pContainer);
		add(scrollPane);
		setResizable(true);

		pack();
	}

	public static void main(String[] args) {

	}
}
