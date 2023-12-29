package org.kse.gui.dialogs;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.io.IOException;
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
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;

import org.kse.crypto.CryptoException;
import org.kse.crypto.digest.DigestType;
import org.kse.crypto.digest.DigestUtil;
import org.kse.crypto.x509.X500NameUtils;
import org.kse.crypto.x509.X509CertUtil;
import org.kse.crypto.x509.X509Ext;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.JEscFrame;
import org.kse.gui.LnfUtil;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;
import org.kse.utilities.StringUtils;
import org.kse.utilities.asn1.Asn1Dump;
import org.kse.utilities.asn1.Asn1Exception;
import org.kse.utilities.io.IndentChar;
import org.kse.utilities.io.IndentSequence;

import com.github.difflib.text.DiffRow;
import com.github.difflib.text.DiffRowGenerator;

import net.miginfocom.swing.MigLayout;

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
    private JPanel jpCompareCert;
    private JScrollPane jspCompareCert;
    private JLabel jlMatch;
    private JButton jbOK;
    private JPanel jpButtons;

    /**
     * Creates a new DCompareCertificates frame.
     *
     * @param frame Parent frame
     * @param cert1 Certificate 1 for comparison
     * @param cert2 Certificate 2 for comparison
     */
    public DCompareCertificates(JFrame frame, X509Certificate cert1, X509Certificate cert2) {
        super(MessageFormat.format(res.getString("DCompareCertificates.Title"), X509CertUtil.getShortName(cert1),
                                   X509CertUtil.getShortName(cert2)));
        this.setIconImages(frame.getIconImages());
        initComponents(cert1, cert2);
    }

    private void initComponents(X509Certificate cert1, X509Certificate cert2) {

        HTMLEditorKit kit = new HTMLEditorKit();
        StyleSheet styleSheet = kit.getStyleSheet();
        if (LnfUtil.isDarkLnf()) {
            styleSheet.addRule(".editOldInline {background-color: #B27537;}");
            styleSheet.addRule(".editNewInline {background-color: #CD5C5C;}");
        } else {
            styleSheet.addRule(".editOldInline {background-color: #EFCB05;}");
            styleSheet.addRule(".editNewInline {background-color: #EF7774;}");
        }
        editorLeft = new JEditorPane();
        editorLeft.setContentType("text/html");
        editorLeft.setEditable(false);
        editorLeft.setEditorKit(kit);

        editorRight = new JEditorPane();
        editorRight.setContentType("text/html");
        editorRight.setEditable(false);
        editorRight.setEditorKit(kit);

        jbOK = new JButton(res.getString("DCompareCertificates.jbOK.text"));
        jbOK.addActionListener(evt -> okPressed());

        jlMatch = new JLabel();
        jpButtons = new JPanel(new MigLayout("nogrid, fillx, aligny 100%"));
        jpButtons.add(jlMatch, "sgx");
        jpButtons.add(jbOK, "right, tag ok");

        DiffRowGenerator generator =
                DiffRowGenerator.create().showInlineDiffs(true).inlineDiffByWord(true).ignoreWhiteSpaces(true).build();

        List<DiffRow> rows = null;
        try {
            String text1 = getCertificateDump(cert1);
            String text2 = getCertificateDump(cert2);
            rows = generator.generateDiffRows(getLines(text1), getLines(text2));
        } catch (Asn1Exception | IOException | CertificateEncodingException | CryptoException ex) {
            DError.displayError(this, ex);
        }

        StringBuilder sbuilderLeft = new StringBuilder();
        StringBuilder sbuilderRight = new StringBuilder();
        sbuilderLeft.append("<tt>");
        sbuilderRight.append("<tt>");
        int equals = 0;
        for (DiffRow row : rows) {
            if (row.getOldLine().equals(row.getNewLine())) {
                equals++;
            }
            sbuilderLeft.append(row.getOldLine().replace(" ", "&nbsp;"));
            sbuilderLeft.append("<br>");
            sbuilderRight.append(row.getNewLine().replace(" ", "&nbsp;"));
            sbuilderRight.append("<br>");
        }
        if (!rows.isEmpty()) {
            int percent = equals * 100 / rows.size();
            jlMatch.setText(MessageFormat.format(res.getString("DCompareCertificates.jlMatch.text"),
                                                 percent));
        }

        sbuilderLeft.append("</tt>");
        editorLeft.setText(sbuilderLeft.toString());
        sbuilderRight.append("</tt>");
        editorRight.setText(sbuilderRight.toString());

        jpCompareCert = new JPanel();
        jpCompareCert.setLayout(new MigLayout("insets 0", "[]", "[]"));
        jpCompareCert.add(editorLeft, "");
        jpCompareCert.add(new JSeparator(SwingConstants.VERTICAL), "");
        jpCompareCert.add(editorRight, "");

        jspCompareCert = PlatformUtil.createScrollPane(jpCompareCert, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                       ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets 0, fill", "[]", "[]"));
        pane.add(jspCompareCert, "wrap, growx");
        pane.add(jpButtons, "spanx, growx");

        setResizable(true);
        pack();

        // as the compare window can become quite large, we adjust its size depending on the screen size
        Rectangle maximumWindowBounds = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        if (getWidth() > maximumWindowBounds.width) {
            setSize(maximumWindowBounds.width, getHeight());
        }
        if (getHeight() > maximumWindowBounds.height) {
            setSize(getWidth(), maximumWindowBounds.height);
        }

        setMinimumSize(new Dimension(getWidth(), 200));
        SwingUtilities.invokeLater(() -> jspCompareCert.getVerticalScrollBar().setValue(0));
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
        String[] lines = text.split(NEWLINE);
        return Arrays.asList(lines);
    }

    private String getKeyUsage(X509Extension extensions) throws IOException {
        byte[] value = extensions.getExtensionValue(X509ExtensionType.KEY_USAGE.oid());
        if (value != null) {
            X509Ext ext = new X509Ext(X509ExtensionType.KEY_USAGE.oid(), value, true);
            String keyUsage = ext.getStringValue();
            String[] keyUsages = keyUsage.split(NEWLINE);
            return MessageFormat.format(res.getString("DCompareCertificates.KeyUsage"), String.join(", ", keyUsages));
        }
        return null;
    }

    private String getSubject(X509Certificate certificate) {
        String subject = MessageFormat.format(res.getString("DProperties.properties.Subject"),
                                              X500NameUtils.x500PrincipalToX500Name(
                                                      certificate.getSubjectX500Principal()));
        return subject;
    }

    private String getIssuer(X509Certificate certificate) {
        String issuer = MessageFormat.format(res.getString("DProperties.properties.Issuer"),
                                             X500NameUtils.x500PrincipalToX500Name(
                                                     certificate.getIssuerX500Principal()));
        return issuer;
    }

    private String getSerialNumber(X509Certificate certificate) {
        String serialNumber = MessageFormat.format(res.getString("DProperties.properties.SerialNumber"),
                                                   X509CertUtil.getSerialNumberAsHex(certificate));
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

    // for quick testing
    public static void main(String[] args) throws Exception {
        String cert1Pem =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n" +
                "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n" +
                "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n" +
                "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n" +
                "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n" +
                "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n" +
                "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n" +
                "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n" +
                "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n" +
                "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n" +
                "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n" +
                "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n" +
                "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n" +
                "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n" +
                "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n" +
                "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n" +
                "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n" +
                "WD9f\n" +
                "-----END CERTIFICATE-----\n";
        String cert2Pem =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEg\n" +
                "MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh\n" +
                "bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQx\n" +
                "MjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET\n" +
                "MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJ\n" +
                "KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRI\n" +
                "xutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1k\n" +
                "ZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxD\n" +
                "aNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJw\n" +
                "LnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw\n" +
                "1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2HBNX\n" +
                "k7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2\n" +
                "SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/h\n" +
                "bguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4n\n" +
                "WUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpY\n" +
                "rZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bonvzce\n" +
                "MgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD\n" +
                "AQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSu\n" +
                "bAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLN\n" +
                "nsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGt\n" +
                "Ixg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr61\n" +
                "55wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLj\n" +
                "vUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/hpvvf\n" +
                "cDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpz\n" +
                "oHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZp\n" +
                "nOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfs\n" +
                "pA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+v\n" +
                "JJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R\n" +
                "8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJwGW4\n" +
                "5hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA=\n" +
                "-----END CERTIFICATE-----\n";

        X509Certificate cert1 = X509CertUtil.loadCertificates(cert1Pem.getBytes())[0];
        X509Certificate cert2 = X509CertUtil.loadCertificates(cert2Pem.getBytes())[0];

        DialogViewer.prepare();
        DialogViewer.run(new DCompareCertificates(new JFrame(), cert1, cert2));
    }
}
