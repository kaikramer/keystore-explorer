package org.kse.gui.dialogs.extensions;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.kse.crypto.x509.X509ExtensionType;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.distributionpoints.JDistributionPoints;
import org.kse.gui.error.DError;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

/**
 * Dialog used to add or edit a CRL distribution points extension.
 */
public class DCrlDistributionPoints extends DExtension {

	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlCrlDistributionPoints;
	private JDistributionPoints jdpDistributionPoints;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	/**
	 * Creates a new DCrlDistributionPoints dialog.
	 *
	 * @param parent The parent dialog
	 */
	public DCrlDistributionPoints(JDialog parent) {
		super(parent);
		setTitle(res.getString("DCrlDistributionPoints.Title"));
		initComponents();
	}

	/**
	 * Creates a new DCrlDistributionPoints dialog.
	 *
	 * @param parent The parent dialog
	 * @param value CRL distribution points DER-encoded
	 * @throws IOException If value could not be decoded
	 */
	public DCrlDistributionPoints(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DCrlDistributionPoints.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlCrlDistributionPoints = new JLabel(res.getString("DCrlDistributionPoints.jlCrlDistributionPoints.text"));

		jdpDistributionPoints = new JDistributionPoints(
				res.getString("DCrlDistributionPoints.DistributionPoints.Title"));
		jdpDistributionPoints.setPreferredSize(new Dimension(400, 150));

		jbOK = new JButton(res.getString("DCrlDistributionPoints.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());

		jbCancel = new JButton(res.getString("DCrlDistributionPoints.jbCancel.text"));
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, "insets 0");

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[right]unrel[]", "[][]"));
		pane.add(jlCrlDistributionPoints, "top");
		pane.add(jdpDistributionPoints, "wrap unrel");
		pane.add(jpButtons, "spanx, tag ok");

		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});


		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private void prepopulateWithValue(byte[] value) throws IOException {

		CRLDistPoint cRLDistPoint = CRLDistPoint.getInstance(value);
		if (cRLDistPoint != null) {
			jdpDistributionPoints.setCRLDistPoint(cRLDistPoint);
		}
	}

	private void okPressed() {

		CRLDistPoint cRLDistPoint = jdpDistributionPoints.getCRLDistPoint();
		if (cRLDistPoint.getDistributionPoints().length == 0) {
			JOptionPane.showMessageDialog(this, res.getString("DCrlDistributionPoints.ValueReq.message"), getTitle(),
					JOptionPane.WARNING_MESSAGE);
			return;
		}
		try {
			value = cRLDistPoint.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			DError.displayError(this, e);
			return;
		}

		closeDialog();
	}

	@Override
	public byte[] getValue() {
		return value;
	}

	@Override
	public String getOid() {
		return X509ExtensionType.CRL_DISTRIBUTION_POINTS.oid();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	public static void main(String[] args) throws Exception {
		DCrlDistributionPoints dialog = new DCrlDistributionPoints(new JDialog());
		DialogViewer.run(dialog);
	}
}
