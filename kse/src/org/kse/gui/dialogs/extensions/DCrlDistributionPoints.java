package org.kse.gui.dialogs.extensions;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
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
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.kse.gui.PlatformUtil;
import org.kse.gui.crypto.distributionpoints.JDistributionPoints;
import org.kse.gui.error.DError;

public class DCrlDistributionPoints extends DExtension {

	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/extensions/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JPanel jpCrlDistributionPoints;
	private JLabel jlCrlDistributionPoints;
	private JDistributionPoints jdpDistributionPoints;
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private byte[] value;

	public DCrlDistributionPoints(JDialog parent) {
		super(parent);
		setTitle(res.getString("DCrlDistributionPoints.Title"));
		initComponents();
	}

	public DCrlDistributionPoints(JDialog parent, byte[] value) throws IOException {
		super(parent);
		setTitle(res.getString("DCrlDistributionPoints.Title"));
		initComponents();
		prepopulateWithValue(value);
	}

	private void initComponents() {
		jlCrlDistributionPoints = new JLabel(res.getString("DCrlDistributionPoints.jlCrlDistributionPoints.text"));

		GridBagConstraints gbc_jlDistributionPoints = new GridBagConstraints();
		gbc_jlDistributionPoints.gridx = 0;
		gbc_jlDistributionPoints.gridy = 1;
		gbc_jlDistributionPoints.gridwidth = 1;
		gbc_jlDistributionPoints.gridheight = 1;
		gbc_jlDistributionPoints.insets = new Insets(5, 5, 5, 5);
		gbc_jlDistributionPoints.anchor = GridBagConstraints.NORTHEAST;

		jdpDistributionPoints = new JDistributionPoints(
				res.getString("DCrlDistributionPoints.DistributionPoints.Title"));
		jdpDistributionPoints.setPreferredSize(new Dimension(400, 150));

		GridBagConstraints gbc_jdpDistributionPoints = new GridBagConstraints();
		gbc_jdpDistributionPoints.gridx = 1;
		gbc_jdpDistributionPoints.gridy = 1;
		gbc_jdpDistributionPoints.gridwidth = 1;
		gbc_jdpDistributionPoints.gridheight = 1;
		gbc_jdpDistributionPoints.insets = new Insets(5, 5, 5, 5);
		gbc_jdpDistributionPoints.anchor = GridBagConstraints.WEST;

		jpCrlDistributionPoints = new JPanel(new GridBagLayout());

		jpCrlDistributionPoints.setBorder(new CompoundBorder(new EmptyBorder(5, 5, 5, 5), new EtchedBorder()));

		jpCrlDistributionPoints.add(jlCrlDistributionPoints, gbc_jlDistributionPoints);
		jpCrlDistributionPoints.add(jdpDistributionPoints, gbc_jdpDistributionPoints);

		jbOK = new JButton(res.getString("DCrlDistributionPoints.jbOK.text"));
		jbOK.addActionListener(evt -> okPressed());

		jbCancel = new JButton(res.getString("DCrlDistributionPoints.jbCancel.text"));
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(jpCrlDistributionPoints, BorderLayout.CENTER);
		getContentPane().add(jpButtons, BorderLayout.SOUTH);

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

	/**
	 * Get extension value DER-encoded.
	 *
	 * @return Extension value
	 */
	@Override
	public byte[] getValue() {
		return value;
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	/*
	 * 
	 * private void okPressed() { String crlDistributionPointsStr =
	 * jtCrlDistributionPoints.getText().trim();
	 * 
	 * if (crlDistributionPointsStr.length() == 0) {
	 * JOptionPane.showMessageDialog(this,
	 * res.getString("DCrlDistributionPoints.ValueReq.message"), getTitle(),
	 * JOptionPane.WARNING_MESSAGE); return; }
	 * 
	 * final GeneralName generalName = new
	 * GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPointsStr);
	 * 
	 * final DistributionPointName pointName = new DistributionPointName(new
	 * GeneralNames(generalName)); final DistributionPoint[] points = new
	 * DistributionPoint[]{new DistributionPoint(pointName, null, null)};
	 * 
	 * for (DistributionPoint point : points) {
	 * System.out.println(point.toString()); }
	 * 
	 * CRLDistPoint cRLDistPoint = new CRLDistPoint(points);
	 * 
	 * 
	 * try { value = cRLDistPoint.getEncoded(ASN1Encoding.DER); } catch (IOException
	 * e) { DError.displayError(this, e); return; }
	 * 
	 * closeDialog(); }
	 * 
	 */

}
