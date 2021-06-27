package org.kse.gui.dialogs;

import static org.kse.crypto.SecurityProvider.BOUNCY_CASTLE;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.ResourceBundle;

import javax.crypto.spec.DHParameterSpec;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.DHParameters;
import org.kse.gui.JEscDialog;
import org.kse.gui.error.DError;

import net.miginfocom.swing.MigLayout;

/**
 * <h1>DH Parameters generation</h1> The class DGeneratingDHParameters initiates
 * DH Parameters generation. Bouncy Castle is the provider used to generate the
 * parameters.
 * <p>
 * The user may cancel at any time by pressing the cancel button.
 */
public class DGeneratingDHParameters extends JEscDialog {
	private static final long serialVersionUID = 1L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JLabel jlGenDHParameters;
	private JProgressBar jpbGenDHParameters;
	private JButton jbCancel;

	private byte[] dhParameters;
	private int keySize;
	private Thread generator;
	private boolean successStatus = true;

	/**
	 * Creates a new DGeneratingDHParameters dialog.
	 *
	 * @param parent  The parent frame
	 * @param keySize The key size to generate
	 */
	public DGeneratingDHParameters(JFrame parent, int keySize) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		this.keySize = keySize;
		initComponents();
	}

	/**
	 * Initializes the dialogue panel and associated elements
	 */
	private void initComponents() {
		// TODO Generate DH Parameters icon
		jlGenDHParameters = new JLabel(res.getString("DGeneratingDHParameters.jlGenDHParameters.text"));
		ImageIcon icon = new ImageIcon(getClass().getResource("images/genkp.png"));
		jlGenDHParameters.setIcon(icon);

		jpbGenDHParameters = new JProgressBar();
		jpbGenDHParameters.setIndeterminate(true);

		jbCancel = new JButton(res.getString("DGeneratingDHParameters.jbCancel.text"));
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

		Container pane = getContentPane();
		pane.setLayout(new MigLayout("insets dialog, fill", "[]", "[]unrel"));
		pane.add(jlGenDHParameters, "wrap");
		pane.add(jpbGenDHParameters, "growx, wrap");
		pane.add(jbCancel, "tag Cancel");

		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent evt) {
				if ((generator != null) && (generator.isAlive())) {
					generator.interrupt();
				}
				closeDialog();
			}
		});

		setTitle(res.getString("DGeneratingDHParameters.Title"));
		setResizable(false);

		pack();
	}

	/**
	 * Start DH Parameters generation in a separate thread.
	 */
	public void startDHParametersGeneration() {
		generator = new Thread(new GenerateDHParameters());
		generator.setPriority(Thread.MIN_PRIORITY);
		generator.start();
	}

	/**
	 * Returns the current success status
	 *
	 * @return successStatus The success status boolean
	 */
	public boolean isSuccessful() {
		return successStatus;
	}

	/**
	 * Calls the close dialogue, Sets the success value to false
	 */
	private void cancelPressed() {
		if ((generator != null) && (generator.isAlive())) {
			generator.interrupt();
		}
		successStatus = false;
		closeDialog();
	}

	/**
	 * Closes the dialogue
	 */
	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	/**
	 * Get the generated DH Parameters.
	 *
	 * @return byte array of the generated DH Parameters or null if the user
	 *         cancelled the dialog or an error occurred
	 */
	public byte[] getDHParameters() {
		return dhParameters;
	}

	/**
	 * Generates the DH Parameters.
	 * <p>
	 * Identifies a safe prime using the Bouncy Castle provider.
	 * <p>
	 * The parameters are then encoded in DER.
	 */
	private class GenerateDHParameters implements Runnable {
		@Override
		public void run() {
			try {
				AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", BOUNCY_CASTLE.jce());
				algGen.init(keySize, new SecureRandom());
				AlgorithmParameters dhParams = algGen.generateParameters();
				DHParameterSpec dhSpec = dhParams.getParameterSpec(DHParameterSpec.class);

				// Generator G is set as random in params, but it has to be 2 to conform to
				// openssl
				DHParameters realParams = new DHParameters(dhSpec.getP(), BigInteger.valueOf(2));
				// Add DH Params to ASN.1 Encoding vector
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(new ASN1Integer(realParams.getP()));
				vec.add(new ASN1Integer(realParams.getG()));
				// Add DER Encoding to byte array
				dhParameters = new DERSequence(vec).getEncoded(ASN1Encoding.DER);

				SwingUtilities.invokeLater(() -> {
					if (DGeneratingDHParameters.this.isShowing()) {
						closeDialog();
					}
				});
			} catch (final Exception ex) {
				SwingUtilities.invokeLater(() -> {
					if (DGeneratingDHParameters.this.isShowing()) {
						DError dError = new DError(DGeneratingDHParameters.this, ex);
						dError.setLocationRelativeTo(DGeneratingDHParameters.this);
						dError.setVisible(true);
						closeDialog();
					}
				});
			}
		}
	}
}
