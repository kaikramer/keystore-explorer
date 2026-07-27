/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.kse.gui.dialogs;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.util.ResourceBundle;

import javax.crypto.spec.DHParameterSpec;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.DHParameters;
import org.kse.KSE;
import org.kse.gui.error.DError;
import org.kse.utilities.rng.RNG;

/**
 * <h1>DH Parameters generation</h1> The class DGeneratingDHParameters initiates
 * DH Parameters generation. Bouncy Castle is the provider used to generate the
 * parameters.
 * <p>
 * The user may cancel at any time by pressing the cancel button.
 */
public class DGeneratingDHParameters extends JWaitDialog {
    private static final long serialVersionUID = 1L;

    private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

    private byte[] dhParameters;
    private int keySize;

    /**
     * Creates a new DGeneratingDHParameters dialog.
     *
     * @param parent  The parent frame
     * @param keySize The key size to generate
     */
    public DGeneratingDHParameters(JFrame parent, int keySize) {
        super(parent, res.getString("DGeneratingDHParameters.Title"),
                res.getString("DGeneratingDHParameters.jlGenDHParameters.text"), "images/genkp.png",
                res.getString("DGeneratingDHParameters.jbCancel.text"));
        this.keySize = keySize;
    }

    /**
     * Start DH Parameters generation in a separate thread.
     */
    public void startDHParametersGeneration() {
        startTask(new GenerateDHParameters());
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
                AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", KSE.BC);
                algGen.init(keySize, RNG.newInstanceForLongLivedSecrets());
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
