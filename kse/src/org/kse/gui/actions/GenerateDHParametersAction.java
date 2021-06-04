package org.kse.gui.actions;

import java.awt.Toolkit;

import java.util.ResourceBundle;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;


import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DGenerateDHParameters;
import org.kse.gui.dialogs.DGeneratingDHParameters;
import org.kse.gui.dialogs.DViewDHParameters;
import org.kse.gui.error.DError;
import org.kse.utilities.history.HistoryAction;


public class GenerateDHParametersAction extends KeyStoreExplorerAction implements HistoryAction {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7477452992392634450L;
	protected static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/actions/resources");

		public GenerateDHParametersAction(KseFrame kseFrame) {
		super(kseFrame);

		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("GenerateDHParametersAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("GenerateDHParametersAction.statusbar"));
		putValue(NAME, res.getString("GenerateDHParametersAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("GenerateDHParametersAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource("images/genkeypair.png"))));

	}
		@Override
		public String getHistoryDescription() {
			// TODO Auto-generated method stub
			return (String) getValue(NAME);
		}

		@Override
		protected void doAction() {
			generateDHParameters();
			
		}

		/**
		 * Generate DH Parameters in the currently opened KeyStore.
		 *
		 * @return Does not return any value
		 */
		public void generateDHParameters() {

			try {
                
				//Get KeySize selection
				DGenerateDHParameters dGenerateDHParameters = new DGenerateDHParameters(frame);
				dGenerateDHParameters.setLocationRelativeTo(frame);
				dGenerateDHParameters.setVisible(true);

				if (!dGenerateDHParameters.isSuccessful()) {
					return;
				}
				
			    //Generate DER Encoded DH Parameters
				DGeneratingDHParameters dGeneratingDH = new DGeneratingDHParameters(frame, 
						dGenerateDHParameters.getKeySize());
				dGeneratingDH.setLocationRelativeTo(frame);
				dGeneratingDH.startDHParametersGeneration();
				dGeneratingDH.setVisible(true);
				
				if (!dGeneratingDH.isSuccessful()) {
					return;
				}
				
				//View Base64 DH Parameters with copy and export
				DViewDHParameters dViewDH = new DViewDHParameters(frame,
						res.getString("GenerateDHParametersAction.ViewDHParameters.Title"),
						dGeneratingDH.getDHParameters());
				dViewDH.setLocationRelativeTo(frame);
				dViewDH.setVisible(true);
						
			} catch (Exception ex) {
				DError.displayError(frame, ex);
			}

			return;
		}

}
