package org.kse.gui.actions;

import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.apache.commons.io.FileUtils;
import org.kse.crypto.Password;

import org.kse.gui.CurrentDirectory;
import org.kse.gui.FileChooserFactory;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.gui.error.DProblem;
import org.kse.gui.error.Problem;
import org.kse.gui.password.DGetPassword;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;

public class OpenLunaAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;
	public Provider provider;
	public KeyStore openedKeyStore = null;
    private LunaSlotManager manager;
  
	public String slot; 
	/**
	 * Construct action.
	 *
	 * @param kseFrame
	 *            KeyStore Explorer frame
	 */
	public OpenLunaAction(KseFrame kseFrame) {
		super(kseFrame);
		provider = new LunaProvider();
		Security.addProvider(provider);

		putValue(
				ACCELERATOR_KEY,
				KeyStroke.getKeyStroke(res.getString("OpenLunaAction.accelerator").charAt(0), Toolkit
						.getDefaultToolkit().getMenuShortcutKeyMask() + InputEvent.SHIFT_MASK));
		putValue(LONG_DESCRIPTION, res.getString("OpenLunaAction.statusbar"));
		putValue(NAME, res.getString("OpenLunaAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("OpenLunaAction.tooltip"));
		putValue(
				SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(
						getClass().getResource(res.getString("OpenLunaAction.image")))));
	}

	/**
	 * Do action.
	 */
	@Override
	protected void doAction() {
		JFileChooser chooser = FileChooserFactory.getKeyStoreFileChooser();
		chooser.setCurrentDirectory(CurrentDirectory.get());
		chooser.setDialogTitle(res.getString("OpenAction.OpenKeyStore.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showOpenDialog(frame);
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File openFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(openFile);
			openKeyStore(openFile);
		}
	}

	/**
	 * Open the supplied KeyStore file from disk.
	 *
	 * @param keyStoreFile
	 *            The KeyStore file
	 */
	public void openKeyStore(File keyStoreFile) {
		openKeyStore(keyStoreFile, null);
	}

	/**
	 * Open the supplied KeyStore file from disk.
	 *
	 * @param keyStoreFile
	 *            The KeyStore file
	 */
	public void openKeyStore(File keyStoreFile, String defaultPassword) {

		try {
			if (!keyStoreFile.isFile()) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("OpenAction.NotFile.message"), keyStoreFile),
						res.getString("OpenAction.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}

			if (isKeyStoreFileOpen(keyStoreFile)) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("OpenAction.NoOpenKeyStoreAlreadyOpen.message"),
								keyStoreFile),
						res.getString("OpenAction.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
				return;
			}
			try {
				slot = FileUtils.readFileToString(keyStoreFile);
			} catch (IOException e) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("OpenAction.NoReadFile.message"), keyStoreFile.getName()),
						res.getString("OpenAction.OpenKeyStore.Title"), JOptionPane.WARNING_MESSAGE);
				slot = "slot:0";
			}


			// use (optional) default password for first try
			Password password = (defaultPassword != null) ? new Password(defaultPassword.toCharArray()) : null;

			openedKeyStore = null;
			boolean firstTry = true;
			while (true) {

				// show password dialog if no default password was passed or if last try to unlock ks has failed
				if (password == null) {
					password = showPasswordDialog(slot);
				}

				// user did not enter password -> abort
				if (password == null) {
					return;
				}

				// try to load keystore
				try {
					manager = LunaSlotManager.getInstance();
					String pw = new String(password.toCharArray());
					manager.login(pw);
					openedKeyStore = KeyStore.getInstance("Luna");
					ByteArrayInputStream is1 = null;
					if (slot.contains("slot:")) {
						is1 = new ByteArrayInputStream((slot).getBytes());
					} // this is a bit dubious; the newer Luna FW requires a "slot" parameter, while the old one expects a null
					openedKeyStore.load(is1, password.toCharArray()); 
					break;
				} catch (Exception klex) {
					// show error message only after first try with default password or if no default password set
					if (defaultPassword == null || !firstTry) {

						int tryAgainChoice = showErrorMessage(slot, klex);
						if (tryAgainChoice == JOptionPane.NO_OPTION) {
							return;
						}
					}
				}

				// failure, reset password
				password.nullPassword();
				password = null;
				firstTry = false;
			}

			if (openedKeyStore == null) {
				JOptionPane.showMessageDialog(frame,
						MessageFormat.format(res.getString("OpenAction.FileNotRecognisedType.message"),
								provider.getName() + slot, res.getString("OpenAction.OpenKeyStore.Title"),
								JOptionPane.WARNING_MESSAGE));
				return;
			}

			kseFrame.addKeyStore(openedKeyStore, keyStoreFile, password);
		} catch (Exception ex) {
			DError.displayError(frame, ex);
		}
	}

	private Password showPasswordDialog(String slot) {
		DGetPassword dGetPassword = new DGetPassword(frame, MessageFormat.format(
				res.getString("OpenAction.UnlockKeyStore.Title"), slot));
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		return dGetPassword.getPassword();
	}

	private int showErrorMessage(String slot, Exception klex) {
		String problemStr = MessageFormat.format(res.getString("OpenAction.NoOpenKeyStore.Problem"),
				 provider.getName() , slot);

		String[] causes = new String[] { res.getString("OpenAction.PasswordIncorrectKeyStore.Cause"),
				res.getString("OpenAction.CorruptedKeyStore.Cause") };

		Problem problem = new Problem(problemStr, causes, klex);

		DProblem dProblem = new DProblem(frame,
				res.getString("OpenAction.ProblemOpeningKeyStore.Title"), problem);
		dProblem.setLocationRelativeTo(frame);
		dProblem.setVisible(true);

		int choice = JOptionPane.showConfirmDialog(frame, res.getString("OpenAction.TryAgain.message"),
				res.getString("OpenAction.TryAgain.Title"), JOptionPane.YES_NO_OPTION);
		return choice;
	}

}
