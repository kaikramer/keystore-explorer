package net.sf.keystore_explorer.gui.dialogs;


import java.io.IOException;
import java.util.ResourceBundle;
import java.util.concurrent.CancellationException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JFrame;

import net.sf.keystore_explorer.crypto.Password;
import net.sf.keystore_explorer.gui.password.DGetPassword;
import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

public class PasswordCallbackHandler implements CallbackHandler {
	
	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");
	
	private JFrame frame;

	public PasswordCallbackHandler(JFrame frame) {
		this.frame = frame;
	}

	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof PasswordCallback) {
				handlePasswordCallback((PasswordCallback) callbacks[i]);
			} else {
				throw new UnsupportedCallbackException(callbacks[i],
						"Callback not supported " + callbacks[i].getClass().getName());
			}
		}
	}
	
	private void handlePasswordCallback(PasswordCallback passCb) throws UnsupportedCallbackException {
		
		
		DGetPassword dGetPassword = new DGetPassword(frame, res.getString("PasswordCallbackHandler.Title"),
				DOCUMENT_MODAL);
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		Password password = dGetPassword.getPassword();
		
		if (password == null) {
			throw new CancellationException("Password Callback canceled by user");
		}
		
		passCb.setPassword(password.toCharArray());
	}

}
