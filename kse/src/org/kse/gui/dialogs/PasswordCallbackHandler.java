/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
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


import java.io.IOException;
import java.util.ResourceBundle;
import java.util.concurrent.CancellationException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JFrame;

import org.kse.crypto.Password;
import org.kse.gui.password.DGetPassword;

public class PasswordCallbackHandler implements CallbackHandler {

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private JFrame frame;

	public PasswordCallbackHandler(JFrame frame) {
		this.frame = frame;
	}

	@Override
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


		DGetPassword dGetPassword = new DGetPassword(frame, res.getString("PasswordCallbackHandler.Title")
				);
		dGetPassword.setLocationRelativeTo(frame);
		dGetPassword.setVisible(true);
		Password password = dGetPassword.getPassword();

		if (password == null) {
			throw new CancellationException("Password Callback canceled by user");
		}

		passCb.setPassword(password.toCharArray());
	}

}
