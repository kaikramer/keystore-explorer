package org.kse.gui.actions;

import java.awt.Toolkit;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.KeyStroke;

import org.kse.gui.KseFrame;
import org.kse.gui.dialogs.DFindKeyStoreEntry;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to Find a KeyStore entry.
 *
 */
public class FindAction extends KeyStoreExplorerAction {
	private static final long serialVersionUID = 1L;

	/**
	 * Construct action
	 * 
	 * @param kseFrame KeyStore Explorer frame
	 */
	public FindAction(KseFrame kseFrame) {
		super(kseFrame);
		putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(res.getString("FindAction.accelerator").charAt(0),
				Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()));
		putValue(LONG_DESCRIPTION, res.getString("FindAction.statusbar"));
		putValue(NAME, res.getString("FindAction.text"));
		putValue(SHORT_DESCRIPTION, res.getString("FindAction.tooltip"));
		putValue(SMALL_ICON,
				new ImageIcon(Toolkit.getDefaultToolkit().createImage(getClass().getResource("images/find.png"))));
	}

	@Override
	protected void doAction() {

		DFindKeyStoreEntry dialog = new DFindKeyStoreEntry(frame);
		dialog.setLocationRelativeTo(frame);
		dialog.setVisible(true);

		if (dialog.isSuccess()) {
			try {
				String previousAlias = kseFrame.getSelectedEntryAlias();
				String alias = findEntryAlias(previousAlias, dialog.getEntryName());
				if (alias == null && previousAlias != null) {
					alias = findEntryAlias(null, dialog.getEntryName());
				}
				if (alias == null) {
					JOptionPane.showMessageDialog(frame, dialog.getEntryName() + " " + res.getString("FindAction.NotFound.message"),
							res.getString("FindAction.Find.Title"),
							JOptionPane.WARNING_MESSAGE);					
				}
				else {
					kseFrame.setSelectedEntriesByAliases(alias);
				}
			} catch (KeyStoreException ex) {
				DError.displayError(frame, ex);
			}
		}
	}

	private String findEntryAlias(String previousAlias, String name) throws KeyStoreException {
		KeyStoreHistory history = kseFrame.getActiveKeyStoreHistory();
		KeyStore keyStore = history.getCurrentState().getKeyStore();

		boolean search = true;
		if (previousAlias != null) {
			search = false;
		}
		Enumeration<String> enumeration = keyStore.aliases();
		while (enumeration.hasMoreElements()) {
			String alias = enumeration.nextElement();
			if (alias.equals(previousAlias)) {
				search = true;
			} else {
				if (search && alias.contains(name)) {
					return alias;
				}
			}
		}
		return null;
	}
}
