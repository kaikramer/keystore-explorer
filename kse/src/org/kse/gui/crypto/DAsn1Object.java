package org.kse.gui.crypto;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.gui.error.DError;

public class DAsn1Object<T> extends JEscDialog {
	private static final long serialVersionUID = 6374222942197111228L;
	
	private ResourceBundle res;

	private static final String CANCEL_KEY = "CANCEL_KEY";
	
	private T object;
	
	private JButton jbOK;

	private JButton jbCancel;

	private JPanel jpButtons;

	private String messagePreffix;

	/**
	 * Constructs a new DDistributionPoints dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param title
	 *            The dialog title
	 * @param asn1Object
	 *            asn1 object
	 */
	public DAsn1Object(JFrame parent, String title, T asn1Object, ResourceBundle res, String preffix) {
		super(parent, title, ModalityType.DOCUMENT_MODAL);
		this.messagePreffix = preffix;
		this.res = res;
		object = asn1Object;
		initComponents();
	}

	/**
	 * Constructs a new DDistributionPoints dialog.
	 *
	 * @param parent
	 *            The parent dialog
	 * @param title
	 *            The dialog title
	 * @param asn1Object
	 *            asn1 object
	 */
	public DAsn1Object(JDialog parent, String title, T asn1Object, ResourceBundle res, String preffix) {
		super(parent, title, Dialog.ModalityType.DOCUMENT_MODAL);
		this.messagePreffix = preffix;
		this.res = res;
		object = asn1Object;
		initComponents();
	}

	private void initComponents() {
		jbOK = new JButton(res.getString(messagePreffix + ".jbOK.text"));
		jbOK.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		jbCancel = new JButton(res.getString(messagePreffix + ".jbCancel.text"));
		jbCancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel, false);
		
		getContentPane().setLayout(new BorderLayout());
		JPanel contentBody = createDialogBody();
		getContentPane().add(contentBody, BorderLayout.CENTER);
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

	protected JPanel createDialogBody() {
		return null;
	}

	public void okPressed() {
		try {
			createObject();
		} catch (Exception ex) {
			DError dError = new DError(this, ex);
			dError.setLocationRelativeTo(this);
			dError.setVisible(true);
			return;
		}

		closeDialog();
	}

	protected void createObject() {
		// TODO Auto-generated method stub
		
	}

	public void cancelPressed() {
		closeDialog();
	}

	public void closeDialog() {
		setVisible(false);
		dispose();
	}

	protected void setObject(T object) {
		this.object = object;
	}
	
	public T getObject() {
		return object;
	}

}
