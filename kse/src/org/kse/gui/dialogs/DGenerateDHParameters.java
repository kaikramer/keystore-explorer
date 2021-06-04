package org.kse.gui.dialogs;

import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import org.kse.gui.JEscDialog;
import org.kse.gui.PlatformUtil;
import org.kse.utilities.DialogViewer;

import net.miginfocom.swing.MigLayout;

public class DGenerateDHParameters extends JEscDialog{
	/**
	 * 
	 */
	private static final long serialVersionUID = 5909033737483232104L;

	private static ResourceBundle res = ResourceBundle.getBundle("org/kse/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";
	private String[] keySizeSelection = {"1024", "2048"};
	private JLabel jlDHKeySize;
	private JComboBox<String> jcbDHKeySize;
	
	private JButton jbOK;
	private JButton jbCancel;
	private int dhKeySize;
	private boolean success = false;

	/**
	 * Creates a new DGeneratingKeyPair dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param keySize
	 *            The key size to generate
	 *  @param base
	 *  
	 */
	public DGenerateDHParameters(JFrame parent) {
		super(parent, res.getString("DGenerateDHParameters.Title"), Dialog.ModalityType.DOCUMENT_MODAL);
		initComponents();
	}
	private void initComponents() {
		
		//TODO Generate DH Parameters icon
		//ImageIcon icon = new ImageIcon(getClass().getResource("images/gendhp.png"));
		//jlGenDHParam.setIcon(icon);
		//jlGenDHParam.setHorizontalTextPosition(SwingConstants.LEADING);
		//jlGenDHParam.setIconTextGap(15);
		
		jlDHKeySize = new JLabel(res.getString("DGenerateDHParameters.jlDHKeySize.text"));

		jcbDHKeySize = new JComboBox<>();
		jcbDHKeySize.setModel(new DefaultComboBoxModel<>(keySizeSelection));
		jcbDHKeySize.setToolTipText(res.getString("DGenerateDHParameters.jcbDHKeySize.tooltip"));

		jbCancel = new JButton(res.getString("DGenerateDHParameters.jbCancel.text"));
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

		jbOK = new JButton(res.getString("DGenerateDHParameters.jbOK.text"));

		JPanel jpContent = new JPanel();
		jpContent.setBorder(new TitledBorder(new EtchedBorder(), res.getString("DGenerateDHParameters.jpContent.text")));
		JPanel buttons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

		// layout
		getContentPane().setLayout(new MigLayout("fill", "", "para[]"));
		getContentPane().add(jpContent, "wrap unrel");
		getContentPane().add(buttons, "growx");
		jpContent.setLayout(new MigLayout("insets dialog, ", "[][right][]", "[]unrel[]"));
		jpContent.add(jlDHKeySize, "");
		jpContent.add(jcbDHKeySize, "growx, wrap");

		jbOK.addActionListener(evt -> okPressed());
		jbCancel.addActionListener(evt -> cancelPressed());
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			@Override public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});
		
		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	/**
	 * Set the selected key size.
	 */
	
	private void setKeySize() {
			dhKeySize = Integer.parseInt((String) jcbDHKeySize.getSelectedItem());
	}
	
	/**
	 * Get the selected key size.
	 *
	 * @return The the key size value
	 */
	public int getKeySize() {	
		return dhKeySize;
	}

	/**
	 * Have the parameters been entered correctly?
	 *
	 * @return True if they have, false otherwise
	 */
	public boolean isSuccessful() {
		return success;
	}

	private void okPressed() {
		setKeySize();
		success = true;
		closeDialog();
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}

	// for quick UI testing
	public static void main(String[] args) throws Exception {
		DGenerateDHParameters dialog = new DGenerateDHParameters(new JFrame());
		DialogViewer.run(dialog);
	}

}
