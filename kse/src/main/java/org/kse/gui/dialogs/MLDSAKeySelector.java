package org.kse.gui.dialogs;

import org.kse.crypto.keypair.KeyPairType;
import org.kse.gui.PlatformUtil;

import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import java.awt.Container;
import java.awt.event.ItemListener;
import java.io.Serializable;
import java.util.Arrays;
import java.util.ResourceBundle;

public class MLDSAKeySelector implements Serializable {
    private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(
            "org/kse/gui/dialogs/resources");

    private static final long serialVersionUID = 1998L;

    protected JRadioButton jRadioButton;
    protected JLabel jLabelKeyType;
    protected JComboBox<String> jComboBoxKeyType;


    public MLDSAKeySelector(ButtonGroup buttonGroup) {

        jRadioButton = new JRadioButton(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.text"));
        jRadioButton.setToolTipText(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.tooltip"));
        PlatformUtil.setMnemonic(
                jRadioButton, RESOURCE_BUNDLE.getString("MLDSAKeySelector.jRadioButton.mnemonic").charAt(0));

        jLabelKeyType = new JLabel(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jLabelKeyType.tooltip"));


        jComboBoxKeyType = new JComboBox<>();
        jComboBoxKeyType.setToolTipText(RESOURCE_BUNDLE.getString("MLDSAKeySelector.jComboBoxKeyType.tooltip"));


        String[] names = Arrays.stream(KeyPairType.values())
                .filter(KeyPairType::isMlDSA)
                .map(KeyPairType::jce)
                .toArray(String[]::new);

        jComboBoxKeyType.setModel(new DefaultComboBoxModel<>(names));
        jRadioButton.setEnabled(true);
        jRadioButton.addItemListener(event -> enableDisableElements());
        this.setSelected(true);
        if (buttonGroup != null) {
            buttonGroup.add(jRadioButton);
        }
    }

    public void add(Container pane) {
        if (pane == null) {
            return;
        }
        pane.add(jRadioButton, "");
        pane.add(jLabelKeyType, "");
        pane.add(jComboBoxKeyType, "growx, wrap");
    }

    public void enableDisableElements() {
        jComboBoxKeyType.setEnabled(jRadioButton.isSelected());
    }

    public void setPreferredKeyType(KeyPairType keyType) {
        if (KeyPairType.isMlDSA(keyType)) {
            jComboBoxKeyType.setSelectedItem(keyType.jce());
        }
    }

    public void addItemListener(ItemListener itemListener) {
        jRadioButton.addItemListener(itemListener);
    }

    public boolean isSelected() {
        return jRadioButton.isSelected();
    }

    public void setEnabled(boolean enabled) {
        jRadioButton.setEnabled(enabled);
        enableDisableElements();
    }

    public void setSelected(boolean selected) {
        jRadioButton.setSelected(selected);
        enableDisableElements();
    }

    public KeyPairType getKeyPairType() {
        return KeyPairType.resolveJce((String) jComboBoxKeyType.getSelectedItem());
    }

}
