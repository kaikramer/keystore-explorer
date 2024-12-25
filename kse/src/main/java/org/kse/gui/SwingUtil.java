package org.kse.gui;

import java.awt.FontMetrics;

import javax.swing.JLabel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

public class SwingUtil {
    private SwingUtil() {
    }

    /**
     * Fix scrolling in a JScrollPane. This method sets the unit increment of the vertical and horizontal scroll bars to
     * the height of a line and the width of a character, respectively. This makes scrolling faster and more responsive.
     * <p>
     * Without this fix, scrolling is slow because the unit increment is set to a fixed value that is too small.
     * <p>
     * Before calling this method, the JScrollPane should be populated with content.
     * </p>
     *
     * @param jScrollPane Scroll pane to fix
     */
    public static void fixScrolling(JScrollPane jScrollPane) {
        JLabel systemLabel = new JLabel();
        FontMetrics metrics = systemLabel.getFontMetrics(systemLabel.getFont());
        int lineHeight = metrics.getHeight();
        int charWidth = metrics.getMaxAdvance();

        JScrollBar systemVBar = new JScrollBar(JScrollBar.VERTICAL);
        JScrollBar systemHBar = new JScrollBar(JScrollBar.HORIZONTAL);
        int verticalIncrement = systemVBar.getUnitIncrement();
        int horizontalIncrement = systemHBar.getUnitIncrement();

        jScrollPane.getVerticalScrollBar().setUnitIncrement(lineHeight * verticalIncrement);
        jScrollPane.getHorizontalScrollBar().setUnitIncrement(charWidth * horizontalIncrement);
    }
}