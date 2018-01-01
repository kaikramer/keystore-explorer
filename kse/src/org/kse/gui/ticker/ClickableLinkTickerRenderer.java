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
package org.kse.gui.ticker;

import java.awt.Desktop;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.accessibility.AccessibleContext;
import javax.accessibility.AccessibleText;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

/**
 * Renderer to use with the JTicker Swing control that displays clickable links.
 *
 */
public class ClickableLinkTickerRenderer extends JLabel implements TickerRenderer {

	private static final long serialVersionUID = 1L;
	private static final Pattern PATTERN_LINK = Pattern.compile("<a href=['\"]([^']*?)['\"][^>]*?>.*?</a>");
	private static final Pattern PATTERN_TAG = Pattern.compile("<[^>]*?>");
	private List<LinkDescriptor> listLinks;

	/**
	 * Get the rendering component for the specified JTicker and ticker item
	 *
	 * @return Rendering component
	 * @param ticker
	 *            The JTicker that is asking the renderer to draw
	 * @param value
	 *            The value of the ticker item to be rendered
	 */
	@Override
	public JComponent getTickerRendererComponent(JTicker ticker, Object value) {

		String text = value.toString();
		setText("<html>" + text + "</html>");
		determineLinks(getText());

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				String link = getLink(e.getPoint());
				if (link == null)
					return;
				try {
					Desktop.getDesktop().browse(new URI(link));
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(null, "Could not open link", "Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		return this;
	}

	protected String getLink(Point p) {
		final AccessibleContext aC = getAccessibleContext();
		if (aC instanceof AccessibleJLabel) {
			final AccessibleJLabel aL = (AccessibleJLabel) aC;
			final AccessibleText aT = aL.getAccessibleText();
			if (aT == null) {
				return null;
			}
			final int index = aL.getIndexAtPoint(p);
			for (final LinkDescriptor entry : listLinks) {
				if (index >= entry.getStart() && index <= entry.getEnd()) {
					return entry.getUrl();
				}
			}
		}
		return null;
	}

	public void determineLinks(String text) {

		if (listLinks == null) {
			listLinks = new ArrayList<LinkDescriptor>();
		} else {
			listLinks.clear();
		}

		final Matcher mLink = PATTERN_LINK.matcher(text);
		final List<LinkDescriptor> lLinks = new ArrayList<LinkDescriptor>();
		while (mLink.find()) {
			lLinks.add(new LinkDescriptor(mLink.start(), mLink.end(), mLink.group(1)));
		}
		if (lLinks.isEmpty()) {
			return;
		}
		final Matcher mTag = PATTERN_TAG.matcher(text);
		final List<Integer[]> lTags = new ArrayList<Integer[]>();
		while (mTag.find()) {
			lTags.add(new Integer[] { mTag.start(), mTag.end(), 0 });
		}
		final StringBuilder rawText = new StringBuilder(text.substring(0, lTags.get(0)[0]));
		lTags.get(0)[2] = rawText.length();
		for (int i = 1; i < lTags.size(); i++) {
			rawText.append(text.substring(lTags.get(i - 1)[1], lTags.get(i)[0]));
			lTags.get(i)[2] = rawText.length();
		}
		LinkDescriptor entry = new LinkDescriptor();
		for (final LinkDescriptor link : lLinks) {
			for (final Integer[] tag : lTags) {
				if (tag[0].equals(link.getStart())) {
					entry.setStart(tag[2]);
				} else if (tag[1].equals(link.getEnd())) {
					entry.setEnd(tag[2]);
					entry.setUrl(link.getUrl());
					listLinks.add(entry);
					entry = new LinkDescriptor();
				}
			}
		}
	}

	private final class LinkDescriptor {

		private int start;
		private int end;
		private String url;

		public LinkDescriptor() {
		}

		public LinkDescriptor(int start, int stop, String url) {
			super();
			this.start = start;
			this.end = stop;
			this.url = url;
		}

		public int getStart() {
			return start;
		}

		public void setStart(int start) {
			this.start = start;
		}

		public int getEnd() {
			return end;
		}

		public void setEnd(int stop) {
			this.end = stop;
		}

		public String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		@Override
		public String toString() {
			return "LinkDescriptor [start=" + start + ", end=" + end + ", url=" + url + "]";
		}

	}

}
