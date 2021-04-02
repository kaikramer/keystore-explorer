/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2021 Kai Kramer
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
package org.kse.utilities.io;

/**
 * Indentation sequence.
 *
 */
public class IndentSequence {
	public static final IndentSequence FOUR_SPACES = new IndentSequence(IndentChar.SPACE, 4);
	public static final IndentSequence SINGLE_TAB = new IndentSequence(IndentChar.TAB, 1);

	private IndentChar indentChar;

	private int indentSize;
	/**
	 * Construct IndentSequence.
	 *
	 * @param indentChar
	 *            Indent character
	 * @param indentSize
	 *            Indent size
	 */
	public IndentSequence(IndentChar indentChar, int indentSize) {
		this.indentChar = indentChar;
		this.indentSize = indentSize;
	}

	/**
	 * Get indent sequence for level.
	 *
	 * @param level
	 *            Indent level
	 * @return Indent sequence for level
	 */
	public String toString(int level) {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < level; i++) {
			sb.append(toString());
		}

		return sb.toString();
	}

	/**
	 * Get indent sequence.
	 *
	 * @return Indent sequence
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < indentSize; i++) {
			sb.append(indentChar.getIndentChar());
		}

		return sb.toString();
	}

	/**
	 * Get the indent character.
	 *
	 * @return
	 */
	public IndentChar getIndentChar() {
		return indentChar;
	}
}
