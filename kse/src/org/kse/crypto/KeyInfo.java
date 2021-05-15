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
package org.kse.crypto;

/**
 * Holds information about a key.
 *
 */
public class KeyInfo {
	private KeyType keyType;
	private String algorithm;
	private Integer size;
	private String detailedAlgorithm;

	public KeyInfo(KeyType keyType, String algorithm) {
		this(keyType, algorithm, null,algorithm);
	}

	public KeyInfo(KeyType keyType, String algorithm, Integer size) {
		this.keyType = keyType;
		this.algorithm = algorithm;
		this.size = size;
		this.detailedAlgorithm =  algorithm+Integer.toString(size);
	}
	public KeyInfo(KeyType keyType, String algorithm, Integer size, String detailedAlgorithm) {
		this.keyType = keyType;
		this.algorithm = algorithm;
		this.size = size;
		this.detailedAlgorithm = detailedAlgorithm;
	}

	public KeyType getKeyType() {
		return keyType;
	}

	public String getAlgorithm() {
		return algorithm;
	}
	public String getDetailedAlgorithm() {
		return detailedAlgorithm;
	}

	/**
	 * Get key size in bits.
	 *
	 * @return Key size or null if size unknown
	 */
	public Integer getSize() {
		return size;
	}
}
