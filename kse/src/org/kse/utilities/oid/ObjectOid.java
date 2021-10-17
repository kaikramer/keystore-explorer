package org.kse.utilities.oid;

/**
 * 
 * Representation as a string of an oid object
 *
 */
public class ObjectOid implements Comparable<ObjectOid> {
	private String identifier;
	private String representation;

	public ObjectOid(String prefix, String identifier, String representation) {
		super();
		this.identifier = identifier.replaceFirst(prefix, "");
		this.representation = representation;
	}

	public String getIdentifier() {
		return identifier;
	}

	public String getRepresentation() {
		return representation;
	}

	@Override
	public String toString() {
		return identifier + " " + representation;
	}

	@Override
	public int compareTo(ObjectOid arg0) {

		String id1 = getIdentifier();
		String[] a1 = id1.split("\\.");
		String id2 = arg0.getIdentifier();
		String[] a2 = id2.split("\\.");

		for (int i = 0; i < a1.length; i++) {
			Integer i1 = Integer.valueOf(a1[i].trim());
			if (i >= a2.length) {
				return 1;
			}
			Integer i2 = Integer.valueOf(a2[i].trim());
			if (i1.intValue() != i2.intValue()) {
				return i1.compareTo(i2);
			}
		}
		if (a1.length == a2.length) {
			return 0;
		} else {
			return -1;
		}
	}
}
