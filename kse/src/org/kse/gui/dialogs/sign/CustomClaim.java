package org.kse.gui.dialogs.sign;

/**
 * Class for a custom claim.
 *
 */
public class CustomClaim {

	private String name;
	private String value;

	/**
	 * Construct a new CustomClaim
	 * 
	 * @param name  name of claim
	 * @param value value of claim
	 */
	public CustomClaim(String name, String value) {
		super();
		this.name = name;
		this.value = value;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
}
