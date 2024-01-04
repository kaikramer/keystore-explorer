package org.kse.crypto.privatekey;

public enum PrivateKeyFormat {
   PKCS1("PKCS#1"), PKCS8("PKCS#8"), MSPVK("MS PVK");

   private String value;

   private PrivateKeyFormat(String value) {
      this.value = value;
   }

   public String getValue() {
      return value;
   }
}