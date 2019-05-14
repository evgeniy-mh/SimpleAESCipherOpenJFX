package main.java.com.evgeniy_mh.simpleaescipher;

public class MACOptions {

  public enum CipherMode {CTR, CBC}

  ;

  public enum MACType {HMAC, ECBC}

  ;

  private final byte[] key1, key2;
  private final MACType type;
  private final CipherMode mode;

  public MACOptions(MACType type, CipherMode mode, byte[] key1, byte[] key2) {
    this.type = type;
    this.mode = mode;
    this.key1 = key1;
    this.key2 = key2;
  }

  public byte[] getKey1() {
    return key1;
  }

  public byte[] getKey2() {
    return key2;
  }

  public CipherMode getMode() {
    return mode;
  }

  public MACType getType() {
    return type;
  }

}
