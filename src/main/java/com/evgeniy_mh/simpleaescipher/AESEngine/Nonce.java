package main.java.com.evgeniy_mh.simpleaescipher.AESEngine;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * @author evgeniy
 */
public class Nonce {

  private static Nonce instance;
  private static Preferences userPrefs;
  private static final String NONCE_KEY = "NONCE";

  private Nonce() {
    userPrefs = Preferences.userNodeForPackage(Nonce.class);
  }

  public static Nonce getInstance() {
    if (instance == null) {
      instance = new Nonce();
    }
    return instance;
  }

  public int getNonce() {
    if (userPrefs.getInt(NONCE_KEY, -1) == -1) {
      setNonce(0); //если еще нет такого поля
    }
    return userPrefs.getInt(NONCE_KEY, 0);
  }

  public void setNonce(int nonce) {
    userPrefs.putInt(NONCE_KEY, nonce);
    try {
      userPrefs.sync();
    } catch (BackingStoreException ex) {
      Logger.getLogger(Nonce.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public void IncNonce() {
    if (userPrefs.getInt(NONCE_KEY, 0) == Integer.MAX_VALUE) {
      setNonce(0);
    } else {
      setNonce(userPrefs.getInt(NONCE_KEY, 0) + 1);
    }
  }

}
