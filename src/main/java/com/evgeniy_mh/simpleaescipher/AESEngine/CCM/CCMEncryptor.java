package main.java.com.evgeniy_mh.simpleaescipher.AESEngine.CCM;


import java.io.File;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.AES_CBCEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.AES_CTREncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.MACOptions;

public abstract class CCMEncryptor {

  protected final AES_CTREncryptor mAES_CTREncryptor;
  protected final AES_CBCEncryptor mAES_CBCEncryptor;

  public CCMEncryptor(ProgressIndicator progressIndicator) {
    mAES_CTREncryptor = new AES_CTREncryptor(progressIndicator);
    mAES_CBCEncryptor = new AES_CBCEncryptor(progressIndicator);
  }

  /**
   * Выполняет шифрование файла
   *
   * @param in Файл открытого текста
   * @param out Файл для сохранения результата шифрования (будет перезаписан)
   */
  public abstract Task encrypt(File in, File out, MACOptions options);

  /**
   * Выполняет дешифрование файла
   *
   * @param in Файл шифрованного текста
   * @param out Файл для сохранения результата расшифрования (будет перезаписан)
   */
  public abstract Task decrypt(File in, File out, MACOptions options);
}
