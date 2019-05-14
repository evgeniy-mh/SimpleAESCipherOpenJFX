package main.java.com.evgeniy_mh.simpleaescipher.AESEngine.CCM;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import main.java.com.evgeniy_mh.simpleaescipher.CommonUtils;
import main.java.com.evgeniy_mh.simpleaescipher.FileUtils;
import main.java.com.evgeniy_mh.simpleaescipher.MACOptions;

public class Encrypt_and_MAC extends CCMEncryptor {

  public Encrypt_and_MAC(ProgressIndicator progressIndicator) {
    super(progressIndicator);
  }

  @Override
  public Task encrypt(File in, File out, MACOptions options) {
    return new Task<Void>() {
      @Override
      //Основной метод потока
      protected Void call() throws IOException {
        switch (options.getMode()) {
          //В случае использования алгоритма CBC при шифровании сообщения
          case CBC:
            //Шифрование файла in в режиме CBC, запись результата в файл out
            mAES_CBCEncryptor.encrypt(in, out, options.getKey1()).run();
            break;
          //В случае использования алгоритма CTR при шифровании сообщения
          case CTR:
            //Шифрование файла in в режиме CTR, запись результата в файл out
            mAES_CTREncryptor.encrypt(in, out, options.getKey1()).run();
            break;
        }

        //Task для подсчета кода аутентификации сообщения
        Task MACTask = null;
        switch (options.getType()) {
          //В случае использования алгоритма ECBC для создания кода аутентификации
          case ECBC:
            ECBCEncryptor ecbce = new ECBCEncryptor();
            //Создание кода аутентификации для файла in(оригинальное сообщение) и добавление его в конец файла out
            MACTask = ecbce.addECBCToFile(in, out, options.getKey1(), options.getKey2());
            break;
          //В случае использования алгоритма HMAC для создания кода аутентификации
          case HMAC:
            HMACEncryptor hmace = new HMACEncryptor();
            //Создание кода аутентификации для файла in(оригинальное сообщение) и добавление его в конец файла out
            MACTask = hmace.addHMACToFile(in, out, options.getKey1());
            break;
        }
        //Запуск Task для подсчета кода аутентификации сообщения
        Thread MACThread = new Thread(MACTask);
        MACThread.start();

        try {
          //Ожидание завершения выполнения потока подсчитывающего код аутентификации сообщения
          MACThread.join();
        } catch (InterruptedException ex) {
          CommonUtils.reportExceptionToMainThread(ex, "MACThread.join();");
        }
        return null;
      }
    };
  }

  @Override
  public Task decrypt(File in, File out, MACOptions options) {
    return new Task<Boolean>() {
      @Override
      protected Boolean call() throws IOException {
        //Считывание кода аутентификации сообщения из файла in
        //Последние 16 байт это код аутентификации
        byte[] MACFromFile = FileUtils
            .readBytesFromFile(in, (int) in.length() - 16, (int) in.length());
        //Создание временного файла в котором будет хранится результат расшифрования
        File tempFile = new File(in.toPath() + "_temp");
        //Копирование сообщения из зашифрованного файла во временный
        FileUtils.createFileCopy(in, tempFile, in.length() - 16);

        switch (options.getMode()) {
          //В случае использования алгоритма CBC при шифровании сообщения
          case CBC:
            //Расшифровка сообщения в файл out с использованием алгоритма CBC
            mAES_CBCEncryptor.decrypt(tempFile, out, options.getKey1()).run();
            break;
          //В случае использования алгоритма CTR при шифровании сообщения
          case CTR:
            //Расшифровка сообщения в файл out с использованием алгоритма CTR
            mAES_CTREncryptor.decrypt(tempFile, out, options.getKey1()).run();
            break;
        }

        //Объявление буфера для хранения созданного кода аутентификации
        byte[] MAC = null;
        switch (options.getType()) {
          //В случае использования алгоритма ECBC для создания кода аутентификации
          case ECBC:
            ECBCEncryptor ecbce = new ECBCEncryptor();
            //Запись нового кода аутентификации в буфер
            MAC = ecbce.getECBC(out, options.getKey1(), options.getKey2());
            break;
          //В случае использования алгоритма HMAC для создания кода аутентификации
          case HMAC:
            HMACEncryptor hmace = new HMACEncryptor();
            //Запись нового кода аутентификации в буфер
            MAC = hmace
                .getHMAC(FileUtils.readBytesFromFile(out, (int) out.length()), options.getKey1());
            break;
        }

        //Сравнение полученного кода аутентификации с созданным
        if (MAC != null && Arrays.equals(MACFromFile, MAC)) {
          tempFile.delete();
          //Если коды аутентификации совпадают - возвращается true
          return true;
        } else {
          tempFile.delete();
          //Если коды аутентификации не совпадают - возвращается false
          return false;
        }
      }
    };
  }
}
