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

public class Encrypt_then_MAC extends CCMEncryptor {

  public Encrypt_then_MAC(ProgressIndicator progressIndicator) {
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
            //Добавление кода аутентификации в конец файла out
            //(код аутентификации создается на основе зашифрованного сообщения)
            MACTask = ecbce.addECBCToFile(out, options.getKey1(), options.getKey2());
            break;
          //В случае использования алгоритма HMAC для создания кода аутентификации
          case HMAC:
            HMACEncryptor hmace = new HMACEncryptor();
            //Добавление кода аутентификации в конец файла out
            //(код аутентификации создается на основе зашифрованного сообщения)
            MACTask = hmace.addHMACToFile(out, options.getKey1());
            break;
        }
        //Запуск потока прикрепляющего код аутентификации к файлу
        Thread MACThread = new Thread(MACTask);
        MACThread.start();

        try {
          //Ожидание завершения потока
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

        //Объявление буфера для хранения созданного кода аутентификации
        byte[] MAC = null;
        switch (options.getType()) {
          //В случае использования алгоритма ECBC для создания кода аутентификации
          case ECBC:
            ECBCEncryptor ecbce = new ECBCEncryptor();
            //Получение кода аутентификации из зашифрованного сообщения
            MAC = ecbce.getECBC(tempFile, options.getKey1(), options.getKey2());
            break;
          //В случае использования алгоритма HMAC для создания кода аутентификации
          case HMAC:
            HMACEncryptor hmace = new HMACEncryptor();
            //Получение кода аутентификации из зашифрованного сообщения
            MAC = hmace.getHMAC(FileUtils.readBytesFromFile(tempFile, (int) tempFile.length()),
                options.getKey1());
            break;
        }

        //Сравнение полученного кода аутентификации с созданным
        if (MAC != null && Arrays.equals(MACFromFile, MAC)) {
          switch (options.getMode()) {
            //Если для расшифровки используется алгоритм CBC
            case CBC:
              //Расшифровка сообщения, запись резульатата в файл out
              mAES_CBCEncryptor.decrypt(tempFile, out, options.getKey1()).run();
              break;
            //Если для расшифровки используется алгоритм CTR
            case CTR:
              //Расшифровка сообщения, запись резульатата в файл out
              mAES_CTREncryptor.decrypt(tempFile, out, options.getKey1()).run();
              break;
          }
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
