package main.java.com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import javafx.concurrent.Task;
import main.java.com.evgeniy_mh.simpleaescipher.CommonUtils;

public class ECBCEncryptor {

  private AES mAES;

  public ECBCEncryptor() {
    mAES = new AES();
  }

  /**
   * Создает Task для подсчета ECBC
   *
   * @param in Файл шифрованного текста
   * @param out Файл для сохранения результата
   * @param key1 Ключ шифрования
   * @param key2 Доп. ключ ECBC
   */
  public Task getECBC(File in, File out, byte[] key1, byte[] key2) {
    return new Task<Void>() {
      @Override
      protected Void call() {
        try {
          byte[] ECBC = getECBC(in, key1, key2);
          Files.write(out.toPath(), ECBC, StandardOpenOption.WRITE);
        } catch (IOException ex) {
          CommonUtils
              .reportExceptionToMainThread(ex, "Exception in encrypt thread, ECBC task!");
        }

        return null;
      }
    };
  }

  public Task addECBCToFile(File in, byte[] key1, byte[] key2) {
    return new Task<Void>() {
      @Override
      protected Void call() {
        try {
          byte[] ECBC = getECBC(in, key1, key2);
          Files.write(in.toPath(), ECBC, StandardOpenOption.APPEND);
        } catch (IOException ex) {
          CommonUtils.reportExceptionToMainThread(ex, "Exception in encrypt thread, ECBC task!");
        }
        return null;
      }
    };
  }

  //добавить ECBC in файла в out file
  public Task addECBCToFile(File in, File out, byte[] key1, byte[] key2) {
    return new Task<Void>() {
      @Override
      protected Void call() {
        try {
          byte[] ECBC = getECBC(in, key1, key2);
          Files.write(out.toPath(), ECBC, StandardOpenOption.APPEND);
        } catch (IOException ex) {
          CommonUtils.reportExceptionToMainThread(ex, "Exception in encrypt thread, ECBC task!");
        }
        return null;
      }
    };
  }

  public byte[] getECBC(File in, byte[] key1, byte[] key2) throws IOException {

    byte[] tempKey1 = key1;
    //Если длина первого ключа не кратна размеру блока
    //Здесь и далее длины ключей key1<128, key2<128
    if (key1.length % AES.BLOCK_SIZE != 0) {
      //Дополнение первого ключа
      tempKey1 = PKCS7.PKCS7(key1);
    }

    byte[] tempKey2 = key2;
    //Если длина второго ключа не кратна размеру блока
    if (key2.length % AES.BLOCK_SIZE != 0) {
      //Дополнение второго ключа
      tempKey2 = PKCS7.PKCS7(key2);
    }
    //Инициализация первого ключа
    mAES.makeKey(tempKey1, 128, AES.DIR_BOTH);

    //Открытие файла для считывания
    RandomAccessFile INraf = new RandomAccessFile(in, "r");
    //сколько блоков открытого текста
    int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE);

    //Буфер байт
    byte[] temp = new byte[AES.BLOCK_SIZE];
    //Вектор инициализации
    byte[] IV = new byte[AES.BLOCK_SIZE];
    java.util.Arrays.fill(IV, (byte) 0);

    //Цикл по блокам файла
    for (int i = 0; i < nBlocks + 1; i++) {
      //Установка указателя для считывания файла
      INraf.seek(i * 16);

      //Если последняя итерация
      if ((i + 1) == nBlocks + 1) {
        int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
        //Если последний блок файла меньше 16 байт
        if (deltaToBlock > 0) {
          temp = new byte[deltaToBlock];
          //Считывание неполного блока в temp
          INraf.read(temp, 0, deltaToBlock);
          //Дополнение неполного блока
          temp = PKCS7.PKCS7(temp);

          //Иначе если длина последнего блока равна 16 байтам
        } else {
          temp = new byte[AES.BLOCK_SIZE];
          //Создание последнего блока где все биты равны 16
          for (int t = 0; t < AES.BLOCK_SIZE; t++) {
            temp[t] = (byte) AES.BLOCK_SIZE;
          }
        }
      } else {
        //Иначе если не последняя итерация считывание из файла
        INraf.read(temp, 0, AES.BLOCK_SIZE);
      }

      for (int k = 0; k < AES.BLOCK_SIZE; k++) {
        //c_i=(c_i-1 XOR p_i)
        temp[k] = (byte) (temp[k] ^ IV[k]);
      }
      //Выполнение первого шифрования
      mAES.encrypt(temp, IV);
    }
    //Инициализация второго ключа
    mAES.makeKey(tempKey2, 128, AES.DIR_BOTH);
    //Выполнение повторного шифрования
    mAES.encrypt(IV, IV);

    return IV;
  }
}
