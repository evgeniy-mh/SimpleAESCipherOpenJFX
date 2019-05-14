package main.java.com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;
import main.java.com.evgeniy_mh.simpleaescipher.CommonUtils;
import main.java.com.evgeniy_mh.simpleaescipher.FileUtils;

/**
 * Created by evgeniy on 08.04.17.
 */
public class AES_CTREncryptor extends Encryptor {

  public AES_CTREncryptor(ProgressIndicator progressIndicator) {
    super(progressIndicator);
  }

  @Override
  public Task encrypt(File in, File out, final byte[] key) {
    return new Task<Void>() {
      @Override
      protected Void call() throws IOException {
        //Создание блоков байт для хранения nonce и счетчика(counter)
        byte[] nonce = ByteBuffer.allocate(8).putInt(getNonce()).array();
        byte[] counter = ByteBuffer.allocate(8).putInt(0).array();
        //Блок байт, который будет использоваться в раундах(16 байт): 0000nnnn|0000cccc
        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE];
        //Блок байт, который будет  добавлен в начало зашифрованного файла: nnnncccc
        byte[] nonceAndCounterInfo = new byte[8];
        System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
        System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);

        //Если длина ключа не кратна длине блока(16 байт), то он дополняется  PKCS7
        byte[] tempKey = key;
        if (key.length % AES.BLOCK_SIZE != 0) {
          tempKey = PKCS7.PKCS7(key);
        }
        //mAES - объект класса AES. В него передается ключ, его длина и направление шифрования.
        mAES.makeKey(tempKey, 128, AES.DIR_BOTH);
        try {
          //Открытие файла для записи результата шифрования
          RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
          OUTraf.setLength(8 + in.length());

          //Запись в него информации о nonce и счетчике
          OUTraf.write(nonceAndCounterInfo);
          //Открытие исходного файла
          RandomAccessFile INraf = new RandomAccessFile(in, "r");
          //Количество блоков открытого текста
          int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE);
          //В буффер  temp будут считываться блоки по 16 байт из исходного файла
          byte[] temp = new byte[AES.BLOCK_SIZE];

          //Главный цикл в котором происходит обработка блоков
          for (int i = 0; i < nBlocks + 1; i++) {
            INraf.seek(i * 16); //установка указателя для считывания файла

            //Если это последняя итерация
            if ((i + 1) == nBlocks + 1) {
              //deltaToBlock — колчество недостающих байт до полного блока
              int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
              //Если это количество больше нуля происходит PKCS7 дополнение блока
              if (deltaToBlock > 0) {
                temp = new byte[deltaToBlock];
                INraf.read(temp, 0, deltaToBlock);  //считывание неполного блока в temp
                temp = PKCS7.PKCS7(temp);
                //Иначе создается блок со значение всех байт 16
              } else {
                temp = new byte[AES.BLOCK_SIZE];
                for (int t = 0; t < AES.BLOCK_SIZE; t++) {
                  temp[t] = (byte) AES.BLOCK_SIZE;
                }
              }
              //Иначе происходит обычное считывание блока исходного текста в буфер temp
            } else {
              INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp
            }
            //Заполнение блока счетчика и формирование блока байт, который будет использоваться в раундах: 0000nnnn|0000cccc
            counter = ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System
                .arraycopy(counter, 0, nonceAndCounter, 12, 4);//nonceAndCounter: 0000nnnn|0000cccc

            byte[] k = new byte[AES.BLOCK_SIZE]; // k_i
            mAES.encrypt(nonceAndCounter, k);

            byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
            for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor c_i=(p_i XOR k_i)
              c[j] = (byte) (temp[j] ^ k[j]);
            }
            //Запись результата шифрования
            OUTraf.write(c);
            //Обновление элемента пользовательского интерфейса
            progressIndicator.setProgress((double) i / nBlocks);
          }
          //Закрытие файловых потоков
          OUTraf.close();
          INraf.close();
        } catch (IOException e) {
          CommonUtils.reportExceptionToMainThread(e, "Exception in encrypt thread!");
        }
        progressIndicator.setProgress(0.0);
        return null;
      }
    };
  }

  @Override
  public Task decrypt(File in, File out, final byte[] key) {
    return new Task<Void>() {
      @Override
      protected Void call() throws IOException {
        //Считывание из начала файла блока байт, который был добавлен при шифровании: nnnncccc
        byte[] nonceAndCounterInfo = new byte[8];
        nonceAndCounterInfo = FileUtils.readBytesFromFile(in, 0, 8);

        //Создание блоков байт для хранения nonce и счетчика(counter)
        byte[] nonce = new byte[8];
        byte[] counter = new byte[8];
        //Копирование значений в эти блоки
        System.arraycopy(nonceAndCounterInfo, 0, nonce, 0, 4);
        System.arraycopy(nonceAndCounterInfo, 4, counter, 0, 4);

        //Блок байт, который будет использоваться в раундах(16 байт): 0000nnnn|0000cccc
        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE];

        //Если длина ключа не кратна длине блока(16 байт), то он дополняется  PKCS7
        byte[] tempKey = key;
        if (key.length % AES.BLOCK_SIZE != 0) {
          tempKey = PKCS7.PKCS7(key);
        }
        //mAES — Объект класса AES. В него передается ключ, его длина и направление шифрования
        mAES.makeKey(tempKey, 128, AES.DIR_BOTH);
        try {
          //Открытие файла для записи результата дешифрования
          RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
          //Его длина устанавливается на 8 байт меньше чем длина зашифрованного файла
          OUTraf.setLength(in.length() - 8);
          //Открытие зашифрованного файла
          RandomAccessFile INraf = new RandomAccessFile(in, "r");

          //Количество блоков открытого текста
          int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE); //сколько блоков шифро текста
          //Количество байт, которые будут удалены с конца файла
          int nToDeleteBytes = 0; //сколько байт нужно удалить с конца сообщения

          //В буфер  temp будут считываться блоки по 16 байт из зашифрованного файла
          byte[] temp = new byte[AES.BLOCK_SIZE];
          //Главный цикл, в котором происходит обработка блоков
          for (int i = 0; i < nBlocks; i++) {
            //Установка указателя для считывания файла
            INraf.seek(i * 16 + 8);
            //Считывание из файла в буфер temp
            INraf.read(temp, 0, AES.BLOCK_SIZE);

            //Заполнение блока счетчика и формирование блока байт который будет использоваться в раундах: 0000nnnn|0000cccc
            counter = ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System.arraycopy(counter, 0, nonceAndCounter, 12, 4);

            byte[] k = new byte[AES.BLOCK_SIZE]; // k_i

            mAES.encrypt(nonceAndCounter, k);

            byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
            for (int j = 0; j < AES.BLOCK_SIZE; j++) {
              c[j] = (byte) (temp[j] ^ k[j]); //p_i=(c_i XOR k_i)
            }
            //Запись результата дешифрования
            OUTraf.write(c);

            //Если это последняя итерация
            if ((i + 1) == nBlocks) {
              //На случай дешифрования с неправильным ключом
              if (c[AES.BLOCK_SIZE - 1] > 0 && c[AES.BLOCK_SIZE - 1] <= 16) {
                //Количество байт, которые будут удалены с конца файла
                nToDeleteBytes = c[AES.BLOCK_SIZE
                    - 1]; //на случай дешифрования с неправильным ключем
              }
            }
            //Обновление элемента пользовательского интерфейса
            progressIndicator.setProgress((double) i / nBlocks);
          }
          //Из расшифрованного файла удаляются байты, которыми он был дополнен при шифровании
          OUTraf.setLength(OUTraf.length() - nToDeleteBytes);

          //Закрытие файловых потоков
          OUTraf.close();
          INraf.close();
        } catch (IOException e) {
          CommonUtils.reportExceptionToMainThread(e, "Exception in decrypt thread!");
        }
        progressIndicator.setProgress(0.0);
        return null;
      }
    };
  }

  /**
   * Получить Nonce
   *
   * @return значение Nonce
   */
  private int getNonce() {
    return Nonce.getInstance().getNonce();
  }
}
