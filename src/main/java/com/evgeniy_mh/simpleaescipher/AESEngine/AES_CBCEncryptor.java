package main.java.com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Random;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;
import main.java.com.evgeniy_mh.simpleaescipher.CommonUtils;
import main.java.com.evgeniy_mh.simpleaescipher.FileUtils;

public class AES_CBCEncryptor extends Encryptor {

  public AES_CBCEncryptor(ProgressIndicator progressIndicator) {
    super(progressIndicator);
  }

  @Override
  public Task encrypt(File in, File out, byte[] key) {
    return new Task<Void>() {
      @Override
      protected Void call() throws IOException {
        //Создание блока вектора инициализации
        //с_0=IV
        Random random = new Random();
        byte[] IV = new byte[AES.BLOCK_SIZE];
        random.nextBytes(IV);

        //Если длина ключа не кратна длине блока(16 байт), то он дополняется  PKCS7
        byte[] tempKey = key;
        if (key.length % AES.BLOCK_SIZE != 0) {
          tempKey = PKCS7.PKCS7(key);
        }
        //mAES — Объект класса AES. В него передается ключ, его длина и направление шифрования
        mAES.makeKey(tempKey, 128, AES.DIR_BOTH);

        try {
          //Открытие файла для записи результата шифрования
          RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
          //Установка длины результирующего файла
          OUTraf.setLength(IV.length + in.length());
          //Запись нулевого блока (вектора инициализации)
          OUTraf.write(IV);

          //Открытие исходного файла
          RandomAccessFile INraf = new RandomAccessFile(in, "r");

          //Подсчет количества блоков открытого текста
          int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE);
          //Считываемый блок исходного текста
          byte[] temp = new byte[AES.BLOCK_SIZE];
          //Предыдущий зашифрованный блок
          byte[] prev = new byte[AES.BLOCK_SIZE];

          //Главный цикл в котором происходит обработка блоков
          for (int i = 0; i < nBlocks + 1; i++) {
            //Установка указателя для считывания файла
            INraf.seek(i * 16);

            if ((i + 1) == nBlocks + 1) { //последняя итерация
              //deltaToBlock — колчество недостающих байт до полного блока
              int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
              //Если это количество больше нуля происходит PKCS7 дополнение блока
              if (deltaToBlock > 0) {
                temp = new byte[deltaToBlock];
                //Считывание неполного блока в temp
                INraf.read(temp, 0, deltaToBlock);
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
              INraf.read(temp, 0, AES.BLOCK_SIZE);
            }

            byte[] k = new byte[AES.BLOCK_SIZE];
            if (i == 0) { //первая итерация
              for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                //c_1=(IV XOR p_1)
                k[j] = (byte) (IV[j] ^ temp[j]);
              }
            } else { //последующие итерации
              for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                //c_i=(c_i-1 XOR p_i)
                k[j] = (byte) (prev[j] ^ temp[j]);
              }
            }
            mAES.encrypt(k, prev);

            //Запись результата шифрования
            OUTraf.write(prev);
            //Обновление элемента пользовательского интерфейса
            progressIndicator.setProgress((double) i / nBlocks);
          }
          //Закрытие файловых потоков
          INraf.close();
          OUTraf.close();
        } catch (IOException e) {
          CommonUtils.reportExceptionToMainThread(e, "Exception in encrypt thread!");
        }
        //Обновление элемента пользовательского интерфейса
        progressIndicator.setProgress(0.0);
        return null;
      }
    };
  }

  @Override
  public Task decrypt(File in, File out, byte[] key) {
    return new Task<Void>() {
      @Override
      protected Void call() throws IOException {
        //Считывание вектора инициализации из входного файла
        byte[] IV = FileUtils.readBytesFromFile(in, AES.BLOCK_SIZE);

        byte[] tempKey = key;
        //Если длина ключа не кратна длине блока(16 байт), то он дополняется  PKCS7
        if (key.length % AES.BLOCK_SIZE != 0) {
          tempKey = PKCS7.PKCS7(key);
        }
        //mAES - объект класса AES. В него передается ключ, его длина и направление шифрования.
        mAES.makeKey(tempKey, 128, AES.DIR_BOTH);

        try {
          //Открытие файла для записи результата дешифрования
          RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
          //Установка длины файла
          OUTraf.setLength(in.length() - IV.length);
          //Открытие зашифрованного файла
          RandomAccessFile INraf = new RandomAccessFile(in, "r");

          //Количество блоков открытого текста
          int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE);
          //Количество байт, которые будут удалены с конца файла
          int nToDeleteBytes = 0;

          //В буфер  temp будут считываться блоки по 16 байт из зашифрованного файла
          byte[] temp = new byte[AES.BLOCK_SIZE];
          //В буфере prev хранится предыдущий блок зашифрованного сообщения
          byte[] prev = new byte[AES.BLOCK_SIZE];
          //Главный цикл, в котором происходит обработка блоков
          for (int i = 1; i < nBlocks; i++) {
            //Установка указателя для считывания файла
            INraf.seek(i * 16);
            //Считывание блока в temp
            INraf.read(temp, 0, AES.BLOCK_SIZE);

            byte[] k = new byte[AES.BLOCK_SIZE]; // k_i
            byte[] c = new byte[AES.BLOCK_SIZE]; //c_i

            //k_i=Dk(c_i)
            mAES.decrypt(temp, k);

            if (i == 1) { //первая итерация
              for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                //p_1=(IV XOR Dk(k_1))
                c[j] = (byte) (IV[j] ^ k[j]);
              }
              System.arraycopy(temp, 0, prev, 0, AES.BLOCK_SIZE);
            } else {
              for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                c[j] = (byte) (prev[j] ^ k[j]);
              }
            }
            System.arraycopy(temp, 0, prev, 0, AES.BLOCK_SIZE);
            OUTraf.write(c);

            //Если это последняя итерация
            if ((i + 1) == nBlocks) {
              //На случай дешифрования с неправильным ключом
              if (c[AES.BLOCK_SIZE - 1] > 0 && c[AES.BLOCK_SIZE - 1] <= 16) {
                //Количество байт, которые будут удалены с конца файла
                nToDeleteBytes = c[AES.BLOCK_SIZE - 1];
              }
            }
            //Обновление элемента пользовательского интерфейса
            progressIndicator.setProgress((double) i / nBlocks);
          }
          //Удаление байт дополнения
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
}
