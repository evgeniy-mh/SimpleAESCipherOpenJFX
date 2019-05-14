package main.java.com.evgeniy_mh.simpleaescipher.AESEngine;

public class PKCS7 {

  /**
   * Дополняет массив байт до размера кратного AES.BLOCK_SIZE по стандарту PKCS7
   *
   * @param b-массив байт для которого будет выполнено дополнение PKCS7
   * @return Дополненный массив байт
   */
  public static byte[] PKCS7(byte[] b) {
    //Сколько байт нужно добавить и какое у них будет значение
    int n = countDeltaBlocks(b);

    //Если необходимо дополнить
    if (n != 0) {
      //bPadded - результат дополнения
      byte[] bPadded = new byte[b.length + n];
      for (int i = 0; i < bPadded.length; i++) {
        if (i < b.length) {
          //Запись существующих байт
          bPadded[i] = b[i];
        } else {
          //Запись дополняющей последовательности
          bPadded[i] = (byte) n;
        }
      }
      return bPadded;
    } else {
      return b;
    }
  }

  /**
   * Подсчет скольких байт не хватает до полного блока
   *
   * @param b Массив байт
   */
  private static int countDeltaBlocks(byte[] b) {
    return AES.BLOCK_SIZE - b.length % AES.BLOCK_SIZE;
  }
}
