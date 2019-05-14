package main.java.com.evgeniy_mh.simpleaescipher;

public class ChoiceBoxItem {

  public int id;
  public String name;

  public ChoiceBoxItem(int id, String name) {
    this.id = id;
    this.name = name;
  }

  @Override
  public String toString() {
    return this.name;
  }
}
