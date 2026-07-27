import javafx.fxml.FXML;

class PrintController {
  @FXML
  private void printButtonAction() {
    System.out.println("print");
  }

  @FXML
  private void staleAnnotated() {
    System.out.println("stale annotation");
  }

  private void staleHelper() {
    System.out.println("stale");
  }
}
