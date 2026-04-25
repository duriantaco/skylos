public class App {
  public static void main(String[] args) {
    App app = new App();
    app.handle();
  }

  void handle() {
    formatStatus("ok");
  }

  String formatStatus(String status) {
    return status;
  }

  String unusedFormatter() {
    return "stale";
  }
}

class UnusedController {
  String render() {
    return "unused";
  }
}
