class TextCodec {
  int _process() => _measure();
  int _measure() => 1;
  int _snapshot() => 2;

  void run() {
    print(_process());
  }
}

class BinaryCodec {
  int _process() => 3;
}

void main() {
  BinaryCodec();
  TextCodec().run();
}
