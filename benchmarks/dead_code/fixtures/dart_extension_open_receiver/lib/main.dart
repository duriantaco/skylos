import 'config.dart';
import 'extensions.dart';
import 'spare_extensions.dart';

class Loader {
  static String parseLike(String raw) => raw;
}

String render(Config config) {
  final label = config.describe().indent('  ');
  return config.describe().capitalized + label + Loader.parseLike(label);
}

void main() {
  print(render(const Config('report')));
}
