import 'alias.dart';
import 'getter.dart';
import 'shadow.dart';
import 'spare.dart';
import 'version.dart';

void notify(NoticeCallback callback, String label) {
  callback(currentPlatform + toolVersion + label);
}

void main() {
  notify(print, 'local');
}
