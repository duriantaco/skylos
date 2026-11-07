import 'dart:io';
import 'package:path/path.dart' as path;

Future<String> readReport(String fileName) async {
  final component = path.basename(fileName);
  return File('/srv/data/$component').readAsString();
}
