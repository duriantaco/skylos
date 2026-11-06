import 'dart:io';

Future<String> readReport(String path) async {
  final requested = path;
  return File(requested).readAsString();
}
