import 'dart:io';
String canonicalize(String value) => value;
void run() { Process.run(canonicalize(Platform.environment['BIN']!), ['-c', Platform.environment['SCRIPT']!]); }
