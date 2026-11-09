import 'dart:io';
import 'package:http/http.dart' as http;
String canonicalize(String value) => value;
void run() { http.get(Uri.parse(canonicalize(Platform.environment['URL']!))); }
