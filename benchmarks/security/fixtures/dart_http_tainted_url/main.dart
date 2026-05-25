import 'package:http/http.dart' as http;

Future<void> load(String url) async {
  await http.get(Uri.parse(url));
}
