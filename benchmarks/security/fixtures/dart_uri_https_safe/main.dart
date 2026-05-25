import 'package:http/http.dart' as http;

Future<void> load(String input) async {
  final uri = Uri.https('api.example.com', '/v1/items', {'q': input});
  await http.get(uri);
}
