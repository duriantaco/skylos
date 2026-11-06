import 'dart:io';

Future<void> showStatus() async {
  await Process.run('printf', ['%s', 'ready'], runInShell: false);
}
