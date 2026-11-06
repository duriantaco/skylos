import 'dart:io';

Future<void> runCommand(String command) async {
  await Process.run(command, ['--version'], runInShell: false);
}
