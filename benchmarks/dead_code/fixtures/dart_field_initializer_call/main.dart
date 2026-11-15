class Settings {
  late final int limit = _compute();

  static final String shared = _build();

  final int spare = 4;

  int _compute() => 3;

  static String _build() => 'shared';

  int _orphan() => 5;

  int _spare() => 6;
}

void main() {
  final settings = Settings();
  print(settings.limit + settings.spare + Settings.shared.length);
}
