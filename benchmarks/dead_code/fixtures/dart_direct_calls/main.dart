int _normalize(String value) => value.length;

int _render(String value) => _normalize(value);

int _summarize(String value) => value.length + 1;

void main() {
  print(_render('sample'));
}
