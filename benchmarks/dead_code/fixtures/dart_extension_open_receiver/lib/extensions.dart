extension TextTools on String {
  String indent(String prefix) => '$prefix$this';

  String get capitalized =>
      isEmpty ? this : this[0].toUpperCase() + substring(1);

  String orphanTrim() => trim();

  String parseLike() => this;
}
