static int parse_record(int value) {
    return value + 2;
}

static int serialize_record(int value) {
    return value - 2;
}

using Transform = int (*)(int);

int main() {
    Transform selected = &parse_record;
    return selected(4);
}
