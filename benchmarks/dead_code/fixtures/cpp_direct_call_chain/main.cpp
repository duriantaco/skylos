static int normalize(int value) {
    return value + 1;
}

static int render(int value) {
    return normalize(value);
}

static int summarize(int value) {
    return value - 1;
}

int main() {
    return render(7);
}
