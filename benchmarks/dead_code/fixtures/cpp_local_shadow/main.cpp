static int helper() { return 1; }
static int spare() { return 2; }
static int orphan() { return 4; }
int main() { int spare = 3; return helper() + spare; }
