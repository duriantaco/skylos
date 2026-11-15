package app;

class Permissions {
    private boolean flag;

    void setFlag(boolean flag) {
        this.flag = flag;
    }

    boolean isFlag() {
        return flag;
    }

    void retire() {
        flag = false;
    }

    boolean canRead() {
        return flag;
    }
}
