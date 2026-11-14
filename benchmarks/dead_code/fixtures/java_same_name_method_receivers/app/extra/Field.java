package app.extra;

class Field {
    private boolean flag;

    void setFlag(boolean flag) {
        this.flag = flag;
    }

    void retire() {
        flag = false;
    }

    boolean canRead() {
        return flag;
    }

    @Override
    public String toString() {
        return String.valueOf(flag);
    }
}
