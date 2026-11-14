package other;

public class Idle {
    private boolean flag;

    void setFlag(boolean flag) {
        this.flag = flag;
    }

    @Override
    public String toString() {
        return String.valueOf(flag);
    }
}
