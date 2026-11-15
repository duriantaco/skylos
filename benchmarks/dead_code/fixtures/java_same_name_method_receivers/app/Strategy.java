package app;

import java.io.File;

public class Strategy {
    public Object build() {
        Permissions p = new Permissions();
        p.setFlag(true);
        return p;
    }

    public boolean ready(File marker) {
        return marker.canRead();
    }
}
