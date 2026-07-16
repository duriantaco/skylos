package demo.app;

import demo.security.TokenVerifier;

class App {
    boolean run() {
        return TokenVerifier.verify("token");
    }
}
