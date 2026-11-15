import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class App {
  byte[] fingerprint(String password) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("SHA-256").digest(password.getBytes());
  }
}
