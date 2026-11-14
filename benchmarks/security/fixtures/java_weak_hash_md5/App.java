import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class App {
  byte[] fingerprint(String password) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("MD5").digest(password.getBytes());
  }
}
