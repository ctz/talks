import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class Test
{
  public static byte[] PBKDF2(String password, String salt, int iterations)
    throws NoSuchAlgorithmException, InvalidKeySpecException
  {
    SecretKeyFactory keyFactory = keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(Charset.forName("UTF-8")), iterations, 160);

    SecretKey secret = keyFactory.generateSecret(keySpec);

    return secret.getEncoded();
  }

  public static void main(String[] args)
  {
    try
    {
      int iterations = 1 << 22;
      byte[] v = PBKDF2("password", "saltsalt", iterations);
      System.out.print("SHA1," + iterations + ",");
      for (int i = 0; i < v.length; i++)
        System.out.print(String.format("%02x", v[i]));
      System.out.println("");
    } catch (Exception e) {
      throw new Error("Unexpected exception", e);
    }
  }
}
