import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
  private static int BUFFER_SIZE = 5 * 1024;
  
  private static PrivateKey RSAKey() throws IOException {
    ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream("YPrivate.key")));
    PrivateKey key;
    try {
      BigInteger modulus = (BigInteger) in.readObject();
      BigInteger exponent = (BigInteger) in.readObject();
      RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(modulus, exponent);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      key = factory.generatePrivate(privSpec);
    } catch (Exception e) {
      throw new IOException("Failed to read RSA key from file", e);
    } finally {
      in.close();
    }
    return key;
  }

  private static SecretKeySpec RSADecrypt(PrivateKey Ky) throws IOException {
    ObjectOutputStream wfile = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("message.kmk")));
    ObjectInputStream rfile = new ObjectInputStream(new BufferedInputStream(new FileInputStream("../sender/xky.rsacipher")));
    SecretKeySpec Kxy;
    try {
      int len = rfile.read();
      byte[] eKxy = new byte[len];
      rfile.read(eKxy);
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, Ky);
      byte[] decryptedKxy = cipher.doFinal(eKxy);
      Kxy = new SecretKeySpec(decryptedKxy, "AES");

      System.out.println("Symmetric Key (hex value)");
      for (int k=0, j=0; k<decryptedKxy.length; k++, j++) {
        System.out.format("%2X ", Byte.valueOf(decryptedKxy[k]));
        if (j >= 15) {
          System.out.println("");
          j=-1;
        }
      }

    } catch(Exception e) {
      throw new IOException("Failed to read Encrypted AES Key", e);
    } finally {
      rfile.close();
      wfile.close();
    }
    return Kxy;
  }

  private static void decryptM(SecretKeySpec Kxy, String fileName) throws Exception{
    File file = new File("../sender/message.aescipher");
    FileInputStream inStream = new FileInputStream("../sender/message.aescipher");
    FileOutputStream wStream = new FileOutputStream(fileName);
    BufferedWriter wfile = new BufferedWriter(new FileWriter("message.kmk"));
    byte[] bfile = new byte[(int) file.length()];
    String m = "";
    try {
      String eKxy = Base64.getEncoder().encodeToString(Kxy.getEncoded());
      wfile.write(eKxy);
      inStream.read(bfile);
      int extra = bfile.length % 16;
      for (int i = 0; i < bfile.length + extra; i+=16) {
        byte[] slice = new byte[16];
        for (int j = 0; j < 16; j++) {
          if (i+j < bfile.length) {
            slice[j] = bfile[i+j];
          }
        }
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, Kxy);
        byte[] decoded = cipher.doFinal(slice);

        wStream.write(decoded);
        wfile.write(new String(decoded, "UTF-8"));
      }
      
      wfile.write(eKxy);
    } catch (Exception e) {
      throw new IOException("Failed to perform AES Decryption", e);
    } finally {
      inStream.close();
      wStream.close();
      wfile.close();
    }
    System.out.println(m);
  }

  private static void verifyHash() throws Exception { 
    BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.kmk"));
    ObjectInputStream rfile = new ObjectInputStream(new BufferedInputStream(new FileInputStream("../sender/message.khmac")));
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    DigestInputStream in = new DigestInputStream(file, md);
    int i;
    byte[] buffer = new byte[BUFFER_SIZE];
    do {
      i = in.read(buffer, 0, BUFFER_SIZE);
    } while (i == BUFFER_SIZE);
    md = in.getMessageDigest();
    in.close();

    byte[] hash = md.digest();
    System.out.println("Calculated hash value:");
    for (int k=0, j=0; k<hash.length; k++, j++) {
      System.out.format("%2X ", Byte.valueOf(hash[k]));
      if (j >= 15) {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");

    int len = rfile.readInt();
    byte[] eKxy = new byte[len];
    rfile.read(eKxy);

    System.out.println("Stored hash value:");
    for (int k=0, j=0; k<len; k++, j++) {
      System.out.format("%2X ", Byte.valueOf(eKxy[k]));
      if (j >= 15) {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");

    for(int n=0; n < len; n++){
      if(eKxy[n] != hash[n]) {
        throw new Exception("Hash verification failed");
      }
    }

    System.out.println("Verified!");
    file.close();
    rfile.close();
  }

  public static void main(String[] args){
    PrivateKey Ky;
    SecretKeySpec Kxy;
    Scanner in = new Scanner(System.in);
    System.out.println("Enter the name of the message file: ");
    String fileName = in.nextLine();
    in.close();
    try{
      Ky = RSAKey();
      Kxy = RSADecrypt(Ky);
      decryptM(Kxy, fileName);
      verifyHash();
    } catch (Exception e) {
      System.err.println(e);
    }
  }
}