import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Sender {
  private static int BUFFER_SIZE = 5 * 1024;

  private static SecretKeySpec AESKey() throws IOException {
    ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream("../symmetric.key")));
    SecretKeySpec key;
    try {
      key = (SecretKeySpec) in.readObject();
    } catch (Exception e) {
      throw new IOException("Failed to read AES key file", e);
    } finally {
      in.close();
    }
    return key;
  }

  private static PublicKey RSAKey() throws IOException {
    ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream("YPublic.key")));
    PublicKey key;
    try {
      BigInteger modulus = (BigInteger) in.readObject();
      BigInteger exponent = (BigInteger) in.readObject();
      RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      key = factory.generatePublic(publicSpec);
    } catch (Exception e) {
      throw new IOException("Failed to read RSA key from file", e);
    } finally {
      in.close();
    }
    return key;
  }

  private static void writeKMK(SecretKeySpec Kxy, String fileName) throws IOException {
    File file = new File(fileName);
    byte[] bfile = new byte[(int) file.length()];
    FileInputStream inStream = new FileInputStream(fileName);
    BufferedWriter wfile = new BufferedWriter(new FileWriter("message.kmk"));
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
        wfile.write(new String(slice, "UTF-8"));
      }
      wfile.write(eKxy);
    } catch (Exception e) {
      throw new IOException("Failed to write kmk", e);
    } finally {
      wfile.close();
      inStream.close();
    }
  }

  private static void writeHash() throws Exception { 
    BufferedInputStream file = new BufferedInputStream(new FileInputStream("message.kmk"));
    ObjectOutputStream wfile = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("message.khmac")));
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
    System.out.println("hash value:");
    wfile.writeInt(hash.length);
    wfile.write(hash);
    for (int k=0, j=0; k<hash.length; k++, j++) {
      System.out.format("%2X ", Byte.valueOf(hash[k]));
      if (j >= 15) {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");

    file.close();
    wfile.close();
  }

  private static void AESEncrypt(String fileName, SecretKeySpec Kxy) throws Exception {
    File file = new File(fileName);
    FileOutputStream wfile = new FileOutputStream("message.aescipher");
    FileInputStream inStream = new FileInputStream(file);
    byte[] bfile = new byte[(int) file.length()];
    try {
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
        cipher.init(Cipher.ENCRYPT_MODE, Kxy);
        wfile.write(cipher.doFinal(slice));
      }
    } catch (Exception e) {
      throw new IOException("Failed to perform AES Encryption", e);
    } finally {
      wfile.close();
      inStream.close();
    }
  }

  private static void RSAEncrypt(PublicKey Ky, SecretKeySpec Kxy) throws IOException {
    ObjectOutputStream wfile = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("xky.rsacipher")));
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, Ky);
      byte[] eKxy = cipher.doFinal(Kxy.getEncoded());
      wfile.write(eKxy.length);
      wfile.write(eKxy);
    } catch (Exception e) {
      throw new IOException("Failed to perform RSA Encryption", e);
    } finally {
      wfile.close();
    }
  }

  public static void main(String[] args) {
    SecretKeySpec Kxy;
    PublicKey Ky;
    Scanner in = new Scanner(System.in);
    System.out.println("Enter the name of the message file: ");
    String fileName = in.nextLine();
    in.close();

    try {
      Kxy = AESKey();
      Ky = RSAKey();
      writeKMK(Kxy, fileName);
      writeHash();
      AESEncrypt(fileName, Kxy);
      RSAEncrypt(Ky, Kxy);
    } catch (Exception e) {
      System.err.println(e);
      return;
    }
  }
}