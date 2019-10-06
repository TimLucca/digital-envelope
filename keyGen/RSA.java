import java.util.*;
import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;
import javax.crypto.SecretKey;

import javax.crypto.Cipher;

public class RSA {
  public static void main(String[] args) throws Exception {
    String[] list = {"X","Y"};
    for(String item:list){
      SecureRandom random = new SecureRandom();
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(1024, random);  //1024: key size in bits
      KeyPair pair = generator.generateKeyPair();
      Key pubKey = pair.getPublic();
      Key privKey = pair.getPrivate();
      
      KeyFactory factory = KeyFactory.getInstance("RSA");
      RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
          RSAPublicKeySpec.class);
      RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
          RSAPrivateKeySpec.class);

      //save the parameters of the keys to the files
      if(item.equals("X")){
        saveToFile("../sender/"+item+"Private.key", privKSpec.getModulus(), 
          privKSpec.getPrivateExponent());
        saveToFile("../receiver/"+item+"Public.key", pubKSpec.getModulus(), 
          pubKSpec.getPublicExponent());
      } else {
        saveToFile("../sender/"+item+"Public.key", pubKSpec.getModulus(), 
          pubKSpec.getPublicExponent());
        saveToFile("../receiver/"+item+"Private.key", privKSpec.getModulus(), 
          privKSpec.getPrivateExponent());
      }
      saveToFile(""+item+"Public.key", pubKSpec.getModulus(), 
        pubKSpec.getPublicExponent());
      saveToFile(""+item+"Private.key", privKSpec.getModulus(), 
        privKSpec.getPrivateExponent());
    }
    System.out.println("Enter a character message: ");
    Scanner scannyboi = new Scanner(System.in);
    SecretKeySpec key  = new SecretKeySpec(scannyboi.nextLine().getBytes("UTF-8"),"AES");
    saveToFile("../symmetric.key", key);
    scannyboi.close();
  }

  public static void saveToFile(String fileName, SecretKeySpec key) throws IOException{
    ObjectOutputStream oout = new ObjectOutputStream(
      new BufferedOutputStream(new FileOutputStream(fileName)));
    try {
      oout.writeObject(key);
    } catch (Exception e) {
      throw new IOException("Unexpected error", e);
    } finally {
      oout.close();
    }
  }

  public static void saveToFile(String fileName,
    BigInteger mod, BigInteger exp) throws IOException {

    System.out.println("Write to " + fileName + ": modulus = " + 
        mod.toString() + ", exponent = " + exp.toString() + "\n");

    ObjectOutputStream oout = new ObjectOutputStream(
      new BufferedOutputStream(new FileOutputStream(fileName)));

    try {
      oout.writeObject(mod);
      oout.writeObject(exp);
    } catch (Exception e) {
      throw new IOException("Unexpected error", e);
    } finally {
      oout.close();
    }
  }
}