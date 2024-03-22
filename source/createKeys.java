import security.src.Security;
import java.security.*;

public class createKeys {

    // generate keypair for Alice
    // generate keypair for Bob
    // generate keypair for Eve
    // generate secret key for Charlie
    public static void main(String[] args) {
        
        try {
            KeyPair keyPair = Security.generateKeyPair();
            PublicKey publicKeyClient = keyPair.getPublic();
            PrivateKey privateKeyClient = keyPair.getPrivate();
            Security.savePublicKey(publicKeyClient, "keys/Alice_ser.pub");
            Security.savePrivateKey(privateKeyClient, "keys/Alice_cli.key");

            keyPair = Security.generateKeyPair();
            PublicKey publicKeyServer = keyPair.getPublic();
            PrivateKey privateKeyServer = keyPair.getPrivate();
            Security.savePublicKey(publicKeyServer, "keys/Alice_cli.pub");
            Security.savePrivateKey(privateKeyServer, "keys/Alice_ser.key");

            keyPair = Security.generateKeyPair();
            publicKeyClient = keyPair.getPublic();
            privateKeyClient = keyPair.getPrivate();
            Security.savePublicKey(publicKeyClient, "keys/Bob_ser.pub");
            Security.savePrivateKey(privateKeyClient, "keys/Bob_cli.key");

            keyPair = Security.generateKeyPair();
            publicKeyServer = keyPair.getPublic();
            privateKeyServer = keyPair.getPrivate();
            Security.savePublicKey(publicKeyServer, "keys/Bob_cli.pub");
            Security.savePrivateKey(privateKeyServer, "keys/Bob_ser.key");

            keyPair = Security.generateKeyPair();
            publicKeyClient = keyPair.getPublic();
            privateKeyClient = keyPair.getPrivate();
            Security.savePublicKey(publicKeyClient, "keys/Eve_ser.pub");
            Security.savePrivateKey(privateKeyClient, "keys/Eve_cli.key");

            keyPair = Security.generateKeyPair();
            publicKeyServer = keyPair.getPublic();
            privateKeyServer = keyPair.getPrivate();
            Security.savePublicKey(publicKeyServer, "keys/Eve_cli.pub");
            Security.savePrivateKey(privateKeyServer, "keys/Eve_ser.key");

            keyPair = Security.generateKeyPair();
            publicKeyClient = keyPair.getPublic();
            privateKeyClient = keyPair.getPrivate();
            Security.savePublicKey(publicKeyClient, "keys/Charlie_ser.pub");
            Security.savePrivateKey(privateKeyClient, "keys/Charlie_cli.key");

            keyPair = Security.generateKeyPair();
            publicKeyServer = keyPair.getPublic();
            privateKeyServer = keyPair.getPrivate();
            Security.savePublicKey(publicKeyServer, "keys/Charlie_cli.pub");
            Security.savePrivateKey(privateKeyServer, "keys/Charlie_ser.key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}