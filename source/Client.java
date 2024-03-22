import com.google.gson.*;

import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.net.*;
import javax.net.ssl.*;
import java.nio.ByteBuffer;

import security.src.ProtectCommand;
import security.src.UnprotectCommand;
import security.src.CheckCommand;
import security.src.Security;

public class Client {

    private static Properties config = loadConfig();

    public static void startClient(String host, int port) throws IOException, NoSuchAlgorithmException {

        String accountHolder = "";
        String pathToSecretKey = "";
        String pathToPublicKey = "";
        String pathToPrivateKey = "";

        SocketFactory factory = SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {

            socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            socket.setEnabledProtocols(new String[] { "TLSv1.3" });

            System.out.println("Welcome to A43 Insurance & Banking: BlingBank");
            System.out.print("Please enter your username to login: ");

            String line = "";
            try (Scanner scanner = new Scanner(System.in)) {
                accountHolder = scanner.nextLine();
                System.out.println("Type: 'exit' to close the connection");

                /* START */

                KeyPair keyPair = Security.generateKeyPair();

                // The private key is equal from the client and the server
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                // Save the private key to a file
                Security.savePrivateKey(privateKey, "keys/" + accountHolder + "_cli.key");

                // Save the public key to a file -> it will be sent to the server so it useless to save it
                //Security.savePublicKey(publicKey, "keys/" + accountHolder + "_cli.pub");

                // Send the public key to the server
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

                String message = accountHolder + " " + publicKeyString;

                BufferedOutputStream os = new BufferedOutputStream(socket.getOutputStream());
                BufferedInputStream is = new BufferedInputStream(socket.getInputStream());

                // send message to the server
                byte[] digitalSignature = "".getBytes();
                byte[] messageBytes = message.getBytes();

                os.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
                os.flush();

                os.write(messageBytes);
                os.flush();

                // Send the length of the digital signature
                os.write(ByteBuffer.allocate(4).putInt(digitalSignature.length).array());
                os.flush();

                // Send the digital signature
                os.write(digitalSignature);
                os.flush();

                byte[] data = new byte[16384];
                int len = is.read(data);
                String response = new String(data, 0, len);

                //Convert response to PublicKey  
                PublicKey serverPublicKey = Security.getPublicKeyfromString(response);
                
                // Save the server public key received from the server
                Security.savePublicKey(serverPublicKey, "keys/" + accountHolder + "_cli.pub");
                
                pathToPrivateKey = "keys/" + accountHolder + "_cli.key";
                pathToPublicKey = "keys/" + accountHolder + "_cli.pub";
                
                /* END */
                
                message = "connecting ( " + accountHolder + " ) to the server";

                os = new BufferedOutputStream(socket.getOutputStream());
                is = new BufferedInputStream(socket.getInputStream());

                response = sendMessageAndSignature(message, is, os, pathToPrivateKey);

                while (!line.equals("Exit")) {
                    try {
                        line = scanner.nextLine();
                        ;
                        System.out.println("sending message: " + line);

                        String command = line.split(" ")[0];

                        if (command.equals("checkBalance") || command.equals("listMovements")) {

                            response = sendMessageAndSignature(command
                                , new BufferedInputStream(socket.getInputStream())
                                , new BufferedOutputStream(socket.getOutputStream())
                                , pathToPrivateKey);

                            // Check if data is not empty or null
                            if (response != null) {
                                try {

                                    // Convert data to a JsonObject
                                    JsonObject dataToDecryptJson = JsonParser.parseString(response).getAsJsonObject();

                                    if (!(CheckCommand.checkDocument(dataToDecryptJson))) {
                                        System.out.println("Invalid document! It may have been tampered.");
                                        System.exit(0);
                                    }
                                    
                                    String outputFileName = "database/" + accountHolder + "_unprotected.json";
                                    
                                    // Get the encrypted data from the JsonObject
                                    JsonObject unprotectedJsonCheck = UnprotectCommand.unprotectDocument(dataToDecryptJson, 
                                        outputFileName, "keys/" + accountHolder + "_cli.key");
                                    
                                    if (command.equals("checkBalance")) {
                                        System.out.println("");
                                        System.out.println("Balance: " + unprotectedJsonCheck.get("account").getAsJsonObject().get("balance").getAsString());
                                        System.out.println("");
                                    } else {
                                        System.out.println("");
                                        System.out.println("Movements: "); 
                                        JsonArray movements = unprotectedJsonCheck.get("account").getAsJsonObject().get("movements").getAsJsonArray();
                                        for (int i = 0; i < movements.size(); i++) {
                                            JsonObject movement = movements.get(i).getAsJsonObject();
                                            System.out.println("    " + movement.get("date").getAsString() + " " + movement.get("value").getAsString() + " " + movement.get("description").getAsString());
                                        }
                                        System.out.println("");
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                
                            } else {
                                System.out.println("No data received from the server.");
                            }
                        } else if (command.equals("addAccountHolder")) {
                            
                            String[] args = line.split(" ");
                            String accountHolderToAdd = args[1];
                            try {
                                String encryptedAccountHolderToAdd = Base64.getEncoder().encodeToString(
                                    Security.hybridEncrypt(accountHolderToAdd.getBytes(), Security.loadPublicKey(pathToPublicKey)));

                                message = "addAccountHolder " + encryptedAccountHolderToAdd;

                                response = sendMessageAndSignature(message
                                    , new BufferedInputStream(socket.getInputStream())
                                    ,new BufferedOutputStream(socket.getOutputStream())
                                    , pathToPrivateKey);

                            } catch (Exception e) {
                                e.printStackTrace();
                            }    
                        } else if (command.equals("payment")) { // payment destinationAcccountHolder Amount Description
                            String[] args = line.split(" ");
                            String destinationAccountHolder = args[1];
                            String amount = args[2];
                            String description = "";
                            for (int i = 3; i < args.length; i++) {
                                description += args[i] + " ";
                            }

                            try {

                                JsonObject movement = new JsonObject();

                                String date = java.time.LocalDate.now().toString();
                                // Convert this format 2023-12-11 to this 09/11/2023
                                date = date.substring(8, 10) + "/" + date.substring(5, 7) + "/" + date.substring(0, 4);

                                movement.addProperty("date", date);
                                movement.addProperty("value", Double.parseDouble(amount));
                                movement.addProperty("description", description);
                                movement.addProperty("destinationAccountHolder", destinationAccountHolder);

                                JsonObject paymentProtected = ProtectCommand.protectDocument(movement, "database/paymentProtected.json", pathToPublicKey);

                                //convert JsonObject to String
                                String paymentProtectedString = paymentProtected.toString();

                                message = "payment" + " " + paymentProtectedString;

                                response = sendMessageAndSignature(message
                                    , new BufferedInputStream(socket.getInputStream())
                                    ,new BufferedOutputStream(socket.getOutputStream())
                                    , pathToPrivateKey);

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else if (command.equals("confirm")) {

                            response = sendMessageAndSignature(line
                                , new BufferedInputStream(socket.getInputStream())
                                ,new BufferedOutputStream(socket.getOutputStream())
                                , pathToPrivateKey);
            
                        } else if (command.equals("help")) {
                            System.out.println("Commands: ");
                            System.out.println("    checkBalance");
                            System.out.println("    listMovements");
                            System.out.println("    payment destinationAcccountHolder Value Description");
                            System.out.println("    exit");
                        } else if (command.equals("exit")) {
                            response = sendMessageAndSignature(command
                                    , new BufferedInputStream(socket.getInputStream())
                                    ,new BufferedOutputStream(socket.getOutputStream())
                                    , pathToPrivateKey);
                            break;
                        } else {
                            System.out.println("Invalid command!");
                            System.out.println("");
                            continue;
                        }
                    } catch (IOException i) {
                        System.out.println(i);
                        return;
                    }
                }
                try {
                    scanner.close();
                    is.close();
                    os.close();
                    socket.close();
                } catch (IOException i) {
                    System.out.println(i);
                    return;
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }
    

    private static Properties loadConfig() {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream("credentials/configClient.properties")) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;

    }

    public static String sendMessageAndSignature(String message, BufferedInputStream is, BufferedOutputStream os, String keyPath){
        
        String response = null;

        String command = message.split(" ")[0];

        if (command.equals("connecting")) {

            try {
                byte[] digitalSignature = "".getBytes();
                byte[] messageBytes = message.getBytes();

                os.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
                os.flush();

                os.write(messageBytes);
                os.flush();

                // Send the length of the digital signature
                os.write(ByteBuffer.allocate(4).putInt(digitalSignature.length).array());
                os.flush();

                // Send the digital signature
                os.write(digitalSignature);
                os.flush();

                byte[] data = new byte[16384];
                int len = is.read(data);
                response = new String(data, 0, len);
                
                if (len < 2048) {
                    System.out.println("");
                    System.out.printf("client received %d bytes: %s%n", len, response);
                    System.out.println("");
                }
                    
            }
            catch (Exception e){
                e.printStackTrace();
            }
        
            return response;

        } else {

            try {
                byte[] digitalSignature = Security.signMessage(message, Security.loadPrivateKey(keyPath));
                byte[] messageBytes = message.getBytes();

                System.out.println("debug: message has been signed");

                os.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
                os.flush();

                os.write(messageBytes);
                os.flush();

                // Send the length of the digital signature
                os.write(ByteBuffer.allocate(4).putInt(digitalSignature.length).array());
                os.flush();

                // Send the digital signature
                os.write(digitalSignature);
                os.flush();

                byte[] data = new byte[16384];
                int len = is.read(data);
                response = new String(data, 0, len);
                if(len < 2048) {
                    System.out.println("");
                    System.out.printf("client received %d bytes: %s%n", len, response);
                    System.out.println("");
                }
                    
            }
            catch (Exception e){
                e.printStackTrace();
            }
        
            return response;
        }
    }

    public static void main(String args[]) throws IOException {

        System.setProperty("javax.net.ssl.keyStore", config.getProperty("keyStorePath"));
        System.setProperty("javax.net.ssl.keyStorePassword", config.getProperty("keyStorePassword"));
        System.setProperty("javax.net.ssl.trustStore", config.getProperty("trustStorePath"));
        System.setProperty("javax.net.ssl.trustStorePassword", config.getProperty("trustStorePassword"));
        if (args.length == 1) {
            int port = Integer.parseInt(args[0]);
            try {
                startClient("localhost", port);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        } else
            return;
    }
}