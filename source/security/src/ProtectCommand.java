package security.src;

import com.google.gson.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;

import javax.crypto.Mac;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import java.io.FileWriter;
import java.io.FileReader;

public class ProtectCommand {

    public static void main(String[] args)
    {
        if (args.length != 3) {
            System.out.println("This program protects a document.");
            System.out.println("Usage: protect <inputFile> <outputFile> <publicKeyFile>");
            return;
        }

        System.out.println("Protecting document...");
        try {
            JsonObject document = loadDocument(args[0]);
            protectDocument(document, args[1], args[2]);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } 

        System.out.println("Document protected successfully.");

    }

    public static JsonObject protectDocument(JsonObject document, String outputFile, String publicKeyFile) throws NoSuchAlgorithmException, FileNotFoundException, IOException
    {
        try {

            PublicKey publicKey = Security.loadPublicKey(publicKeyFile);
            SecretKey secretKey = Security.generateSecretKey();

            // save secret key to file
            Security.saveSecretKey(secretKey, "keys/secret.key");

            System.out.println("debug: secret key updated");

            if (document != null) {
                // Apply confidentiality protection to values, not keys
                JsonObject protectedDocument = protectValues(document, publicKey);

                // Apply integrity protection
                String integrityHash = Security.hash(protectedDocument.toString());
                //protectedDocument.addProperty("integrity", integrityHash);

                try {
                    // Create a MAC instance with HMAC-SHA-256 algorithm
                    Mac mac = Mac.getInstance("HmacSHA256");
                    
                    // Initialize the MAC with the secret key
                    mac.init(secretKey);
        
                    // Compute the MAC for the message
                    byte[] macBytes = mac.doFinal(protectedDocument.toString().getBytes(StandardCharsets.UTF_8));
        
                    // Convert the MAC bytes to a Base64-encoded string for transmission
                    String macString = Base64.getEncoder().encodeToString(macBytes);

                    protectedDocument.addProperty("mac", macString);

                    System.out.println("debug: mac added");
        
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    // Handle exceptions appropriately
                    e.printStackTrace();
                }
            
                protectedDocument.addProperty("integrity", integrityHash);

                System.out.println("debug: integrity hash added");

                // Apply freshness protection with timestamp
                long timestamp = new Date().getTime();
                protectedDocument.addProperty("timestamp", timestamp);

                System.out.println("debug: timestamp added");

                //Apply freshness protection with sequence number 
                // Generate a random sequence number
                SecureRandom random = SecureRandom.getInstanceStrong();
                protectedDocument.addProperty("sequenceNumber", random.nextInt());

                System.out.println("debug: unique sequence number added");

                // Serialize the protected document to JSON
                String protectedJsonString = new Gson().toJson(protectedDocument);

                // Write the protected JSON to the output file            
                try (FileWriter fileWriter = new FileWriter(outputFile)) {
                    fileWriter.write(protectedJsonString);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                return protectedDocument;

            } else {
                System.out.println("Document not loaded");
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static JsonObject loadDocument(String inputFile) {
        // Read the protected document from the inputFile
        try (FileReader fileReader = new FileReader(inputFile)) {
            // Parse the JSON document
            Gson gson = new Gson();
            JsonObject account = gson.fromJson(fileReader, JsonObject.class);

            return account;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new JsonObject();
    }

    private static byte[] encryptBody(byte[] data, PublicKey publicKey) {
        try {
            return Security.hybridEncrypt(data, publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    private static JsonObject protectValues(JsonObject document, PublicKey publicKey) {
        JsonObject protectedDocument = new JsonObject();

        for (Map.Entry<String, JsonElement> entry : document.entrySet()) {
            String key = entry.getKey();
            JsonElement value = entry.getValue();

            if ("movements".equals(key) && value.isJsonArray()) {
                // Handle the "movements" array separately
                JsonArray protectedMovements = new JsonArray();
                for (JsonElement movementElement : value.getAsJsonArray()) {
                    if (movementElement.isJsonObject()) {
                        // Protect individual fields within the movement object
                        JsonObject protectedMovement = new JsonObject();

                        protectField(protectedMovement, movementElement.getAsJsonObject(), "date", publicKey);
                        protectNumericField(protectedMovement, movementElement.getAsJsonObject(), "value", publicKey);
                        protectField(protectedMovement, movementElement.getAsJsonObject(), "description", publicKey);

                        protectedMovements.add(protectedMovement);
                    }
                }

                protectedDocument.add(key, protectedMovements);

            } else if ("accountHolder".equals(key)) {
                JsonArray protectedAccountHolder = new JsonArray();
                
                for (JsonElement protectedAccountHolderElement : value.getAsJsonArray()) {
                    if (protectedAccountHolderElement.isJsonPrimitive()) {
                        byte[] encryptedValue = encryptBody(protectedAccountHolderElement.getAsString().getBytes(StandardCharsets.UTF_8), publicKey);
                        protectedAccountHolder.add(new JsonPrimitive(new String(Base64.getEncoder().encode(encryptedValue))));
                    }
                }
                
                protectedDocument.add(key, protectedAccountHolder);

            } else {
                // Encrypt the value if it's not a JsonObject (nested object)
                if (!(value instanceof JsonObject)) {
                    if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                        // Handle numeric values separately
                        double numericValue = value.getAsJsonPrimitive().getAsDouble();
                        byte[] encryptedValue = encryptBody(Double.toString(numericValue).getBytes(StandardCharsets.UTF_8), publicKey);
                        protectedDocument.add(key, new JsonPrimitive(new String(Base64.getEncoder().encode(encryptedValue))));
                    } else {
                        protectField(protectedDocument, document, key, publicKey);
                    }
                } else {
                    // If it's a nested JsonObject, recursively protect its values
                    protectedDocument.add(key, protectValues(value.getAsJsonObject(), publicKey));
                }
            }
        }

        return protectedDocument;
    }

    private static void protectField(JsonObject protectedObject, JsonObject sourceObject, String field, PublicKey publicKey) {
        if (sourceObject.has(field)) {
            JsonElement fieldValue = sourceObject.get(field);

            if (fieldValue.isJsonPrimitive() && fieldValue.getAsJsonPrimitive().isNumber()) {
                // Handle numeric values separately
                protectedObject.add(field, fieldValue);
            } else {
                byte[] encryptedValue = encryptBody(fieldValue.getAsString().getBytes(StandardCharsets.UTF_8), publicKey);
                protectedObject.add(field, new JsonPrimitive(new String(Base64.getEncoder().encode(encryptedValue))));
            }
        }
    }

    private static void protectNumericField(JsonObject protectedObject, JsonObject sourceObject, String field, PublicKey publicKey) {
        if (sourceObject.has(field)) {
            JsonElement fieldValue = sourceObject.get(field);

            if (fieldValue.isJsonPrimitive() && fieldValue.getAsJsonPrimitive().isNumber()) {
                // Handle numeric values separately
                double numericValue = fieldValue.getAsJsonPrimitive().getAsDouble();
                byte[] encryptedValue = encryptBody(Double.toString(numericValue).getBytes(StandardCharsets.UTF_8), publicKey);
                protectedObject.add(field, new JsonPrimitive(new String(Base64.getEncoder().encode(encryptedValue))));
            } else {
                protectField(protectedObject, sourceObject, field, publicKey);
            }
        }
    }
}