package security.src;

import com.google.gson.*;

import java.io.*;
import java.security.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;


public class CheckCommand {
    public static void main(String[] args) {

        // Check arguments
        if (args.length != 1) {
            System.err.println("Argument(s) missing!");
            System.err.println("Usage: java-check <inputFile>");
            return;
        }

        // Read the protected document from the inputFile
        JsonObject document = loadDocument(args[0]);
        System.out.println(checkDocument(document));

    }

    public static boolean checkDocument(JsonObject document) {
        JsonElement integrityElement = document.get("integrity");
        JsonElement timestampElement = document.get("timestamp");
        JsonElement sequenceNumberElement = document.get("sequenceNumber");
        JsonElement macElement = document.get("mac");

        document.remove("integrity");
        document.remove("timestamp");
        document.remove("sequenceNumber");
        document.remove("mac");

        // Validate integrity, freshness, and confidentiality
        try {
            if (validateIntegrity(document, macElement) == false) {
                return false;
            }
            if (validateFreshness(document, timestampElement, sequenceNumberElement) == false) {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
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

        return null;
    }

    private static boolean validateIntegrity(JsonObject document, JsonElement macElement) throws NoSuchAlgorithmException, InvalidKeyException {
         Mac mac = Mac.getInstance("HmacSHA256");

        // Initialize the MAC with the secret key
        try {
            SecretKey secretKey = Security.loadSecretKey("keys/secret.key");
        
            mac.init(secretKey);
            byte[] computedMacBytes = mac.doFinal(document.toString().getBytes(StandardCharsets.UTF_8));
            String computedMac = Base64.getEncoder().encodeToString(computedMacBytes);

            // Compare the received MAC with the computed MAC
            String receivedMac = macElement.getAsString();
            if (MessageDigest.isEqual(computedMacBytes, Base64.getDecoder().decode(receivedMac))) {
                //System.out.println("Message is authentic. Processing message:");
                return true;
            } else {
                System.out.println("Message is not authentic. Discarding message.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static boolean validateFreshness(JsonObject document, JsonElement timestampElement, JsonElement sequenceNumberElement) throws Exception {
        // Validate freshness by checking the timestamp
        if (timestampElement != null && timestampElement.isJsonPrimitive()) {
            long timestamp = timestampElement.getAsLong();
            long currentTimestamp = new Date().getTime();
            long freshnessThreshold = 5 * 60 * 1000; // 5 minutes in milliseconds (100000 just to pass)

            if (currentTimestamp - timestamp > freshnessThreshold) {
                System.out.println("Freshness violation: Document is not fresh.");
                return false;
            }
        } else {
            System.out.println("Timestamp property not found or is not a primitive type.");
            return false;
        }

        if (sequenceNumberElement != null) {
            // esta lista tera de ser guardada no servidor
            ArrayList<Integer> sequenceNumberArray = new ArrayList<>();
            int sequenceNumber = sequenceNumberElement.getAsInt();
            if (sequenceNumberArray.contains(sequenceNumber)) {
                System.out.println("Freshness violation: Document is not fresh.");
                return false;
            } else {
                sequenceNumberArray.add(sequenceNumber);
            }
        } else {
            System.out.println("Nonce property not found or is not a primitive type.");
            return false;
        }
    
        return true;
    }
}