package security.src;

import com.google.gson.*;

import javax.crypto.SecretKey;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.ClassNotFoundException;

public class UnprotectCommand {

    public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, Exception {
        if (args.length != 3) {
            System.out.println("This program unprotects a document.");
            System.out.println("Usage: unprotect <inputFile> <outputFile> <privateKeyFile>");
            return;
        }

        System.out.println("Unprotecting document...");

        JsonObject protectedDocument = loadDocument(args[0]);
        unprotectDocument(protectedDocument, args[1], args[2]);

        System.out.println("Document unprotected successfully.");
    }

    public static JsonObject unprotectDocument(JsonObject protectedDocument, String outputFile, String keyFile) throws Exception {
        //inputFile = "../database/" + inputFile;
        //outputFile = "../database/" + outputFile;
        //keyFile = "../keys/" + keyFile;

        if (protectedDocument != null) {
            // Load the secret key from the keyFile
            PrivateKey privateKey = Security.loadPrivateKey(keyFile);

            // Remove integrity field before processing
            protectedDocument.remove("integrity");

            System.out.println("debug: integrity removed");

            protectedDocument.remove("timestamp");

            System.out.println("debug: timestamp removed");

            protectedDocument.remove("sequenceNumber");

            System.out.println("debug: sequenceNumber removed");

            protectedDocument.remove("mac");

            System.out.println("debug: mac removed");

            // Decrypt values and reconstruct the original document
            JsonObject originalDocument = unprotect_values(protectedDocument, privateKey);

            // Save the original document to the outputFile
            try (FileWriter fileWriter = new FileWriter(outputFile)) {
                fileWriter.write(new Gson().toJson(originalDocument));
            } catch (Exception e) {
                e.printStackTrace();
            }

            return originalDocument;

        } else {
            System.out.println("Protected document not loaded");
            return null;
        }
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

    private static JsonObject unprotect_values(JsonObject protectedDocument, PrivateKey privateKey) throws FileNotFoundException {
        // Remove protection mechanisms and decrypt the document
        JsonObject unprotectedDocument = new JsonObject();

        for (Map.Entry<String, JsonElement> entry : protectedDocument.entrySet()) {
            String key = entry.getKey();
            JsonElement value = entry.getValue();

            if ("movements".equals(key) && value.isJsonArray()) {
                // Handle the "movements" array separately
                JsonArray originalMovements = new JsonArray();
                for (JsonElement protectedMovementElement : value.getAsJsonArray()) {
                    if (protectedMovementElement.isJsonObject()) {
                        // Unprotect individual fields within the movement object
                        JsonObject originalMovement = new JsonObject();

                        unprotectField(originalMovement, protectedMovementElement.getAsJsonObject(), "date", privateKey);
                        unprotectNumericField(originalMovement, protectedMovementElement.getAsJsonObject(), "value", privateKey);
                        unprotectField(originalMovement, protectedMovementElement.getAsJsonObject(), "description", privateKey);

                        originalMovements.add(originalMovement);
                    }
                }

                unprotectedDocument.add(key, originalMovements);

            } else if ("accountHolder".equals(key) && value.isJsonArray()) {
                // Handle the "accountHolder" array separately
                JsonArray originalAccountHolder = new JsonArray();
                for (JsonElement protectedAccountHolderElement : value.getAsJsonArray()) {
                    if (protectedAccountHolderElement.isJsonPrimitive()) {
                        // Unprotect individual fields within the movement object
                        String decodedValue = decodeValue(protectedAccountHolderElement.getAsString(), privateKey);
                        originalAccountHolder.add(decodedValue);
                    }
                }

                unprotectedDocument.add(key, originalAccountHolder);

            } else {
                // Decrypt the value if it's not a JsonObject (nested object)
                if (!(value instanceof JsonObject) && !("balance".equals(key))) {
                    unprotectField(unprotectedDocument, protectedDocument, key, privateKey);
                } else if ("balance".equals(key)) {
                    unprotectNumericField(unprotectedDocument, protectedDocument, key, privateKey);
                } else {
                    // If it's a nested JsonObject, recursively unprotect its values
                    unprotectedDocument.add(key, unprotect_values(value.getAsJsonObject(), privateKey));
                }
            }
        }

        return unprotectedDocument;
    }

    private static String decodeValue(String encodedValue, PrivateKey privateKey) {
        byte[] decryptedValue = decryptBody(Base64.getDecoder().decode(encodedValue), privateKey);
        return new String(decryptedValue, StandardCharsets.UTF_8);
    }

    private static void unprotectField(JsonObject originalObject, JsonObject protectedObject, String field, PrivateKey privateKey) {
        if (protectedObject.has(field)) {
            JsonElement fieldValue = protectedObject.get(field);

            if (fieldValue.isJsonPrimitive()) {
                // Handle numbers and strings differently
                if (fieldValue.getAsJsonPrimitive().isNumber()) {
                    originalObject.add(field, fieldValue);
                } else {
                    String decodedValue = decodeValue(fieldValue.getAsString(), privateKey);
                    originalObject.addProperty(field, decodedValue);
                }
            } else {
                // For other types, add them directly to the original object
                originalObject.add(field, fieldValue);
            }
        }
    }

    private static double decodeNumericValue(String encodedValue, PrivateKey privateKey) {
        byte[] decryptedValue = decryptBody(Base64.getDecoder().decode(encodedValue), privateKey);
        return Double.parseDouble(new String(decryptedValue, StandardCharsets.UTF_8));
    }

    private static void unprotectNumericField(JsonObject originalObject, JsonObject protectedObject, String field, PrivateKey privateKey) {
        if (protectedObject.has(field)) {
            JsonElement fieldValue = protectedObject.get(field);

            if (fieldValue.isJsonPrimitive() && fieldValue.getAsJsonPrimitive().isNumber()) {
                // Handle numeric values separately
                originalObject.add(field, fieldValue);
            } else if (fieldValue.isJsonPrimitive() && fieldValue.getAsJsonPrimitive().isString()) {
                // Convert string representation of numbers to numeric values
                try {
                    double numericValue = decodeNumericValue(fieldValue.getAsString(), privateKey);
                    originalObject.addProperty(field, numericValue);
                } catch (NumberFormatException e) {
                    // Handle parsing error, if any
                    e.printStackTrace();
                }
            } else {
                // For other types, add them directly to the original object
                originalObject.add(field, fieldValue);
            }
        }
    }

    private static byte[] decryptBody(byte[] data, PrivateKey privateKey) {
        try {
            return Security.hybridDecrypt(data, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[0];
    }
}