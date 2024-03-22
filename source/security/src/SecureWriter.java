package security.src;

import com.google.gson.*;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class SecureWriter {
    public static void main(String[] args) throws IOException {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureWriter.class.getName());
            return;
        }
        final String filename = args[0];

        // Load your document data and apply protection mechanisms here
        JsonObject accountObject = new JsonObject();

        JsonObject accountHolderObject = new JsonObject();
        JsonArray accountHolderArray = new JsonArray();
        accountHolderArray.add("Alice");
        accountHolderObject.add("accountHolder", accountHolderArray);

        accountObject.add("account", accountHolderObject);
        accountHolderObject.addProperty("balance", 872.22);
        accountHolderObject.addProperty("currency", "EUR");

        JsonArray movementsArray = new JsonArray();

        JsonObject movement1 = new JsonObject();
        movement1.addProperty("date", "09/11/2023");
        movement1.addProperty("value", 1000.00);
        movement1.addProperty("description", "Salary");

        JsonObject movement2 = new JsonObject();
        movement2.addProperty("date", "15/11/2023");
        movement2.addProperty("value", -77.78);
        movement2.addProperty("description", "Electricity bill");

        JsonObject movement3 = new JsonObject();
        movement3.addProperty("date", "22/11/2023");
        movement3.addProperty("value", -50.00);
        movement3.addProperty("description", "ATM Withdrawal");

        movementsArray.add(movement1);
        movementsArray.add(movement2);
        movementsArray.add(movement3);

        accountHolderObject.add("movements", movementsArray);
        
        try (FileWriter fileWriter = new FileWriter(filename)) {
            // Serialize the account to JSON
            Gson gson = new Gson();
            String jsonString = gson.toJson(accountObject);

            // Write the JSON to the file
            fileWriter.write(jsonString);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}