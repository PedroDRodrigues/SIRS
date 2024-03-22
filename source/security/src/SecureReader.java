package security.src;

import com.google.gson.*;

import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class SecureReader {
    public static void main(String[] args) throws IOException {
        //Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", SecureReader.class.getName());
            return;
        }
        final String filename = args[0];

        // Read the protected document from a file
        try (FileReader fileReader = new FileReader(filename)) {
            // Parse the JSON document
            Gson gson = new Gson();
            JsonObject account = gson.fromJson(fileReader, JsonObject.class);

            // Validate integrity, freshness, and confidentiality here

            // Extract and print document details
            System.out.println("Account:");
            JsonObject headerObject = account.get("account").getAsJsonObject();
            JsonArray accountHolderArray = headerObject.getAsJsonArray("accountHolder");
            System.out.println("    Account Holder: " + accountHolderArray.get(0).getAsString());
            System.out.println("    Balance: " + headerObject.get("balance").getAsDouble());
            System.out.println("    Currency: " + headerObject.get("currency").getAsString());

            JsonArray movementsArray = headerObject.getAsJsonArray("movements");
            System.out.println("    Movements:");
            for (JsonElement movement : movementsArray) {
                JsonObject movementObject = movement.getAsJsonObject();
                System.out.println("        Date: " + movementObject.get("date").getAsString());
                System.out.println("        Value: " + movementObject.get("value").getAsDouble());
                System.out.println("        Description: " + movementObject.get("description").getAsString());
                System.out.println();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}