package security.src;

import com.google.gson.*;
import java.security.NoSuchAlgorithmException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileReader;

public class CommandLineInterface {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            help();
            return;
        }

        String command = args[0].toLowerCase();

        switch (command) {
            case "protect":
                if (args.length < 3) {
                    System.err.println("Argument(s) missing!");
                    System.out.println("Usage: Usage: protect <inputFile> <outputFile> <publicKeyFile>");
                    return;
                }
                try {
                    protect(args[1], args[2], args[3]);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            case "check":
                if (args.length < 2) {
                    System.err.println("Argument(s) missing!");
                    System.out.println("Usage: java-check <inputFile>");
                    return;
                }
                check(args[1]);
                break;
            case "unprotect":
                if (args.length < 3) {
                    System.err.println("Argument(s) missing!");
                    System.out.println("Usage: java CommandLineInterface unprotect <input file> <output file> <key file>");
                    return;
                }
                try {
                    unprotect(args[1], args[2], args[3]);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e){
                    e.printStackTrace();
                } catch (Exception e){
                    e.printStackTrace();
                }
                break;
            case "help":
                help();
                break;
            default:
                System.out.println("Invalid command. Use 'help' for usage information.");
        }
    }

    private static void help() {
        System.out.println("Usage:");
        System.out.println("  (tool-name) help");
        System.out.println("  (tool-name) protect (input-file) (output-file) (key-file)");
        System.out.println("  (tool-name) check (input-file)");
        System.out.println("  (tool-name) unprotect (input-file) (output-file) (key-file) ...");
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
    private static JsonObject protect(String inputFile, String outputFile, String privateKeyFile) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        JsonObject inputFileJson = loadDocument(inputFile);
        JsonObject protectedDocument = ProtectCommand.protectDocument(inputFileJson, outputFile, privateKeyFile);
        return protectedDocument;
    }

    private static String check(String inputFile) throws NoSuchAlgorithmException {
        JsonObject inputFileJson = loadDocument(inputFile);
        if (CheckCommand.checkDocument(inputFileJson)) {
            return "Document is valid";
        } else {
            return "Document is invalid";
        }
    }

    private static JsonObject unprotect(String inputFile, String outputFile, String keyFile) throws NoSuchAlgorithmException, FileNotFoundException, IOException, ClassNotFoundException, Exception {
        JsonObject inputFileJson = loadDocument(inputFile);
        JsonObject unprotectedDocument = UnprotectCommand.unprotectDocument(inputFileJson, outputFile, keyFile);
        return unprotectedDocument;
    }
}