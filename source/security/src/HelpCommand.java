package security.src;

public class HelpCommand {

    public static void main(String[] args) {
        System.out.println("Usage:");
        System.out.println("  (tool-name) help");
        System.out.println("  (tool-name) protect (input-file) (output-file) (key-file)");
        System.out.println("  (tool-name) check (input-file)");
        System.out.println("  (tool-name) unprotect (input-file) (output-file) (key-file) ...");
    }
}