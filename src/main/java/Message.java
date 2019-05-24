package main.java;

public class Message {
    private final byte[] plainText;
    private final byte[] signature;
    private final byte[] aliasPublic;

    public Message(final byte [] plainText,final byte [] signature,final byte [] aliasPublic) {
        this.plainText = plainText;
        this.signature = signature;
        this.aliasPublic = aliasPublic;
    }

    public String getPlainText() {
        return new String(plainText);
    }

    public byte[] getPlainTextAsByteArray() { return plainText; }

    public byte[] getSignature() {
        return signature;
    }

    public String getAliasPublic() {
        return new String(aliasPublic);
    }

    public byte[] getAliasPublicAsByteArray() {
        return aliasPublic;
    }
}
