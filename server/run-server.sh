javac ../src/main/java/ChatServer.java
javac ../src/main/java/SymmetricCryptography.java

mv ../src/main/java/ChatServer.class ./server
mv ../src/main/java/ChatServerThread.class ./server
mv ../src/main/java/SymmetricCryptography.class ./server

java ChatServer localhost 8080
