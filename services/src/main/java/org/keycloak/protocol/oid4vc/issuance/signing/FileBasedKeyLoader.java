package org.keycloak.protocol.oid4vc.issuance.signing;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileBasedKeyLoader implements KeyLoader {
    private static final Logger LOGGER = Logger.getLogger(FileBasedKeyLoader.class);
    private final String keyPath;

    public FileBasedKeyLoader(String keyPath) {
        this.keyPath = keyPath;
    }

    @Override
    public String loadKey() {
        Path keyFilePath = Paths.get(keyPath);
        try {
            return Files.readString(keyFilePath);
        } catch (IOException e) {
            LOGGER.errorf("Was not able to read the private key from %s", keyPath);
            throw new SigningServiceException("Was not able to read private key. Cannot initiate the SigningService.",
                    e);
        }
    }

}
