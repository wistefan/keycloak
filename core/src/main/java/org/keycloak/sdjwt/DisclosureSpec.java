package org.keycloak.sdjwt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages the specification of undisclosed claims and array elements.
 * 
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 * 
 */
public class DisclosureSpec {

    // Map of undisclosed claims and corresponding salt.
    // salt can be null;
    private final Map<SdJwtClaimName, DisclosureData> undisclosedClaims;

    // List of decoy claim. Digest will be produced from disclosure data (salt)
    private final List<DisclosureData> decoyClaims;

    // Key is the claim name, value is the list of undisclosed elements
    private final Map<SdJwtClaimName, Map<Integer, DisclosureData>> undisclosedArrayElts;

    // Key is the claim name, value is the list of decoy elements
    //  Digest will be produced from disclosure data (salt)
    private final Map<SdJwtClaimName, Map<Integer, DisclosureData>> decoyArrayElts;

    private DisclosureSpec(Map<SdJwtClaimName, DisclosureData> undisclosedClaims,
            List<DisclosureData> decoyClaims,
            Map<SdJwtClaimName, Map<Integer, DisclosureData>> undisclosedArrayElts,
            Map<SdJwtClaimName, Map<Integer, DisclosureData>> decoyArrayElts) {
        this.undisclosedClaims = undisclosedClaims;
        this.decoyClaims = decoyClaims;
        this.undisclosedArrayElts = undisclosedArrayElts;
        this.decoyArrayElts = decoyArrayElts;
    }

    public Map<Integer, DisclosureData> getUndisclosedArrayElts(SdJwtClaimName arrayClaimName) {
        return undisclosedArrayElts.get(arrayClaimName);
    }

    public Map<Integer, DisclosureData> getDecoyArrayElts(SdJwtClaimName arrayClaimName) {
        return decoyArrayElts.get(arrayClaimName);
    }

    public Map<SdJwtClaimName, DisclosureData> getUndisclosedClaims() {
        return undisclosedClaims;
    }

    public List<DisclosureData> getDecoyClaims() {
        return decoyClaims;
    }

    // check if a claim is undisclosed
    public DisclosureData getUndisclosedClaim(SdJwtClaimName claimName) {
        return undisclosedClaims.get(claimName);
    }

    // test is claim has undisclosed array elements
    public boolean hasUndisclosedArrayElts(SdJwtClaimName claimName) {
        return undisclosedArrayElts.containsKey(claimName);
    }

    public static class Builder {
        private final Map<SdJwtClaimName, DisclosureData> undisclosedClaims = new HashMap<>();
        private final List<DisclosureData> decoyClaims = new ArrayList<>();
        private final Map<SdJwtClaimName, Map<Integer, DisclosureData>> undisclosedArrayElts = new HashMap<>();
        private final Map<SdJwtClaimName, Map<Integer, DisclosureData>> decoyArrayElts = new HashMap<>();

        public Builder withUndisclosedClaim(String claimName, String salt) {
            this.undisclosedClaims.put(SdJwtClaimName.of(claimName), DisclosureData.of(salt));
            return this;
        }

        public Builder withUndisclosedClaim(String claimName) {
            return withUndisclosedClaim(claimName, null);
        }

        public Builder withDecoyClaim(String salt) {
            this.decoyClaims.add(DisclosureData.of(salt));
            return this;
        }

        public Builder withUndisclosedArrayElt(String claimName, Integer undisclosedEltIndex, String salt) {
            Map<Integer, DisclosureData> indexes = this.undisclosedArrayElts.computeIfAbsent(SdJwtClaimName.of(claimName),
                    k -> new HashMap<>());
            indexes.put(undisclosedEltIndex, DisclosureData.of(salt));
            return this;
        }

        public Builder withDecoyArrayElt(String claimName, Integer decoyEltIndex, String salt) {
            Map<Integer, DisclosureData> indexes = this.decoyArrayElts.computeIfAbsent(SdJwtClaimName.of(claimName),
                    k -> new HashMap<>());

            indexes.put(decoyEltIndex, DisclosureData.of(salt));
            return this;
        }

        public DisclosureSpec build() {
            Map<SdJwtClaimName, Map<Integer, DisclosureData>> undisclosedArrayEltMap = new HashMap<>();
            undisclosedArrayElts.forEach((k, v) -> {
                undisclosedArrayEltMap.put(k, Collections.unmodifiableMap((v)));
            });

            Map<SdJwtClaimName, Map<Integer, DisclosureData>> decoyArrayEltMap = new HashMap<>();
            decoyArrayElts.forEach((k, v) -> {
                decoyArrayEltMap.put(k, Collections.unmodifiableMap((v)));
            });

            return new DisclosureSpec(Collections.unmodifiableMap(undisclosedClaims),
                    Collections.unmodifiableList(decoyClaims),
                    Collections.unmodifiableMap(undisclosedArrayEltMap),
                    Collections.unmodifiableMap(decoyArrayEltMap));
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class DisclosureData {
        private final SdJwtSalt salt;

        private DisclosureData() {
            this.salt = null;
        }

        private DisclosureData(String salt) {
            this.salt = salt == null ? null : SdJwtSalt.of(salt);
        }

        public static DisclosureData of(String salt) {
            return salt == null ? new DisclosureData() : new DisclosureData(salt);
        }

        public SdJwtSalt getSalt() {
            return salt;
        }
    }
}