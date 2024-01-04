
import {
    Select,
    SelectOption,
    Button,
    PageSectionVariants,
    PageSection,
    ActionList,
    ActionListItem,
    List,
    ListItem,
    SelectOptionObject
} from '@patternfly/react-core';
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAlerts } from "ui-shared";
import { useKeycloak} from "keycloak-masthead";
import { usePromise } from "../utils/usePromise";
import { Page } from "../components/page/Page";
import {QRCodeSVG} from 'qrcode.react';
import { parseResponse } from "../api/parse-response";

interface CredentialOfferURI {
  issuer: string;
  nonce: string;
}


interface CredentialsIssuer {
  credential_issuer: string;
  credential_endpoint: string;
  credentials_supported: SupportedCredential[]
}

interface SupportedCredential {
  id: string,
  format: string,
  types: string[],
  cryptographic_binding_methods_supported: string[],
  cryptographic_suites_supported: string[]
}

type VCState = {
  dropdownItems: string[],
  selectOptions: Map<string, SupportedCredential>,
  credentialIssuer?: CredentialsIssuer,
  credential: string,
  issuerDid: string,
  vcUrl: string,
  offerUrl: string,
  isOpen: boolean,
  isDisabled: boolean,
  vcQRVisible: boolean,
  offerQRVisible: boolean,
  urlQRVisible: boolean,
  selected: string | SelectOptionObject
}

const VCIssuer = () => {
    const { t } = useTranslation();
    const { addAlert, addError } = useAlerts();
    const keycloak = useKeycloak();
    const initialState: VCState = {
        dropdownItems: [],
        selectOptions: new Map<string, SupportedCredential>(),
        credential: "",
        issuerDid: "",
        vcUrl: "",
        offerUrl: "",
        isOpen: false,
        isDisabled: true,
        vcQRVisible: false,
        urlQRVisible: false,
        selected:"",
        offerQRVisible: false
      }
    const [vcState, setState] = useState<VCState>(initialState);

    const url:string = keycloak?.keycloak.createAccountUrl()!
    const accountURL = new URL(url)
    const keycloakHost = accountURL.host
    const realm = keycloak?.keycloak.realm
    const wellKnownIssuer = accountURL.protocol + "//" + keycloakHost + "/realms/" + realm + "/.well-known/openid-credential-issuer"
    
    // just to trigger login
    getAccessToken();
    
    usePromise(
      (signal) =>
        Promise.all([
          getIssuer(wellKnownIssuer),
        ]),
      ([issuer]) => {
        
        const itemsList: string[] = [];
        const options = new Map<string, SupportedCredential>();
        issuer.credentials_supported.forEach((element: SupportedCredential) => {
        const key = element.id;
        itemsList.push(key);
        options.set(key, element);
        });
        setState( {...vcState, credentialIssuer: issuer, dropdownItems: itemsList, selectOptions: options});
    });

    async function getAccessToken() {
      try {
        await keycloak?.keycloak.updateToken();
      } catch (error) {
        await keycloak?.keycloak.login();
      }
    
      return keycloak?.keycloak.token;
    }

    async function getIssuer(wellKnownIssuer: string): Promise<CredentialsIssuer>{
      var options = {  
        method: 'GET'
      }
      return fetch(wellKnownIssuer, options)
        .then(response => parseResponse<CredentialsIssuer>(response))
    }

    function getSelectedCredential(): SupportedCredential {
      const selectedOption = vcState.selectOptions.get(vcState.selected.toString());
      if(selectedOption === undefined) {
        throw new Error("Selection failed.")
      }
    
      return selectedOption
  
    }

    function requestVCOffer() {

      const supportedCredential: SupportedCredential = getSelectedCredential()
      if (vcState.credentialIssuer == null) {
        addAlert("Was not able to retrieve the issuer information.")
      }
     
      
      const requestUrl = vcState.credentialIssuer!.credential_issuer + "/protocol/oid4vp/credential-offer-uri?credentialId=" + supportedCredential.id

      
      getAccessToken()
        .then(token => {
          var options = {  
            method: 'GET',
            headers: {
              'Authorization': 'Bearer ' +  token
            }
          }
          return fetch(requestUrl, options)
        })   
        .then(response => handleOfferResponse(response))

    }

    function handleOfferResponse(response: Response) {
      response.json()
        .then((offerURI: CredentialOfferURI) => {
          if (response.status !== 200) {
            addError("Did not receive an offer.");
            addAlert(response.status + ":" + response.statusText)
          } else {
            const credUrl = "openid-credential-offer://?credential_offer_uri=" + encodeURIComponent(offerURI.issuer + "/protocol/oid4vp/credential-offer/" + offerURI.nonce)
            console.log(credUrl)
            setState({ ...vcState,
              offerUrl: credUrl,
              vcQRVisible: false,
              offerQRVisible: true,
              urlQRVisible: false});
          }
        })    
    }

    return (
        <Page title='Issue VCs' description='Request a VC of the selected type or generate the request for importing it into your wallet.'>
          <PageSection isFilled variant={PageSectionVariants.light}>     
            <List isPlain>    
              <ListItem>   
                <Select
                  placeholderText="Select an option"
                  aria-label="Select Input with descriptions"
                  onToggle={isOpen => {
                    setState({...vcState,
                      isOpen
                    });
                  }}
                  onSelect={(e,s) => setState({ ...vcState,
                    selected: s,
                    isOpen: false,
                    isDisabled: false
                  })}
                  selections={vcState.selected}
                  isOpen={vcState.isOpen}
                >
                  {vcState.dropdownItems.map((option, index) => (
                    <SelectOption
                      key={index}
                      value={option} 
                    />
                  ))}
                </Select>     
              </ListItem>     
              <ListItem>         
                <ActionList>
                  <ActionListItem>
                    <Button 
                      onClick={() => requestVCOffer()}
                      isDisabled={vcState.isDisabled}>
                      Initiate Credential-Issuance(OID4VCI)
                    </Button>
                  </ActionListItem>
                </ActionList>
              </ListItem>           
              
              <ListItem>
              <ActionList>
              { vcState.offerQRVisible &&
                  <ActionListItem>
                <QRCodeSVG 
                  value={vcState.offerUrl}
                  bgColor={"#ffffff"}
                  fgColor={"#000000"}
                  level={"L"}
                  includeMargin={false}
                  size={512}/> 
                  </ActionListItem>
              }   
                </ActionList>
              </ListItem>
            </List>       
          </PageSection>   
        </Page>
        );
};


export default VCIssuer;