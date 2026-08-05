package sso

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ciradar/internal/model"
)

type samlResponse struct {
	XMLName      xml.Name      `xml:"Response"`
	ID           string        `xml:"ID,attr"`
	InResponseTo string        `xml:"InResponseTo,attr"`
	Destination  string        `xml:"Destination,attr"`
	Issuer       string        `xml:"Issuer"`
	Status       samlStatus    `xml:"Status"`
	Assertion    samlAssertion `xml:"Assertion"`
}

type samlStatus struct {
	Code struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
}

type samlAssertion struct {
	ID         string                   `xml:"ID,attr"`
	Issuer     string                   `xml:"Issuer"`
	Subject    samlSubject              `xml:"Subject"`
	Conditions samlConditions           `xml:"Conditions"`
	Attributes []samlAttributeStatement `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID        string `xml:"NameID"`
	Confirmations []struct {
		Method string `xml:"Method,attr"`
		Data   struct {
			InResponseTo string `xml:"InResponseTo,attr"`
			Recipient    string `xml:"Recipient,attr"`
			NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
		} `xml:"SubjectConfirmationData"`
	} `xml:"SubjectConfirmation"`
}

type samlConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Restrictions []struct {
		Audiences []string `xml:"Audience"`
	} `xml:"AudienceRestriction"`
}

type samlAttributeStatement struct {
	Attributes []struct {
		Name   string   `xml:"Name,attr"`
		Values []string `xml:"AttributeValue"`
	} `xml:"Attribute"`
}

func (m *Manager) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if !m.Enabled() || m.cfg.Mode != "saml" {
		http.NotFound(w, r)
		return
	}
	entity := html.EscapeString(m.cfg.SAMLEntityID)
	acs := html.EscapeString(m.cfg.SAMLACSURL)
	metadata := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entity + `"><md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + acs + `" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>`
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, metadata)
}

func (m *Manager) samlLogin(w http.ResponseWriter, r *http.Request) {
	randomID, err := randomText(24)
	if err != nil {
		http.Error(w, "SAML request ID creation failed", http.StatusInternalServerError)
		return
	}
	requestID := "_" + randomID
	state, err := randomText(24)
	if err != nil {
		http.Error(w, "SAML state creation failed", http.StatusInternalServerError)
		return
	}
	flow := flowState{State: state, RequestID: requestID, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to")), Expires: time.Now().Add(10 * time.Minute)}
	if err := m.writeFlow(w, flow); err != nil {
		http.Error(w, "SAML state creation failed", http.StatusInternalServerError)
		return
	}
	request := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>`, html.EscapeString(requestID), time.Now().UTC().Format(time.RFC3339Nano), html.EscapeString(m.cfg.SAMLIdPSSOURL), html.EscapeString(m.cfg.SAMLACSURL), html.EscapeString(m.cfg.SAMLEntityID))
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		http.Error(w, "SAML request compression failed", http.StatusInternalServerError)
		return
	}
	if _, err := writer.Write([]byte(request)); err != nil {
		_ = writer.Close()
		http.Error(w, "SAML request compression failed", http.StatusInternalServerError)
		return
	}
	if err := writer.Close(); err != nil {
		http.Error(w, "SAML request compression failed", http.StatusInternalServerError)
		return
	}
	q := url.Values{}
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(compressed.Bytes()))
	q.Set("RelayState", state)
	http.Redirect(w, r, m.cfg.SAMLIdPSSOURL+joinQuery(m.cfg.SAMLIdPSSOURL, q.Encode()), http.StatusFound)
}

func (m *Manager) samlCallback(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid SAML form", http.StatusBadRequest)
		return
	}
	rawResponse := r.Form.Get("SAMLResponse")
	if rawResponse == "" || len(rawResponse) > 4<<20 {
		http.Error(w, "missing SAML response", http.StatusBadRequest)
		return
	}
	flow, err := m.readFlow(r)
	m.clearFlow(w)
	if err != nil || time.Now().After(flow.Expires) || !constantText(r.Form.Get("RelayState"), flow.State) {
		http.Error(w, "expired SAML state", http.StatusBadRequest)
		return
	}
	xmlBytes, err := base64.StdEncoding.DecodeString(rawResponse)
	if err != nil || len(xmlBytes) > 2<<20 {
		http.Error(w, "invalid SAML encoding", http.StatusBadRequest)
		return
	}
	if err := validateSAMLShape(xmlBytes, flow.RequestID); err != nil {
		http.Error(w, "invalid SAML response", http.StatusUnauthorized)
		return
	}
	if err := verifySAMLXML(m.cfg.SAMLXMLSecPath, m.cfg.SAMLIdPCertificate, xmlBytes); err != nil {
		http.Error(w, "SAML signature validation failed", http.StatusUnauthorized)
		return
	}
	identity, err := m.parseSAMLIdentity(xmlBytes, flow.RequestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := m.writeSession(w, identity, 8*time.Hour); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func validateSAMLShape(data []byte, requestID string) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	ids := map[string]bool{}
	assertions, signatures, encrypted, responses := 0, 0, 0, 0
	references := []string{}
	responseID, assertionID := "", ""
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.Directive, xml.ProcInst:
			return errors.New("SAML directives are not allowed")
		case xml.StartElement:
			depth++
			if depth > 64 {
				return errors.New("SAML document is too deeply nested")
			}
			switch value.Name.Local {
			case "Response":
				if value.Name.Space != "urn:oasis:names:tc:SAML:2.0:protocol" || depth != 1 {
					return errors.New("invalid SAML Response namespace or placement")
				}
				responses++
			case "Assertion":
				if value.Name.Space != "urn:oasis:names:tc:SAML:2.0:assertion" {
					return errors.New("invalid SAML Assertion namespace")
				}
				assertions++
			case "EncryptedAssertion":
				encrypted++
			case "Signature":
				if value.Name.Space != "http://www.w3.org/2000/09/xmldsig#" {
					return errors.New("invalid XML Signature namespace")
				}
				signatures++
			case "Reference":
				if value.Name.Space != "http://www.w3.org/2000/09/xmldsig#" {
					return errors.New("invalid XML Signature Reference namespace")
				}
				for _, attribute := range value.Attr {
					if attribute.Name.Local == "URI" {
						references = append(references, attribute.Value)
					}
				}
			}
			for _, attribute := range value.Attr {
				if attribute.Name.Local != "ID" {
					continue
				}
				if attribute.Value == "" || ids[attribute.Value] {
					return errors.New("duplicate SAML ID")
				}
				ids[attribute.Value] = true
				if value.Name.Local == "Response" {
					responseID = attribute.Value
				}
				if value.Name.Local == "Assertion" {
					assertionID = attribute.Value
				}
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return errors.New("invalid SAML nesting")
			}
		}
	}
	if responses != 1 || assertions != 1 || signatures != 1 || encrypted != 0 || depth != 0 {
		return errors.New("unsupported SAML document shape")
	}
	if requestID == "" || responseID == "" || assertionID == "" {
		return errors.New("missing SAML request or document ID")
	}
	if len(references) != 1 || !strings.HasPrefix(references[0], "#") {
		return errors.New("invalid SAML signature reference")
	}
	target := strings.TrimPrefix(references[0], "#")
	if target != responseID && target != assertionID {
		return errors.New("SAML signature must cover the Response or Assertion")
	}
	return nil
}

func verifySAMLXML(xmlsecPath, certificate string, data []byte) error {
	executable, err := exec.LookPath(xmlsecPath)
	if err != nil {
		return fmt.Errorf("locate xmlsec1: %w", err)
	}
	directory, err := os.MkdirTemp("", "ciradar-saml-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	responsePath := filepath.Join(directory, "response.xml")
	certificatePath := filepath.Join(directory, "idp.pem")
	if err := os.WriteFile(responsePath, data, 0600); err != nil {
		return err
	}
	if strings.Contains(certificate, "BEGIN CERTIFICATE") {
		if err := os.WriteFile(certificatePath, []byte(certificate), 0600); err != nil {
			return err
		}
	} else {
		content, err := os.ReadFile(certificate)
		if err != nil {
			return err
		}
		if err := os.WriteFile(certificatePath, content, 0600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "--verify", "--pubkey-cert-pem", certificatePath, "--enabled-reference-uris", "same-doc", "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion", responsePath)
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("xmlsec verification timed out")
		}
		return fmt.Errorf("xmlsec verification failed: %s", truncateMessage(string(output), 512))
	}
	return nil
}

func (m *Manager) parseSAMLIdentity(data []byte, requestID string) (model.SSOIdentity, error) {
	var response samlResponse
	if err := xml.Unmarshal(data, &response); err != nil {
		return model.SSOIdentity{}, err
	}
	if response.Status.Code.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return model.SSOIdentity{}, errors.New("SAML authentication was not successful")
	}
	if response.InResponseTo != requestID || response.Destination != m.cfg.SAMLACSURL {
		return model.SSOIdentity{}, errors.New("SAML response binding mismatch")
	}
	if strings.TrimSpace(response.Issuer) != m.cfg.SAMLIdPEntityID || strings.TrimSpace(response.Assertion.Issuer) != m.cfg.SAMLIdPEntityID {
		return model.SSOIdentity{}, errors.New("SAML issuer mismatch")
	}
	now := time.Now().UTC()
	if !withinSAMLWindow(response.Assertion.Conditions.NotBefore, response.Assertion.Conditions.NotOnOrAfter, now, m.cfg.SAMLClockSkew) {
		return model.SSOIdentity{}, errors.New("SAML assertion expired")
	}
	audienceOK := false
	for _, restriction := range response.Assertion.Conditions.Restrictions {
		for _, audience := range restriction.Audiences {
			if strings.TrimSpace(audience) == m.cfg.SAMLEntityID {
				audienceOK = true
			}
		}
	}
	if !audienceOK {
		return model.SSOIdentity{}, errors.New("SAML audience mismatch")
	}
	confirmationOK := false
	for _, confirmation := range response.Assertion.Subject.Confirmations {
		if confirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			continue
		}
		if confirmation.Data.InResponseTo == requestID && confirmation.Data.Recipient == m.cfg.SAMLACSURL && beforeSAMLExpiry(confirmation.Data.NotOnOrAfter, now, m.cfg.SAMLClockSkew) {
			confirmationOK = true
		}
	}
	if !confirmationOK {
		return model.SSOIdentity{}, errors.New("SAML subject confirmation mismatch")
	}
	claims := map[string]any{"sub": strings.TrimSpace(response.Assertion.Subject.NameID), "iss": m.cfg.SAMLIdPEntityID}
	for _, statement := range response.Assertion.Attributes {
		for _, attribute := range statement.Attributes {
			values := make([]any, 0, len(attribute.Values))
			for _, value := range attribute.Values {
				values = append(values, strings.TrimSpace(value))
			}
			if len(values) == 1 {
				claims[attribute.Name] = values[0]
			} else if len(values) > 1 {
				claims[attribute.Name] = values
			}
		}
	}
	email := firstNonEmpty(stringClaim(claims, m.cfg.SAMLEmailAttribute), stringClaim(claims, "email"), strings.TrimSpace(response.Assertion.Subject.NameID))
	claims["email"] = email
	// The email attribute is covered by the validated SAML signature. Mark it as
	// verified so the shared identity policy can safely enforce allowed_domains.
	claims["email_verified"] = true
	claims["name"] = firstNonEmpty(stringClaim(claims, m.cfg.SAMLNameAttribute), stringClaim(claims, "name"), email)
	return m.identityFromClaims(claims)
}

func withinSAMLWindow(notBefore, notAfter string, now time.Time, skew time.Duration) bool {
	if notBefore != "" {
		value, err := time.Parse(time.RFC3339Nano, notBefore)
		if err != nil || now.Add(skew).Before(value) {
			return false
		}
	}
	return beforeSAMLExpiry(notAfter, now, skew)
}

func beforeSAMLExpiry(value string, now time.Time, skew time.Duration) bool {
	if value == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && now.Add(-skew).Before(expires)
}

func joinQuery(raw, query string) string {
	if strings.Contains(raw, "?") {
		return "&" + query
	}
	return "?" + query
}

func constantText(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var value byte
	for index := range a {
		value |= a[index] ^ b[index]
	}
	return value == 0
}

func truncateMessage(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
