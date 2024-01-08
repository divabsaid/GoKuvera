package gokuvera

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var once sync.Once

type singleAccessToken struct {
	token     string
	expiresIn time.Time
}

var singleAccessTokenInstance *singleAccessToken

type Kuvera interface {
	CreatePayment(transaction *Transaction) (map[string]interface{}, error)
	CheckPayment(transactionID string) (map[string]interface{}, error)
	CancelPayment(transactionID string) (map[string]interface{}, error)
	CallbackValidation(timestamp, signature string, requestBody []byte) error
}

type kuvera struct {
	baseURL      string
	clientSecret string
	clientID     string
	partnerID    string
	callbackURL  string
	channelID    string
	origin       string

	clientPrivateKey []byte
	clientPublicKey  []byte
	serverPublicKey  []byte
}

type Transaction struct {
	Channel               string
	Method                string
	MerchantNoTransaction string
	Amount                float64
	Name                  string
}

func New(baseURL, clientSecret, clientID, partnerID, callbackURL string, clientPrivateKey, clientPublicKey, serverPublicKey []byte) Kuvera {
	interfaces, _ := net.Interfaces()

	var macAddress string
	for _, i := range interfaces {
		macAddress = i.HardwareAddr.String()
		if macAddress != "" {
			break
		}
	}

	hasher := md5.New()
	hasher.Write([]byte(macAddress))
	hashBytes := hasher.Sum(nil)

	hashDecimal := new(big.Int).SetBytes(hashBytes)
	hashDecimal.Mod(hashDecimal, big.NewInt(100000))

	parsedCallbackURL, _ := url.Parse(callbackURL)

	return &kuvera{
		baseURL:      baseURL,
		clientSecret: clientSecret,
		clientID:     clientID,
		partnerID:    partnerID,
		callbackURL:  callbackURL,
		channelID:    hashDecimal.String(),
		origin:       parsedCallbackURL.Host,

		clientPrivateKey: clientPrivateKey,
		clientPublicKey:  clientPublicKey,
		serverPublicKey:  serverPublicKey,
	}
}

func (kvr *kuvera) CreatePayment(transaction *Transaction) (map[string]interface{}, error) {
	single, err := getAccessTokenInstance(kvr.baseURL, kvr.clientID, kvr.clientPrivateKey)
	if err != nil {
		return nil, err
	}

	accessToken := single.token

	relativeURL := "/api/v1/payments/create"

	data := map[string]interface{}{
		"payment_channel":         transaction.Channel,
		"payment_method":          transaction.Method,
		"merchant_no_transaction": transaction.MerchantNoTransaction,
		"amount":                  transaction.Amount,
		"name":                    transaction.Name,
		"redirect_app":            "-",
	}

	resBody, err := doTransactionMethodPostRequest(kvr.baseURL, relativeURL, accessToken, kvr.origin, kvr.partnerID, kvr.channelID, []byte(kvr.clientSecret), data)
	if err != nil {
		return nil, err
	}

	return resBody["data"].(map[string]interface{}), nil
}

func (kvr *kuvera) CheckPayment(transactionID string) (map[string]interface{}, error) {
	single, err := getAccessTokenInstance(kvr.baseURL, kvr.clientID, kvr.clientPrivateKey)
	if err != nil {
		return nil, err
	}

	accessToken := single.token

	relativeURL := "/api/v1/payments/status"

	data := map[string]interface{}{
		"transaction_id": transactionID,
	}

	resBody, err := doTransactionMethodPostRequest(kvr.baseURL, relativeURL, accessToken, kvr.origin, kvr.partnerID, kvr.channelID, []byte(kvr.clientSecret), data)
	if err != nil {
		return nil, err
	}

	return resBody["data"].(map[string]interface{}), nil
}

func (kvr *kuvera) CancelPayment(transactionID string) (map[string]interface{}, error) {
	single, err := getAccessTokenInstance(kvr.baseURL, kvr.clientID, kvr.clientPrivateKey)
	if err != nil {
		return nil, err
	}

	accessToken := single.token

	relativeURL := "/api/v1/payments/invalidate"

	data := map[string]interface{}{
		"transaction_id": transactionID,
	}

	resBody, err := doTransactionMethodPostRequest(kvr.baseURL, relativeURL, accessToken, kvr.origin, kvr.partnerID, kvr.partnerID, []byte(kvr.clientSecret), data)
	if err != nil {
		return nil, err
	}

	return resBody["data"].(map[string]interface{}), nil
}

func (kvr *kuvera) CallbackValidation(timestamp, signature string, requestBody []byte) error {
	publicKey, err := parsePublicKey(kvr.serverPublicKey)
	if err != nil {
		return err
	}

	stringToSignHashSum, err := hashSHA256(requestBody)
	if err != nil {
		return err
	}

	requestBodyHash := strings.ToLower(hex.EncodeToString(stringToSignHashSum))

	stringToSign := fmt.Sprintf("%s:%s:%s:%s", http.MethodPost, "localhost/webhook", requestBodyHash, timestamp)

	stringToSignHashSum, err = hashSHA256([]byte(stringToSign))
	if err != nil {
		return err
	}

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, stringToSignHashSum, signatureBytes)
	if err != nil {
		return err
	}

	return nil
}

func getAccessTokenInstance(baseURL, clientID string, privateKey []byte) (*singleAccessToken, error) {
	var err error
	now := time.Now().UTC()

	if singleAccessTokenInstance == nil || now.After(singleAccessTokenInstance.expiresIn) {
		once.Do(
			func() {
				reqBody := url.Values{}
				reqBody.Set("grant_type", "client_credentials")

				timestamp := getTimestamp()

				fullURL := fmt.Sprintf("%s/api/v1/access-token", baseURL)

				block, _ := pem.Decode(privateKey)
				if block == nil {
					err = errors.New("failed to parse public key")
					return
				}

				rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return
				}

				stringToSign := fmt.Sprintf("%s|%s", clientID, timestamp)
				stringToSignHashSum, err := hashSHA256([]byte(stringToSign))
				if err != nil {
					return
				}

				signatureByte, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, stringToSignHashSum)
				if err != nil {
					return
				}

				signatureStr := hex.EncodeToString(signatureByte)

				headers := map[string]string{
					"X-TIMESTAMP":  timestamp,
					"X-CLIENT-KEY": clientID,
					"X-SIGNATURE":  signatureStr,
					"Content-Type": "application/x-www-form-urlencoded",
				}

				resBody, err := doRequest(http.MethodPost, fullURL, strings.NewReader(reqBody.Encode()), headers, nil)
				if err != nil {
					return
				}

				accessToken := resBody["data"].(map[string]interface{})["access_token"].(string)
				expiresIn := resBody["data"].(map[string]interface{})["expires_in"].(float64)

				singleAccessTokenInstance = &singleAccessToken{
					token:     accessToken,
					expiresIn: now.Add(time.Second * time.Duration(expiresIn-60)),
				}
			})
	}

	return singleAccessTokenInstance, err
}

func getTimestamp() string {
	timestamp := time.Now().UTC()
	return time.Date(timestamp.Year(), timestamp.Month(), timestamp.Day(), timestamp.Hour(), timestamp.Minute(), timestamp.Second(), timestamp.Nanosecond(), timestamp.Location()).Format("2006-01-02T15:04:05.000Z")
}

func hashSHA256(value []byte) ([]byte, error) {
	s := sha256.New()
	_, err := s.Write(value)
	if err != nil {
		return nil, err
	}
	return s.Sum(nil), nil
}

func hashHMACSHA512(value, key []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(value)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func marshalJSONCompact(value interface{}) ([]byte, error) {
	src, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	dst := &bytes.Buffer{}
	err = json.Compact(dst, src)
	if err != nil {
		return nil, err
	}

	return dst.Bytes(), nil
}

func prepareTransactionSignature(relativeURL, accessToken, timestamp string, clientSecret, reqBody []byte) (string, error) {
	stringToSignHashSum, err := hashSHA256(reqBody)
	if err != nil {
		return "", err
	}

	requestBodyHash := strings.ToLower(hex.EncodeToString(stringToSignHashSum))

	stringToSign := fmt.Sprintf("%s:%s:%s:%s:%s", http.MethodPost, relativeURL, accessToken, requestBodyHash, timestamp)

	signatureByte, err := hashHMACSHA512([]byte(stringToSign), clientSecret)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signatureByte), nil
}

func doRequest(method, url string, body io.Reader, headers map[string]string, queries map[string]string) (map[string]interface{}, error) {
	var client = &http.Client{}
	var resBody map[string]interface{}
	var err error

	req, _ := http.NewRequest(method, url, body)
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	if queries != nil {
		query := req.URL.Query()
		for key, value := range queries {
			query.Add(key, value)
		}
		req.URL.RawQuery = query.Encode()
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&resBody)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		if resBody["response_message"] != nil {
			return nil, fmt.Errorf("%v", resBody["response_message"])
		}
		return nil, errors.New("something wrong")
	}

	return resBody, nil
}

func doTransactionMethodPostRequest(baseURL, relativeURL, accessToken, origin, partnerID, channelID string, clientSecret []byte, data interface{}) (map[string]interface{}, error) {
	timestamp := getTimestamp()

	fullURL := fmt.Sprintf("%s%s", baseURL, relativeURL)

	reqBody, err := marshalJSONCompact(data)
	if err != nil {
		return nil, err
	}

	signature, err := prepareTransactionSignature(relativeURL, accessToken, timestamp, clientSecret, reqBody)
	if err != nil {
		return nil, err
	}

	externalID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
		"Content-Type":  "application/json",
		"X-TIMESTAMP":   timestamp,
		"X-SIGNATURE":   signature,
		"ORIGIN":        origin,
		"X-PARTNER-ID":  partnerID,
		"X-EXTERNAL-ID": externalID.String(),
		"CHANNEL-ID":    channelID,
	}

	resBody, err := doRequest(http.MethodPost, fullURL, bytes.NewReader(reqBody), headers, nil)
	if err != nil {
		return nil, err
	}

	return resBody, nil
}

func parsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("failed to parse public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
}
