package main

import (
	"gokuvera"
	"log"
)

func main() {
	baseURL := "https://kuvera-api-dev.bsa.id"
	clientSecret := "8977b626-a85f-4ec9-be94-830e8e8e0c0e"
	clientID := "ebef955a-43ad-4b8c-8384-68637ebac8e0"
	callbackURL := "www.yourdomain.com/webhook/"
	partnerID := "PlkyeIvJ"
	privateKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
...
...
...
-----END RSA PRIVATE KEY-----`)
	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
...
...
...
-----END PUBLIC KEY-----`)

	var data map[string]interface{}
	var err error

	gk := gokuvera.New(baseURL, clientSecret, clientID, partnerID, callbackURL, privateKey, publicKey)

	data, err = gk.CreatePayment(&gokuvera.Transaction{
		Channel:               gokuvera.BCAChannel,
		Method:                gokuvera.BankTransferMethod,
		MerchantNoTransaction: "xxx",
		Amount:                10000,
		Name:                  "test bca transfer",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)

	data, err = gk.CheckPayment("b15fd079-bd45-4075-8e2e-f636b9be5aaf")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)

	data, err = gk.CancelPayment("b15fd079-bd45-4075-8e2e-f636b9be5aaf")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)

	timestamp := "2023-05-11T03:58:46.937Z"
	signature := "23d23d26cd1e6017f3d66879e5dca85860f283b26b98778ba5dc92a9501700236de3ee27a7056ae804be517e0814bc3ded87088c49d9604d6bad92aa0694f1cd70d19ccc6ec0b667c25d1dd424940d4ee50c143bb4f75a4c9bb6b4352f7e0f70d0e23cb857feab70c1f048668df20fbebac2b2592c864495ac2b6e3dc8e745a2"
	requestBody := `{"payment_status":"paid","transaction_id":"32b663af-2a9a-4fcc-87eb-30a266662eb4","payment_method":"bank_transfer","merchant_no_transaction":"1112","payment_channel":"bca","callback_url":"www.yourdomain.com/webhook","name":"kartika sari","description":"","amount":1980,"channel":{"bca":{"account":"0613005878"}},"created_at":"2023-02-09T03:32:56.3680344Z","updated_at":"2023-02-09T03:32:56.3680344Z","expired_at":"2023-12-12T15:04:05Z"}`
	err = gk.CallbackValidation(timestamp, signature, requestBody)
	if err != nil {
		log.Fatal(err)
	}
}
