# GoKuvera
GoKuvera simplifies the implementation of the Kuvera Payment Gateway on the client side using Go.

Overview
--------
This client provides following easy to implement functionality
- Create payment
- Check payment
- Cancel payment
- Callback validation

To install use

```markdown
    go get github.com/PT-Bima-Sakti-Alterra/GoKuvera
```

Description
-----------

Create instance of `GoKuvera` by passing 
```go
    baseURL := "https://kuvera-api-dev.bsa.id"
	clientSecret := "8977b626-a85f-4ec9-be94-830e8e8e0c0e"
	clientID := "ebef955a-43ad-4b8c-8384-68637ebac8e0"
	callbackURL := "https://kuvera-api-dev.bsa.id/callback/"
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

    gk := gokuvera.New(baseURL, clientSecret, clientID, partnerID, callbackURL, privateKey, publicKey)
    
```

#### Create Payment
```go
    data, err = gk.CreatePayment(&gokuvera.Transaction{
		Channel:               gokuvera.BNIChannel,
		Method:                gokuvera.BankVAMethod,
		MerchantNoTransaction: "xxx",
		Amount:                10000,
		Name:                  "test bni va",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)
```

#### Check Payment
```go
    data, err = gk.CheckPayment("b15fd079-bd45-4075-8e2e-f636b9be5aaf")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)
```

#### Cancel Payment
```go
    data, err = gk.CancelPayment("b15fd079-bd45-4075-8e2e-f636b9be5aaf")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(data)
```

#### Callback Validation
```go
	timestamp := "2023-05-11T03:58:46.937Z"
	signature := "23d23d26cd1e6017f3d66879e5dca85860f283b26b98778ba5dc92a9501700236de3ee27a7056ae804be517e0814bc3ded87088c49d9604d6bad92aa0694f1cd70d19ccc6ec0b667c25d1dd424940d4ee50c143bb4f75a4c9bb6b4352f7e0f70d0e23cb857feab70c1f048668df20fbebac2b2592c864495ac2b6e3dc8e745a2"
	requestBody := `{"payment_status":"paid","transaction_id":"32b663af-2a9a-4fcc-87eb-30a266662eb4","payment_method":"bank_transfer","merchant_no_transaction":"1112","payment_channel":"bca","callback_url":"www.yourdomain.com/webhook","name":"kartika sari","description":"","amount":1980,"channel":{"bca":{"account":"0613005878"}},"created_at":"2023-02-09T03:32:56.3680344Z","updated_at":"2023-02-09T03:32:56.3680344Z","expired_at":"2023-12-12T15:04:05Z"}`

    err = gk.CallbackValidation(timestamp, signature, requestBody)
	if err != nil {
		log.Fatal(err)
	}
```

```go
package main

import (
	"gokuvera"
	"io"

	"github.com/gin-gonic/gin"
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

	gk := gokuvera.New(baseURL, clientSecret, clientID, partnerID, callbackURL, privateKey, publicKey)

	app := gin.Default()

	app.GET("/webhook", func(c *gin.Context) {
		timestamp := c.Request.Header.Get("TIMESTAMP")
		signature := c.Request.Header.Get("SIGNATURE")
		requestBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
		}

		err = gk.CallbackValidation(timestamp, signature, requestBody)
		if err != nil {
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
		}

		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	app.Run(":8080")
}
```

```go
package main

import (
	"gokuvera"

	"github.com/gofiber/fiber/v2"
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

	gk := gokuvera.New(baseURL, clientSecret, clientID, partnerID, callbackURL, privateKey, publicKey)

	app := fiber.New()

	app.Get("/webhook", func(c *fiber.Ctx) error {
		timestamp := c.Get("TIMESTAMP")
		signature := c.Get("SIGNATURE")
		requestBody := c.Body()

		err := gk.CallbackValidation(timestamp, signature, requestBody)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{
				"message": err.Error(),
			})
		}

		return c.Status(fiber.StatusOK).JSON(&fiber.Map{
			"message": "ok",
		})
	})

	app.Listen(":3000")
}
```

License
-------
Apache License, Version 2.0