# compute-hcaptcha

## Backends
2 backends are used.

1. https://httpbin.org for the HTTP post submission
2. https://hcaptcha.com for the hcaptcha captcha validation

Documentation for the hcaptcha captcha may be found at https://docs.hcaptcha.com/

## Requirements

* hcaptcha key
* setup backends
* Dictionary for credentials
* You need the ability to prove you are not a robot (or you are a robot that can solve captchas) ;-)

## Setup
Create a dictionary for the hcaptcha credentials. The dictionary will be write-only so that the credential may NOT be read from the UI or the API. Only the VCL or C@E program will be able to read from the dictionary.

`fastly dictionary create --name='credentials' --write-only=true --autoclone --version=latest`

Obtain the ID of the dictionary that you just created.

`fastly dictionary list --version=latest`

Add the hcaptcha credentials to the dictionary.

`fastly dictionary item create --dictionary-id='YOUR-DICTIONARY-ID-HERE' --key='hcaptcha-key' --value='YOUR-SECRET-HCAPTCHA-KEY'`

Generate an AES key and IV (initialization vector). For information on what an AES and IV are see wikipedia, https://en.wikipedia.org/wiki/Initialization_vector.

`openssl enc -aes-256-cbc -k secret -P -md sha512 -pbkdf2`

Add the AES key and IV to the dictionary.

```
fastly dictionaryitem create --dictionary-id='YOUR-DICTIONARY-ID-HERE' --key='hcaptcha-encryption-key' --value='YOUR-SECRET-HCAPTCHA-ENCRYPTION-KEY'
fastly dictionaryitem create --dictionary-id='YOUR-DICTIONARY-ID-HERE' --key='hcaptcha-encryption-iv' --value='YOUR-SECRET-HCAPTCHA-ENCRYPTION-IV'
```

## How does it work?

See the request flow here as a reference, https://docs.hcaptcha.com/#request-flow. Within this workflow, "Your Server" is Fastly C@E.

When the C@E integration receives a 435 response code from the origin, the C@E will return a captcha page instead of the origin response. When the user clicks submit after solving the captcha, the

1. User does something to cause the origin to return a 435 status code.
2. The C@E returns a captcha page back to the client instead of actual origin response.
3. The user completes the captcha and clicks submit.
4. The browser will send an HTTP POST to hcaptcha-verify.html with the hcaptcha validation information.
5. C@E will reach out to the HCaptcha API to validate the captcha information is correct.
6. C@E will encrypt the response information from the HCaptcha API using the AES key and IV.
7. C@E will return a 302 redirect response to the client with the redirect based on the referrer header of the client request and a set-cookie header containing the encrypted value of the HCaptcha API response.
8. Subsequent requests from the client to C@E should contain the encrypted cookie. The C@E will decrypt the cookie, parse the JSON, and add the header "fastly-hcaptcha-cookie-decrypted-success" with a value of "true" as long as the hcaptcha was solved properly.
9. The header key/value fastly-hcaptcha-cookie-decrypted-success:true may then be used for decision making by the origin that C@E is proxying to.

## TODOs
* When the captcha is submitted correctly, a cookie needs to be set clientside. The cookie should be encrypted with an AES256 key. Subsequent requests made to Fastly should have this cookie decrypted. The contents of this cookie should then be sent to the origin as a header. [Done]
* Build basic example where hcaptcha is part of a form submission.

