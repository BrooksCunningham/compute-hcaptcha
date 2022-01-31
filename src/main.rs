//! Default Compute@Edge template program.

use fastly::http::{header, StatusCode, HeaderValue};
use fastly::{mime, Error, Request, Response, Dictionary};

use lol_html::html_content::ContentType;
use lol_html::{element, rewrite_str, RewriteStrSettings};

use cookie::{Cookie, CookieJar};

use serde_json;

// takes a string and returns the encrypted string value
// input should be plaintext_string: &str
use aes::Aes256;
use aes::cipher::{generic_array::GenericArray};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
// use hex_literal;
use hex::FromHex;
use std::str;

// create an alias for convenience
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
// const BACKEND_NAME: &str = "primary";

/// The name of a second backend associated with this service.
// const BACKEND_HTTPBIN: &str = "httpbin";

// HTTPBIN backend
const BACKEND_HTTPBIN: &str = "httpbin.org";

// BACKEND_HCAPTCHAAPI
const BACKEND_HCAPTCHAAPI: &str = "hcaptchaapi";

// https://docs.hcaptcha.com/
const HCAPTCHA_VERIFY_URL: &str = "https://hcaptcha.com/siteverify";

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Make any desired changes to the client request.
    req.set_header(header::HOST, "github.webbots.page");

    // Pattern match on the path.
    match req.get_path() {
        "/hcaptcha.html" => {
            let page_html = include_str!("hcaptcha.html");
            return Ok(Response::from_status(StatusCode::OK)
                .with_content_type(mime::TEXT_HTML_UTF_8)
                .with_body(page_html));
        }
        path if path.starts_with("/hcaptcha-verify.html") => {
            // https://developer.fastly.com/solutions/examples/add-or-remove-cookies
            req = get_hcaptcha_cookie_value_and_set_header(req);

            let req_referer = req.get_header_str("referer");
            if req_referer.is_none() {
                return Ok(Response::from_status(StatusCode::FOUND)
                .with_header("location", "/"));    
            }

            // Use the tuple from the hcaptcha response later
            let (req, hcaptcha_json)  = hcaptcha_enrichment(req);

            // Encrypt the JSON from hcaptcha and set the value as the cookie on the response back to the client.
            let hcaptcha_encrypted_cookie = encrypt_string(&hcaptcha_json.to_string());

            return Ok(Response::from_status(StatusCode::FOUND)
                .with_header("location", req.get_header_str("referer").unwrap())
                .with_header("set-cookie", format!("cookie_monster={}", &hcaptcha_encrypted_cookie))
            );
        }
        // Catch all other requests and send to the origin.
        _ => {
            // Never cache the request or response for this workflow.
            req.set_pass(true);
            req = get_hcaptcha_cookie_value_and_set_header(req);

            let hcaptcha_cookie_decrypted_success = req.get_header("fastly-hcaptcha-cookie-decrypted-success");

            if hcaptcha_cookie_decrypted_success.is_none(){
                println!("is none");
            } else {
                println!("value for decr");
            }

            // Check origin status
            let origin_resp = req.send(BACKEND_HTTPBIN)?;

            // if the origin response status is 435 the return the captcha page.
            println!("origin_resp.get_status() {:?}", origin_resp.get_status());
            if origin_resp.get_status() == 435 {
                let page_html = include_str!("hcaptcha.html");
                return Ok(Response::from_status(429)
                    .with_content_type(mime::TEXT_HTML_UTF_8)
                    .with_body(page_html));
            }
            
            // Ok(req.send(BACKEND_HTTPBIN)?)
            Ok(origin_resp)
        }
    }
}

// https://developer.fastly.com/solutions/examples/add-or-remove-cookies
fn get_hcaptcha_cookie_value_and_set_header(mut req: Request) -> Request {
    if let Some(req_cookie_jar) = req
    .get_header(header::COOKIE)
    .and_then(|h| parse_cookies_to_jar(h).ok()) 
    {   
        println!("req_cookie_jar: {:?}", 
            req_cookie_jar
                .get("cookie_monster")
                .map(|c| c.value())
                .unwrap_or_default()
        );
        if req_cookie_jar
          .get("cookie_monster")
          .map(|c| c.value())
          .unwrap_or_default().len() > 10 {
                      // return the decrypted string
            let hcaptcha_decrypted_cookie = decrypt_string(
                req_cookie_jar
                .get("cookie_monster")
                .map(|c| c.value())
                .unwrap_or_default()
            );
            req.set_header("fastly-hcaptcha-cookie-decrypted", &hcaptcha_decrypted_cookie);
            let hcaptcha_decrypted_cookie_json: serde_json::Value = serde_json::from_str(&hcaptcha_decrypted_cookie).unwrap();

            println!("hcaptcha_decrypted_cookie_json {:?}", hcaptcha_decrypted_cookie_json);
            req.set_header("fastly-hcaptcha-cookie-decrypted-success", hcaptcha_decrypted_cookie_json["success"].to_string());

        } else {
            println!("Cookies are present, but cookie_monster is missing or less than 10 len()");
        }
    } else {
        println!("cookies are missing.")
    }
    return req;
}


fn encrypt_string(plaintext: &str) -> String {
    let credentials_dictionary: Dictionary = Dictionary::open("credentials");
    let hcaptcha_encryption_key_unwrap: String = credentials_dictionary.get("hcaptcha-encryption-key").unwrap().to_string();
    let hcaptcha_encryption_key: [u8; 32] = <[u8; 32]>::from_hex(&hcaptcha_encryption_key_unwrap).expect("Decoding failed");

    let hcaptcha_encryption_iv_unwrap: String = credentials_dictionary.get("hcaptcha-encryption-iv").unwrap().to_string();
    let hcaptcha_encryption_iv: [u8; 16] = <[u8; 16]>::from_hex(&hcaptcha_encryption_iv_unwrap).expect("Decoding failed");

    // creater cipher
    let cipher = Aes256Cbc::new_from_slices(&hcaptcha_encryption_key, &hcaptcha_encryption_iv).unwrap();

    // buffer could be a variable based on length
    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 1024];

    // copy message to the buffer
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext.as_bytes());
    let ciphertext_vec = cipher.encrypt(&mut buffer, pos).unwrap();

    let ciphertext = hex::encode(&ciphertext_vec);  

    return ciphertext.to_string();

}

fn decrypt_string(ciphertext: &str) -> String {
    let credentials_dictionary: Dictionary = Dictionary::open("credentials");
    let hcaptcha_encryption_key_unwrap: String = credentials_dictionary.get("hcaptcha-encryption-key").unwrap().to_string();
    let hcaptcha_encryption_key: [u8; 32] = <[u8; 32]>::from_hex(&hcaptcha_encryption_key_unwrap).expect("Decoding failed");

    let hcaptcha_encryption_iv_unwrap: String = credentials_dictionary.get("hcaptcha-encryption-iv").unwrap().to_string();
    let hcaptcha_encryption_iv: [u8; 16] = <[u8; 16]>::from_hex(&hcaptcha_encryption_iv_unwrap).expect("Decoding failed");

    //hex encode the ciphertext
    let mut ciphertext_unwrapped = hex::decode(&ciphertext).unwrap();

    // println!("hcaptcha_encryption_key_unwrap {}", &hcaptcha_encryption_key_unwrap);
    // println!("hcaptcha_encryption_iv_unwrap {}", &hcaptcha_encryption_iv_unwrap);

    // get hex into vex
    let cipher = Aes256Cbc::new_from_slices(&hcaptcha_encryption_key, &hcaptcha_encryption_iv).unwrap();

    // do decryption
    let decrypted_ciphertext_vec = cipher.decrypt(&mut ciphertext_unwrapped).unwrap();
    let decrypted_ciphertext = str::from_utf8(&decrypted_ciphertext_vec).unwrap();

    return decrypted_ciphertext.to_string();
}

// returns a tuple of request and the response JSON from hcaptcha
fn hcaptcha_enrichment(mut req: Request) -> (Request, serde_json::Value) {
    let credentials_dictionary = Dictionary::open("credentials");
    let hcaptcha_api_secret: String = credentials_dictionary.get("hcaptcha-key").unwrap();
    
    // Get body as a string from the request
    let body_string = req.take_body_str();

    let mut hcaptcha_resp_json: serde_json::Value = serde_json::json!("{}");

    // Get captcha response from h-captcha-response string
    match sub_field(&body_string, "h-captcha-response", "&") {
        Some("") | None => {
            // No h-captcha-response found or empty credential found
            println!("No h-captcha-response is found");
            req.set_header("fastly-hcaptcha-success-response", "no-response");
        }
        Some(hcaptcha_response) => {
            // println!("credentials_dictionary.get(h-captcha-key) hcaptcha_api_secret: {:}", hcaptcha_api_secret);
            // println!("hcaptcha_verify_data: {}", format!("response={}&secret={}", hcaptcha_response, hcaptcha_api_secret));
            
            // Used for Command ling debugging
            // println!("test curl");
            // println!("test with curl, curl https:/hcaptcha.com/siteverify -X POST -H 'content-type:application/x-www-form-urlencoded' -d '{}'", hcaptcha_verify_data);

            // Calculate the content length to avoid sending a chunked request
            let hcaptcha_verify_data = format!("response={}&secret={}", hcaptcha_response, hcaptcha_api_secret);
            let hcaptcha_verify_data_length = hcaptcha_verify_data.to_string().len();

            let mut hcaptcha_resp = Request::post(HCAPTCHA_VERIFY_URL)
                .with_header("User-Agent", "fastly-rust")
                .with_header("Content-Type", "application/x-www-form-urlencoded")
                .with_header("Content-Length", hcaptcha_verify_data_length.to_string())
                .with_body(hcaptcha_verify_data)
                .send(BACKEND_HCAPTCHAAPI).unwrap();


            // let hcaptcha_resp_json = hcaptcha_resp.take_body_json().;

            hcaptcha_resp_json = hcaptcha_resp.take_body_json::<serde_json::Value>().unwrap();
            println!("hcaptcha_resp_json: {}", hcaptcha_resp_json);

            req.set_header("fastly-hcaptcha-success-response", hcaptcha_resp_json["success"].to_string());
            // req.set_header("fastly-hcaptcha-json-response", hcaptcha_resp_json.to_string());

        }
    }
    // Return the body string to the request before giving the request back to the main function
    req.set_body(body_string);

    return (req, hcaptcha_resp_json);
}

// Helper function to parse for form post fields
fn sub_field<'a>(content: &'a str, field_name: &str, separator_character: &str) -> Option<&'a str> {
    content
        .split(separator_character)
        .find_map(|sub_field| field_value(sub_field, field_name))
}

fn field_value<'a>(content: &'a str, field_name: &str) -> Option<&'a str> {
    let mut i = content.split('=');
    let name = i.next()?.trim();
    if name == field_name {
        let value = i.next()?.trim();
        Some(value)
    } else {
        None
    }
}

fn parse_cookies_to_jar(value: &HeaderValue) -> Result<CookieJar, Error> {
    let mut jar = CookieJar::new();
    for cookie in value.to_str()?.split(';').map(Cookie::parse_encoded) {
        jar.add_original(cookie?.into_owned());
    }
    Ok(jar)
}