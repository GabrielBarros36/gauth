use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use dotenv::dotenv;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
	sub: String,
	username: String,
    exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize,          // Optional. Issued at (as UTC timestamp)
}



//DELETE LATER
fn main() {
	dotenv().ok();
	let key = std::env::var("JWT_SECRET");

}