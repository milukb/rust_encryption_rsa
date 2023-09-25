extern crate openssl;

use openssl::pkey::Private;
use openssl::rsa::{Rsa, Padding};
use openssl::sha::Sha256;
use std::collections::HashMap;
use std::io::{self, Write};




fn main() {
    let mut password_map: HashMap<String, String> = HashMap::new();
    let mut hashvalue_map: HashMap<String, String> = HashMap::new();
    let rsa = Rsa::generate(2048).unwrap();

    loop {
        println!("\n *************************************");
        println!("\n Enter your choice");
        println!("\n 1. Save");
        println!("\n 2. Retrieve");
        println!("\n 3. Exit");

        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                println!("\n Enter your name");
                io::stdout().flush().unwrap();
                let mut name = String::new();
                io::stdin().read_line(&mut name).unwrap();
                let  name = name.trim().to_string();
                let secondname=name.clone();
                println!("\n Enter your account number");
                io::stdout().flush().unwrap();
                let mut accno = String::new();
                io::stdin().read_line(&mut accno).unwrap();

                 let encrypted_password = encrypt(&accno, &rsa);
                 let encrypted_temp = encrypted_password.clone();
                 password_map.insert(name, encrypted_password);
                
                  let hash_string=hashing(&encrypted_temp);
                 
                  hashvalue_map.insert(secondname, hash_string);
            }
            "2" => {
                print!("\nEnter your name: ");
                io::stdout().flush().unwrap();
                let mut name = String::new();
                io::stdin().read_line(&mut name).unwrap();
                let name = name.trim().to_string();
                //hashcheck
                if let Some(encrypted_password) = password_map.get(&name) {
                    if let Some(hash_string) = hashvalue_map.get(&name) {
                        let temp = hashing(encrypted_password);
                        if(hash_string== &temp){
                            let decrypted_account_number = decrypt(&encrypted_password, &rsa);
                                println!("Decrypted Account Number: {}", decrypted_account_number);
                                println!("Hash value maches Successfully");
                                println!("The Hash is:{}",temp);
                        }else{
                            println!("Wrong Hash value, data is tampered");
                            println!("hash string : {}",hash_string);
                            println!("temp string : {}",temp);
                        }
                    //  println!("hash: {}", hash_string);
                    } else {
                    println!("No hash saved associated with the name");
                }}else {
                    println!("No password saved for {}", name);
                }               
            }
            "3" => break,
            _ => println!("Invalid choice"),
        }
    }
}

fn encrypt(accno: &str, rsa: &Rsa<Private>) -> String {
    let mut enc_data = vec![0; rsa.size() as usize];
    let len = rsa.public_encrypt(accno.as_bytes(), &mut enc_data, Padding::PKCS1).unwrap();
    enc_data.truncate(len);
    // let len = rsa.public_encrypt(&sha256(accno.as_bytes()), &mut enc_data, Padding::PKCS1).unwrap();  
    let encrypted_password = base64::encode(&enc_data);

    encrypted_password
}

fn decrypt(encrypted_password: &str, rsa: &Rsa<Private>) -> String {
    let encrypted_password_bytes = base64::decode(encrypted_password).unwrap();
    let mut decrypted_data_buf = vec![0; rsa.size() as usize];
    let decrypted_data = rsa.private_decrypt(&encrypted_password_bytes, &mut decrypted_data_buf, Padding::PKCS1).unwrap();
    decrypted_data_buf.truncate(decrypted_data);
    String::from_utf8_lossy(&decrypted_data_buf).to_string()
}
fn hashing(accno: &str)-> String{
  //  println!("string:{}", accno);
    let input_bytes=accno.as_bytes();
    let mut context=Sha256::new();
    context.update(input_bytes);
    let result=context.finish();

    let hash_hex=result.iter().map(|byte| format!("{:02x}",byte)).collect::<String>();
    hash_hex
    // println!("sha:{}", hash_hex);
}
