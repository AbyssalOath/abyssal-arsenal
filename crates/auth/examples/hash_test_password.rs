fn main() {
    let hash = abyssal_auth::password::hash_password("TestPassw0rd!2345").unwrap();
    println!("{hash}");
}
