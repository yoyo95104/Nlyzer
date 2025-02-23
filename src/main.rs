use std;
use lib::{scan};

mod lib;

#[tokio::main]
async fn main() {
    scan().await;
}
