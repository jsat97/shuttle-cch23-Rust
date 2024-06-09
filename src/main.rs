use actix_web::{error, get, post, web, Result, web::ServiceConfig};

use shuttle_actix_web::ShuttleActixWeb;
use derive_more::{Display, Error};
use tracing::info;
use serde::{Serialize, Deserialize};
use actix_web::HttpResponse;
use futures::StreamExt;
use actix_web::Responder;
use actix_web::HttpRequest;
use base64::{Engine as _, engine::general_purpose};
use serde_json::{Map, Value, json};
// day 11
use actix_files as fs;
use actix_web::http::header::{ContentType, ContentDisposition, DispositionType};
use mime;
use actix_multipart::Multipart;
//use futures_util::StreamExt as _;
// day 12
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::collections::HashMap;
//use ulid:: serde::ulid_as_uuid;
use ulid::Ulid;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use chrono::{Datelike,naive::NaiveDate, Weekday};

// day 13
use sqlx::{Executor, FromRow, PgPool};
use shuttle_runtime::CustomError;
use std::sync::Arc;
use std::pin::Pin;
use std::ops::Deref;
use actix_web::http::StatusCode;

// day 14
use tinytemplate::TinyTemplate;

// day 15
use emojis;
use sha2::{Sha256, Digest};

// allow dead code
#[allow(dead_code)]
// allow unused variables
#[allow(unused_variables)]

#[get("/")]
async fn hello_world() -> &'static str {
    "Hello World !!"
}


#[derive(Debug, Display, Error)]
#[display(fmt = "my error: {}", name)]
struct MyError {
    name: &'static str,
}

// Use default implementation for `error_response()` method
//impl error::ResponseError for MyError {}

#[get("/-1/error")]

async fn send_internal_error() -> Result<String, actix_web::Error> {
    Err(error::ErrorInternalServerError(MyError { name: "test" }))
}

#[get("/1/{nums:.*}")]  
async fn index_multi(path: web::Path<String>) -> Result<String, actix_web::Error> {
    
    // Parse the path into individual segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    info!("segments: {:?}", segments);
    let mut val: u32 = segments.first().unwrap().parse().unwrap();
    info!("first val: {}", val);
    // iterate over vec skipping the first entry
    for seg in segments.clone().into_iter().skip(1) {
        let num :u32 = seg.parse().unwrap(); 
        val ^= num;
        info!("in loop: num: {} val {}", num, val); 
    }
    val = val.pow(3);
    Ok(format!("{}", val))
}
// day 18
// task 1

// moved up from Day 13 for common use between 13 and 18
#[derive(Serialize, Deserialize, FromRow, Debug)]
struct Order {
    id: i32,
    region_id: i32,
    gift_name: String,
    quantity: i32,
}
#[derive(Serialize, Deserialize, Debug, FromRow)]
struct Region {
    id: i32,
    name: String,
}
#[post("/18/reset")]
async fn worldwide_reset(db: actix_web::web::Data<sqlx::PgPool>) -> HttpResponse {
    
    info!("db: {:?}", db);
    let _ =
    sqlx::query_as::<_,Order>(
        r#"
        DROP TABLE IF EXISTS orders;
        "#,
        )
        .fetch_one(db.get_ref())
        .await;

    let _ =
    sqlx::query_as::<_,Region>(
        r#"
        DROP TABLE IF EXISTS regions;
        "#,
        )
        .fetch_one(db.get_ref())
        .await;

    let _ =
        sqlx::query_as::<_,Region>(
        r#"
        CREATE TABLE regions (
        id INT PRIMARY KEY,
        name VARCHAR(50)
        );
        "#,
        )
        .fetch_one(db.get_ref())
        .await;

    let _ =
        sqlx::query_as::<_,Order>(
        r#"
        CREATE TABLE orders (
            id INT PRIMARY KEY,
            region_id INT,
            gift_name VARCHAR(50),
            quantity INT);
            "#,
        )
        .fetch_one(db.get_ref())
        .await;
    HttpResponse::Ok().finish() 
}

#[post("/18/orders")]
async fn worldwide_order(db: actix_web::web::Data<sqlx::PgPool>, ords: web::Json<Vec<Order>>) -> HttpResponse {
    // iterate the orders and insert them into the database
    for ord in ords.iter() {
        info!("order: {:?}", ord);
        let _ =    sqlx::query_as::<_,Order>(
            // insert into orders and accumulate each order if same order is inserted multiple times
            r#"
            INSERT INTO orders (id, region_id, gift_name, quantity) VALUES ($1, $2, $3, $4)
            "#, 
            ) 
            .bind(ord.id)
            .bind(ord.region_id)
            .bind(&ord.gift_name)
            .bind(ord.quantity)
            .fetch_one(db.get_ref())
            .await;
        }

    HttpResponse::Ok().finish() 
}

#[post("/18/regions")]
async fn worldwide_regions(db: actix_web::web::Data<sqlx::PgPool>, regs: web::Json<Vec<Region>>) -> HttpResponse {
    // iterate the orders and insert them into the database
    for reg in regs.iter() {
        info!("region: {:?}", reg);
        let _ =    sqlx::query_as::<_,Region>(
            r#"
            INSERT INTO regions (id, name) VALUES ($1, $2)
            "#, 
            ) 
            .bind(reg.id)
            .bind(&reg.name)
            .fetch_one(db.get_ref())
            .await;
        }

    HttpResponse::Ok().finish() 
}

#[derive(Serialize, Deserialize, Debug, FromRow)]
struct TotalRegion {
    region: String,
    #[serde(rename = "total")]
    total_reg: i64
}

#[get("/18/regions/total")]
async fn worldwide_total(db: actix_web::web::Data<sqlx::PgPool>) -> impl Responder {
    
    // get the total # of orders per region from the orders and regions table
    // the output should be a json object with the region name as the key and the total # of orders as the value
    // sort alphabetically by region name
    // rename the regions.id to "region" and each region total to "total"
    let total_orders_reg : Result<Vec<(String, i64)>, sqlx::Error> =
        sqlx::query_as::<_,(String, i64)>(
            r#"
            SELECT regions.name as region, SUM(orders.quantity) as total FROM orders 
            INNER JOIN regions
            ON orders.region_id = regions.id
            GROUP BY regions.name
            ORDER BY regions.name
            "#
        )
        .fetch_all(db.get_ref())
        .await;

    let total_orders_reg_json: Vec<web::Json<TotalRegion>> = 
        total_orders_reg
        .unwrap()
        .into_iter()
        .map(|tot| web::Json(TotalRegion{region: tot.0, total_reg: tot.1}))
        .collect();
    info!("total_orders_reg_json: {:?}", total_orders_reg_json);
    // return a json object with the region name as the key and the total # of orders as the value
    HttpResponse::Ok().json(total_orders_reg_json)
    
}

#[derive(Serialize, Deserialize, Debug, FromRow)]
struct TotalRegionTop {
    region: String,
    top_gifts: Vec<String>,
}

#[get("/18/regions/top_list/{number}")]
async fn top_list(path: web::Path<String>, db: actix_web::web::Data<sqlx::PgPool>) -> impl Responder {
    let number:i32 = path.parse().unwrap();
    // get an array of the sum of quantities for each gift type per region from the orders and regions table
    // ordered by the sum of quantities in descending order and alphabetically by gift name when
    // the sum of quantities is the same. the array should contain {number} values. 
    // the regions must be ordered alphabetically.
    // rename the regions.id to "region" and each region total to "total"
    let top_list : Result<Vec<(String,Vec<String>)>, sqlx::Error> =
        sqlx::query_as::<_,(String,Vec<String>)>(
            r#"
            WITH region_gift_totals AS (
                SELECT
                regions.name as rn,
                orders.gift_name as gn,
                SUM(orders.quantity) AS tq
            FROM regions
            LEFT JOIN
                orders ON regions.id = orders.region_id
            GROUP BY
            rn,
            gn
            )

        SELECT
            rn,
            ARRAY(
            SELECT COALESCE(gn, '')
            FROM region_gift_totals
            WHERE rn = rg.rn
            ORDER BY tq DESC, gn ASC
            LIMIT $1
        ) AS aggregated_gift_names

        FROM (
            SELECT rn
            FROM region_gift_totals
        )rg
        GROUP BY
        rn
        ORDER BY
        rn ASC;
        "#
        )
        .bind(number)
        .fetch_all(db.get_ref())
        .await;
    info!("top_list: {:?}", top_list);
    let top_orders_reg_json: Vec<web::Json<TotalRegionTop>> = 
        top_list
        .unwrap()
        .into_iter()
        .map(|tot| 
            if tot.1.is_empty() || tot.1[0].is_empty() {
               web::Json(TotalRegionTop{region: tot.0, top_gifts: vec![]})
            } else {
                web::Json(TotalRegionTop{region: tot.0, top_gifts: tot.1})
            }
        )
        .collect();
    info!("top_orders_reg_json: {:?}", top_orders_reg_json);
    HttpResponse::Ok().json(top_orders_reg_json)
}

// day 15
// task 1
#[derive(Debug, Serialize, Deserialize)]
struct Password {
    input: String,
}

#[post("/15/nice")]
// task 1
async fn nice(info: web::Json<Password>) -> impl Responder {
    
    // extract password from request
    // return error if deserialization fails
    let password = &info.input;
    info!("password: {}", password);
    // password is nice if -> (1) it contains at least 3 vowels (2) it contains at least 1 letter
    // that appears twice in a rows (3) doesnt contain the string 'ab' or 'cd' or 'pq' or 'xy'
    // return {"result": "nice"} for a nice password and {"result": "naughty"} for a naughty password
    let mut nice_pass: bool = false;
    if ! (password.contains("ab") || password.contains("cd") || password.contains("pq") || password.contains("xy") ) &&
        // must contain at least 3 vowels
        (password.matches(|c| c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u').count() >= 3 )
            &&
            // must contain at least 1 letter that appears twice in a row
            // get count of repeating consecutive letters in password
            // iterate only over letters (alphabets)
            password.chars().zip(password.chars().skip(1)).filter(|(c1, c2)| c1.is_alphabetic() && c2.is_alphabetic() && c1 == c2).count() >= 1 
    {
        nice_pass = true;
    }

    if nice_pass == true {
        (json!({"result": "nice"}).to_string(),
        StatusCode::OK)
    } else {
        // return the result but set the return status to 400
        (json!({"result": "naughty"}).to_string(), 
        StatusCode::BAD_REQUEST)

    }
}

// day 15
// task 2
#[post("/15/game")]
async fn game(info: web::Json<Password>) -> impl Responder {
    // extract password from request
    // return error if deserialization fails
    let password = &info.input;
    info!("password: {}", password);
    let mut reason = "";
    let mut nice_pass: bool = true;
    let mut status_code = 200;
    
    // 1. Rule 1: must be at least 8 characters long
    if password.len() < 8 {
       reason = "8 chars"; 
       status_code = 400;
       nice_pass = false;
    } 
    if nice_pass {
        // 2. Rule 2: must contain uppercase letters, lowercase letters, and digits
        if ! (password.chars().any(|c|  c.is_ascii_lowercase()) &&
            password.chars().any(|c| c.is_ascii_uppercase()) &&
            password.chars().any(|c| c.is_ascii_digit())) {
            reason = "more types of chars";
            status_code = 400;
            nice_pass = false;
        } 
    }

    if nice_pass {
        // 3. Rule 3: must contain at least 5 digits
        if password.chars().filter(|c| c.is_ascii_digit()).count() < 5 {
            reason = "55555";
            status_code = 400;
            nice_pass = false;
        } 
    }
    if nice_pass {
        // 4. Rule 4: all integers (sequences of consecutive digits) in the string must add up to 2023
        // extract each digit sequence as an integer
        let mut digit_sequences = Vec::new();
        let mut current_sequence = String::new();
        for c in password.chars() {
            if c.is_ascii_digit() {
                current_sequence.push(c);
            } else {
                if current_sequence.len() > 0 {
                    digit_sequences.push(current_sequence.parse::<u32>().unwrap());
                    current_sequence.clear();
                }
            }
        }
        info!("digit_sequences: {:?}", digit_sequences);
        // add up numbers in digit_sequences
        if digit_sequences.iter().sum::<u32>() != 2023 {
            reason = "math is hard";
            status_code = 400;
            nice_pass = false;
        }
    }
    
    if nice_pass {
        // 5. Rule 5: must contain the letters j, o, and y in that order and in no other order
        if  !( password.contains("j") &&
            password.contains("o") &&
            password.contains("y") &&
            // check order of occurence of "j", "o" and "y" 
            password.chars().position(|c| c == 'j').unwrap() < password.chars().position(|c| c == 'o').unwrap() &&
            password.chars().position(|c| c == 'o').unwrap() < password.chars().position(|c| c == 'y').unwrap()
        ) {
            nice_pass = false;
            reason = "not joyful enough";
            status_code = 406;
        }
    }
    if nice_pass {
        // Rule 6: must contain a letter that repeats with exactly one other letter between them (like xyx)
        // iterate over password and check if a character after skipping one is the same
        let mut found = false;
        for (i, c) in password.chars().enumerate() {
            let c1 = password.chars().nth(i + 1);
            let c2 = password.chars().nth(i + 2);
            if c1.is_none() || c2.is_none() {
                break;
            } 
            let c1 = c1.unwrap();
            let c2 = c2.unwrap();
            if ! (c.is_alphabetic() && c1.is_alphabetic() && c2.is_alphabetic()) {
               continue; 
            }
            
            info!("Rule 6 xyx pattern search: {} {} {}", c, c1, c2);
            if c == c2 && c != c1 {
                found = true;
                info!("found xyx pattern: {} {} {}", c, c1, c2);
                break;
            }
        }
        if !found {
            nice_pass = false;
            reason = "illegal: no sandwich";
            status_code = 451;
        }
    }
    if nice_pass {
        // Rule 7: must contain at least one unicode character in the range [U+2980, U+2BFF]
        // https://en.wikipedia.org/wiki/Unicode_block
        if !password.chars().any(|c| c as u32 >= 0x2980 && c as u32 <= 0x2bff) {
            nice_pass = false;
            reason = "outranged";
            status_code = 416;
        }
    }
    if nice_pass {
        // Rule 8: must contain at least one emoji
        // https://unicode.org/emoji/charts/full-emoji-list.html
        if !password.chars().any(|c| c as u32 >= 0x1f600 && c as u32 <= 0x1f64f) {
            nice_pass = false;
            reason = emojis::get_by_shortcode("face_with_rolling_eyes").unwrap().as_str();
            status_code = 426;
        }
    }

    if nice_pass {
        // Rule 9: the hexadecimal representation of the sha256 hash of the string must end with an a
        // https://en.wikipedia.org/wiki/SHA-2
        let hashed = Sha256::digest(password.as_bytes());
        let hashed = format!("{:x}", hashed);
        info!("Rule 9: hashed: {}", hashed);
        if !hashed.ends_with("a") {
            nice_pass = false;
            reason = "not a coffee brewer";
            status_code = 418;
        }
    }

    if nice_pass == true {
        (json!({"result": "nice" }).to_string(),
        StatusCode::OK)
    } else {
        // return the result but set the return status to 400
        (json!({"result": "naughty", "reason": reason}).to_string(), 
         // convert status_code to http status code
         StatusCode::from_u16(status_code).unwrap())
    }
}

// day 14
// task 1
#[derive(Debug, Serialize, Deserialize)]
struct UnsafeHtmlBody {
    content: String,
}

#[derive(Serialize)]
struct Context {
    title: String,
    content: String,
}

static TEMPLATE : &'static str =
"<html><head><title>{title}</title></head><body>{content}</body></html>";

#[post("/14/unsafe")]
// endpoint that outputs unsafe HTML
async fn unsafe_html(body: web::Json<UnsafeHtmlBody>) -> Result<HttpResponse> {
    
   let content = &body.content;
   let title = "CCH23 Day 14".to_string();
   // create html string with title and body
   //let html = format!("<html><head><title>{}</title></head><body>{}</body></html>", title, content);
   let mut tt  = TinyTemplate::new();
   let context: Context = Context {
       title,
       content: content.deref().to_string(),
   };
   tt.set_default_formatter(&tinytemplate::format_unescaped);
   tt.add_template("unsafe_html", TEMPLATE).unwrap();
   
   let html = tt.render("unsafe_html", &context).unwrap();
   info!("html: {}", html);
   Ok(HttpResponse::Ok()
       .content_type(ContentType::html()) // or "text/html")
       .body(html)) 
}

//day 14
//task 2
// endpoint that outputs safe HTML
#[post("/14/safe")]
async fn safe_html(body: web::Json<UnsafeHtmlBody>) -> Result<HttpResponse> {
    
   let content = &body.content;
   let title = "CCH23 Day 14".to_string();
   // create html string with title and body
   //let html = format!("<html><head><title>{}</title></head><body>{}</body></html>", title, content);
   let mut tt  = TinyTemplate::new();
   let context: Context = Context {
       title,
       content: content.deref().to_string(),
   };
   //tt.set_default_formatter(&tinytemplate::format_unescaped);
   tt.add_template("unsafe_html", TEMPLATE).unwrap();
   
   let html = tt.render("unsafe_html", &context).unwrap();
   info!("html: {}", html);
   Ok(HttpResponse::Ok()
       .content_type(ContentType::html()) // or "text/html")
       .body(html)) 
}

// day 13
// task 1

/*
#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[derive(Serialize, Deserialize, FromRow)]
struct Todo {
    pub note: String,
}
*/
#[get("/13/sql")]
async fn sql(db: actix_web::web::Data<sqlx::PgPool>) -> String {
    info!("db: {:?}", db);
    let result: Result<i32, sqlx::Error> = sqlx::query_scalar("SELECT value_column FROM my_table")
        .fetch_one(db.get_ref())
        .await;
    info!("result: {:?}", result);
    result.unwrap().to_string() 
}
// day 13
// task 2a
/*
#[derive(Serialize, Deserialize, FromRow, Debug)]
struct Order {
    id: i32,
    region_id: i32,
    gift_name: String,
    quantity: i32,
}
*/

#[post("/13/reset")]
async fn reset(db: actix_web::web::Data<sqlx::PgPool>) -> HttpResponse {
    
    info!("db: {:?}", db);
    let _ =
    sqlx::query_as::<_,Order>(
        r#"
        DROP TABLE IF EXISTS orders;
        "#,
        )
        .fetch_one(db.get_ref())
        .await;
    let _ =
        sqlx::query_as::<_,Order>(
        r#"
        CREATE TABLE orders (
            id INT PRIMARY KEY,
            region_id INT,
            gift_name VARCHAR(50),
            quantity INT);
            "#,
        )
        .fetch_one(db.get_ref())
        .await;
    HttpResponse::Ok().finish() 
}
// day 13
// task 2b


#[post("/13/orders")]
async fn order(db: actix_web::web::Data<sqlx::PgPool>, orders: web::Json<Vec<Order>>) -> HttpResponse {
    // iterate the orders and insert them into the database
    for order in orders.iter() {
        info!("order: {:?}", order);
        let _ =    sqlx::query_as::<_,Order>(
            // insert into orders and accumulate each order if same order is inserted multiple times
            r#"
            INSERT INTO orders (id, region_id, gift_name, quantity)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id) DO UPDATE SET
            quantity = orders.quantity + $4
            "#, 
            ) 
            .bind(order.id)
            .bind(order.region_id)
            .bind(&order.gift_name)
            .bind(order.quantity)
            .fetch_one(db.get_ref())
            .await;
        }

    HttpResponse::Ok().finish() 
}
// day 13
// task 2c
#[get("/13/orders/total")]
async fn total(db: actix_web::web::Data<sqlx::PgPool>) -> Result<String, actix_web::Error> {
   // sum up the quantity from all orders 
    let total : Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT SUM(quantity) FROM orders")
        .fetch_one(db.get_ref())
        .await;
    info!("total: {:?}", total);
    let total = total.unwrap();
    let json = json!({"total":total});
    Ok(json.to_string())
}

//day 13
//task 3
// return gift with the maximum value of quantity
#[get("/13/orders/popular")]
async fn popular(db: actix_web::web::Data<sqlx::PgPool>) -> Result<String, actix_web::Error> {
    // get the gift with the maximum quantity
    let gift : Result<String, sqlx::Error> =
        // get max of quantity from orders. 
        // sum up the quantities before calculating max if the gift name is the same.
        sqlx::query_scalar("SELECT gift_name, SUM(quantity) FROM orders GROUP BY gift_name ORDER BY SUM(quantity) DESC LIMIT 1")
         
        //sqlx::query_scalar("SELECT gift_name FROM orders WHERE quantity = (SELECT MAX(quantity) FROM orders)")

        .fetch_one(db.get_ref())
        .await;
    info!("popular gift: {:?}", gift);
    //let gift = gift.unwrap_or("null".to_string());
    let pop = 
    match gift {
        Ok(gift) => {
            json!({"popular":gift})
        }
        Err(_) => {
            let value = serde_json::value::Value::Null;
            json!({"popular":value})
        }
    };
    Ok(pop.to_string())
}

//day 12
//task 1
lazy_static! {
    static ref STATE: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new()); 
}

#[post("/12/save/{token}")]
async fn save_token(path: web::Path<String>) -> HttpResponse {
    let token = path.into_inner();
    // get the current time in seconds  
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut state= STATE.lock().unwrap();
    state.insert(token, now);
    info!("{:?}", state);
    HttpResponse::Ok().finish()
}

#[get("/12/load/{token}")]
async fn load_token(path: web::Path<String>) -> Result<String, actix_web::Error> {
    let token = path.into_inner();
    // calculate elapsed time using state
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // time elapsed since the token was set
    let state= STATE.lock().unwrap();
    let old = state.get(&token).unwrap_or(&now);
    info!("old: {} now {}", old, now);
    let elapsed = &now - old;
    info!("elapsed: {}", elapsed);
    Ok(format!("{elapsed}"))
}
// day 12
// task 2
/*
struct UuidExample {
    #[serde(with = "ulid_as_uuid")]
    identifier: Ulid
}
*/
//#[serde(with = "ulid_as_uuid")]
#[post("/12/ulids")]
async fn ulids(info:web::Json<Vec<String>>) -> Result<String> {
    // convert array of ulids in the info vector to UUIDs
    let mut uuids = 
        info.iter()
        .map(|i|  
           <Ulid as Into<Uuid>>::into(ulid::Ulid::from_string(i).unwrap()) 
           .to_string()
        ).collect::<Vec<String>>();
    // reverse the uuids vector
    uuids = uuids.into_iter().rev().collect();
    // wrap ulids vector into json object
    let json = json!(uuids);
    Ok(json.to_string())
}

// day 12
// task 3
#[post("/12/ulids/{weekday}")]
async fn weekday(path: web::Path<String>, info:web::Json<Vec<String>>) -> Result<String> {
    let wkday = path.into_inner().parse::<u8>().unwrap();
    let ts = 
        info.iter()
        .map(|i|  
            ulid::Ulid::from_string(i).unwrap().timestamp_ms()
        ).collect::<Vec<u64>>();
    
    // get count of values in ts with weekday == weekday
    let weekday_count = ts.iter().filter(|t| 
        DateTime::<Utc>::from_timestamp(**t as i64/1000i64, 0u32).unwrap()
        .date_naive().weekday() == Weekday::try_from(wkday).unwrap()).count();

        let future_count = ts.iter().filter(|t| **t > std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64).count();

    let christmas_eve_count = ts.iter().filter(|t| 
        {
            let dt =
                DateTime::<Utc>::from_timestamp(**t as i64/1000i64, 0u32).unwrap();
            dt.date_naive().day() == 24u32 && dt.date_naive().month() == 12u32
        }).count();
        //.date_naive() == chrono::NaiveDate::from_ymd_opt(2023, 12, 24).unwrap()).count();

    let lsb_is_one_count = 
        info.iter()
        .filter(|i|
                (<Ulid as Into<u128>>::into(ulid::Ulid::from_string(i).unwrap()))
                &1 == 1).count();
            
    // wrap ulids vector into json object
    let json = json!( 
        {"christmas eve": christmas_eve_count, 
            "weekday": weekday_count, 
            "in the future": future_count,
            "LSB is one": lsb_is_one_count,
        });
    Ok(json.to_string())

}

//day 11
// task 1
#[get("/11/assets/{name}")]
async fn assets(path: web::Path<String>) -> Result<fs::NamedFile, actix_web::Error> {
    let file = path.into_inner();
    let file = fs::NamedFile::open(format!("assets/{}", file)).unwrap();
    let metadata = std::fs::metadata(file.path()).unwrap();
    
    info!("file {} size {}", file.path().as_os_str().to_str().unwrap(), metadata.len());
    Ok(file
        .set_content_type(mime::IMAGE_PNG)
        .set_content_disposition(ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![],
        }
        )
    )
}

// day 11
// task 2
/*
#[derive(MultipartForm)]
struct Upload {
    description: Option<Text<String>>,
    image: TempFile,
}
*/
#[post("/11/red_pixels")]
async fn red_pixels(mut payload : Multipart) -> Result<impl Responder> {
    // receive body from the request passed in using curl -F "image=@image.png" http://localhost:8000/11/red_pixels
    // get file contents from form
    let mut buffer = web::BytesMut::new();
    while let Some(item) = payload.next().await {
        let mut field = item.unwrap();
        info!("field: {:?}", field);
        /*
        if field.name() != "image" {
            continue;
        }
        */
        while let Some(chunk) = field.next().await {
            // accumulate chunk in a buffer
            buffer.extend_from_slice(&chunk.as_ref().unwrap());
            info!("chunk len: {:?}", &chunk.as_ref().unwrap().len());
            //info!("-- CHUNK: \n{:?}", std::str::from_utf8(&chunk?));
        }
    }

    // get image from buffer
    let image = image::load_from_memory(&buffer).unwrap();
    let rgb = image.to_rgb8();
    let mut count = 0;
    // iterate over pixels in the image
    for pix in rgb.pixels() {
        let red = pix[0];
        let green = pix[1];
        let blue = pix[2];
        let sum: u32 = green as u32 + blue as u32;
        if red as u32 > sum {
            count += 1;
        }
    }
    info!("magical red count: {}", count);
    Ok(web::Json(count))
}

// day 8
// task 1
#[get("/8/weight/{id}")]
async fn weight(path: web::Path<String>) -> Result<String, actix_web::Error> {
    
    let id =  path.into_inner();
    // send request to pokemon api with this id
    let url = format!("https://pokeapi.co/api/v2/pokemon/{}/", id);
    // map error to actix_web::Error
    let resp = reqwest::get(url).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let json = resp.json::<Value>().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let mut weight = json["weight"].as_f64().unwrap();
    weight = weight / 10f64;
    info!("id {} weight: {}", id, weight);
    Ok(format!("{}", weight))
}
// day 8
// task 2
#[get("/8/drop/{id}")]
async fn drop(path: web::Path<String>) -> Result<String, actix_web::Error> {
    let height =  10f64;   // 10m
    const G: f64 = 9.825;
    let id =  path.into_inner();
    // send request to pokemon api with this id
    let url = format!("https://pokeapi.co/api/v2/pokemon/{}/", id);
    // map error to actix_web::Error
    let resp = reqwest::get(url).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let json = resp.json::<Value>().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let mut mass:f64 = json["weight"].as_f64().unwrap();
    mass = mass /10f64; // convert to kg
    let velocity = (2f64 * G * height).sqrt();
    let momentum =  mass * velocity;
    info!("id {} mass: {}", id, mass);
    Ok(format!("{}", momentum))
}

// day 7
// task 1
#[get("/7/decode")]
async fn decode(req:HttpRequest) -> Result<String, actix_web::Error> {
    //extract cookie from info
    let cookie = req.cookie("recipe").unwrap().value().to_string();
    info!("encoded cookie: {}", cookie);
    // base decode cookie using engine
    let cookie = general_purpose::STANDARD.decode(cookie).unwrap();
    // convert Vec<u8> to String
    let cookie = String::from_utf8(cookie).unwrap();
    Ok(format!("{}", cookie))
}

// day 7
// task 2
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
struct Ingredients {
    flour: u64,
    sugar: u64,
    butter: u64,
    #[serde(rename = "baking powder")]
    baking_powder: u64,
    #[serde(rename = "chocolate chips")]
    chocolate_chips: u64,
}
// result of making cookies 
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
struct Output {
    cookies: u64,
    pantry: Ingredients,
}

#[get("/7/bake")]
  
async fn bake(req:HttpRequest) -> Result<impl Responder> {
    
    //extract cookie from request
    let cookie :String = req.cookie("recipe").unwrap().value().to_string();
    info!("encoded cookie: {}", cookie);
    // base decode cookie using engine
    let cookie = general_purpose::STANDARD.decode(cookie).unwrap();
    let cookie = String::from_utf8(cookie).unwrap();
    // extract cookie to json object
    let value: serde_json::Value = 
        serde_json::from_str(&cookie).unwrap();
    info!("value: {:?}", value);
    let mut recipe_obj = Ingredients {flour: 0, sugar: 0, butter: 0, baking_powder: 0, chocolate_chips: 0};
    let mut pantry_obj = Ingredients {flour: 0, sugar: 0, butter: 0, baking_powder: 0, chocolate_chips: 0};
    let mut pantry_input: Map<String, Value> = Map::new();
    match value {
        serde_json::Value::Object(obj) => {
            info!("obj: {:?}", obj);
            match obj.get("recipe") {
                Some(serde_json::Value::Object(recipe)) => {
                    info!("recipe: {:?}", recipe);
                    match recipe.get("flour") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("flour: {:?}", num);
                            recipe_obj.flour = recipe["flour"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("flour not found in recipe");
                        }
                    }
                   match recipe.get("sugar") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("sugar: {:?}", num);
                            recipe_obj.sugar = recipe["sugar"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("sugar not found in recipe");
                        }
                   }
                   match recipe.get("butter") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("butter: {:?}", num);
                            recipe_obj.butter = recipe["butter"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("butter not found in recipe");
                        }
                   }
                   match recipe.get("baking powder") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("baking powder: {:?}", num);
                            recipe_obj.baking_powder = recipe["baking powder"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("baking powder not found in recipe");
                        }
                   }
                   match recipe.get("chocolate chips") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("chocolate chips: {:?}", num);
                            recipe_obj.chocolate_chips = recipe["chocolate chips"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("chocolate chips not found in recipe");
                        }
                    }
                }
                _ => {
                    info!("recipe not found");
                }
            }
            match obj.get("pantry") {
                Some(serde_json::Value::Object(pantry)) => {
                    info!("pantry: {:?}", pantry);
                    pantry_input = pantry.clone();
                    match pantry.get("flour") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("flour: {:?}", num);
                            pantry_obj.flour = pantry["flour"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("flour not found in pantry"); 
                        }
                    }
                    match pantry.get("sugar") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("sugar: {:?}", num);
                            pantry_obj.sugar = pantry["sugar"].as_u64().unwrap() as u64;
                        }
                        _ => {
                           info!("sugar not found in pantry"); 
                        }
                    }
                    match pantry.get("butter") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("butter: {:?}", num); 
                            pantry_obj.butter = pantry["butter"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("butter not found in pantry");
                        }
                    }
                    match pantry.get("baking powder") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("baking powder: {:?}", num);
                            pantry_obj.baking_powder = pantry["baking powder"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("baking powder not found in pantry");
                        }
                    }
                    match pantry.get("chocolate chips") {
                        Some(serde_json::Value::Number(num)) => {
                            info!("chocolate chips: {:?}", num);
                            pantry_obj.chocolate_chips = pantry["chocolate chips"].as_u64().unwrap() as u64;
                        }
                        _ => {
                            info!("chocolate chips not found in pantry");   
                        }
                    }
                }
                _ => {
                    info!("pantry not found");
                }
            }
        }
        _ => {
            panic!("value not found");
        }
    }

    /* 
     * code used for Task 2 initially 
    let recipe = Ingredients {
        flour: value["recipe"]["flour"].as_u64().unwrap() as u64,
        sugar: value["recipe"]["sugar"].as_u64().unwrap() as u64,
        butter: value["recipe"]["butter"].as_u64().unwrap() as u64,
        baking_powder: value["recipe"]["baking powder"].as_u64().unwrap() as u64,
        chocolate_chips: value["recipe"]["chocolate chips"].as_u64().unwrap() as u64,
    };
    let pantry = Ingredients {
        flour: value["pantry"]["flour"].as_u64().unwrap() as u64,
        sugar: value["pantry"]["sugar"].as_u64().unwrap() as u64,
        butter: value["pantry"]["butter"].as_u64().unwrap() as u64,
        baking_powder: value["pantry"]["baking powder"].as_u64().unwrap() as u64,
        chocolate_chips: value["pantry"]["chocolate chips"].as_u64().unwrap() as u64,
    };
    */

    info!("recipe: {:?}", recipe_obj);
    info!("pantry: {:?}", pantry_obj);
    let no_of_cookies = vec![
        pantry_obj.flour.checked_div(recipe_obj.flour).unwrap_or(0), 
        pantry_obj.sugar.checked_div(recipe_obj.sugar).unwrap_or(0), 
        pantry_obj.butter.checked_div(recipe_obj.butter).unwrap_or(0), 
        pantry_obj.baking_powder.checked_div(recipe_obj.baking_powder).unwrap_or(0), 
        pantry_obj.chocolate_chips.checked_div(recipe_obj.chocolate_chips).unwrap_or(0),
    ];
    info!("no_of_cookies vector {:?}", no_of_cookies);
    // min value in no_of_cookies
    let &no_of_cookies = no_of_cookies.iter().min().unwrap();
    if no_of_cookies != 0 {
        Ok(web::Json(json!(
            {
                "cookies": no_of_cookies,
                /*
                 * code used for Task 2 initially 
                 */
                "pantry" : Ingredients {
                    flour: pantry_obj.flour - no_of_cookies*recipe_obj.flour,
                    sugar: pantry_obj.sugar - no_of_cookies*recipe_obj.sugar,
                    butter: pantry_obj.butter - no_of_cookies*recipe_obj.butter,
                    baking_powder: pantry_obj.baking_powder - no_of_cookies*recipe_obj.baking_powder,
                    chocolate_chips: pantry_obj.chocolate_chips - no_of_cookies*recipe_obj.chocolate_chips,
                }
            }))
        )
    } else {
        Ok(web::Json(json!(
            {
                "cookies": no_of_cookies,
                "pantry": pantry_input, 
            })
        ))
    }
    //Ok(web::Json(output))
}


// day 4
// task 1
#[derive(Serialize, Deserialize)]
struct Strengths {
   strength: u32,
   name: String,
}

// day 4
// task 2
#[derive(Serialize, Deserialize, Debug)]
struct StrengthInfo {
   strength: u32,
   name: String,
   speed: f32,
   height: u32,
   antler_width: u32,
   snow_magic_power: u32,
   favorite_food: String,
   #[serde(rename = "cAnD13s_3ATeN-yesT3rdAy")]
   candies_eaten_yesterday: u32,
}

// day 4
// task 2
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
struct Winner {
    fastest: String,
    tallest: String,
    magician: String,
    consumer: String,
}

// day 6
// task 1 - count elves
// task 2 - never count on an elf
#[derive(Debug)]
#[derive(Serialize)]
struct ElfCount {
    elf: usize,
   #[serde(rename = "elf on a shelf")]
    elf_on_a_shelf: usize,
   #[serde(rename = "shelf with no elf on it")]
    shelf_with_no_elf: usize,
}
#[post("/6")]
async fn elf_count(mut body: web::Payload) -> Result<impl Responder> {
    let elf_on_a_shelf :usize = 0; 
    let mut buf = web::BytesMut::new();
    while let Some(item) = body.next().await {
       let item = item?;
       buf.extend_from_slice(&item);
    }
    info!("input data for /6: {:?}", buf);
    let body = String::from_utf8(buf.to_vec()).unwrap();
    // match if substring of a word is "elf"
    let shelf_indices  = body.match_indices("shelf").filter(|(i, _)| body.is_char_boundary(*i) ).collect::<Vec<_>>();
    let shelf_count = shelf_indices.len();
    // look for a match for "elf on a" preceding the 'shelf' for each of the "shelf" occurences
    let mut shelf_with_elf = 0;
    for (i, _) in shelf_indices {
        if let Some(index) = body[i-9..i].find("elf on a") {
            shelf_with_elf +=1;
            info!("for shelf index {} 'elf on a' found at {:?} shelf with elf: {:?}", i, index, shelf_with_elf);
                }
            }
    info!("shelf_count: {:?} shelf_with_elf: {:?}", shelf_count, shelf_with_elf);

    let elf_count = ElfCount {
        elf :body.split_ascii_whitespace().filter_map(|s| if s.contains("elf")  {Some(())} else {None} ).count(),
        elf_on_a_shelf: 
           shelf_with_elf,
        shelf_with_no_elf:  {
            shelf_count - shelf_with_elf
        },
    };
    info!("elf_count: {:?}", elf_count);
    Ok(web::Json(elf_count))
}

// day 4
// task 1
#[post("/4/strength")]
async fn strength(info:web::Json<Vec<Strengths>>) -> Result<String, actix_web::Error> {
    let sum_of_strengths:u32 = info.iter().map(|i| i.strength).sum();
    info!("sum_of_strengths: {}", sum_of_strengths);
    Ok(format!("{}", sum_of_strengths))
}

// day 4
// task 2
use ordered_float::OrderedFloat;
#[post("/4/contest")]

async fn contest(info:web::Json<Vec<StrengthInfo>>) -> Result<HttpResponse, actix_web::Error> {
    info!("contest info: {:?}", info);
    let winner = Winner {
        fastest: info
            .iter()
            .max_by_key(|i| OrderedFloat(i.speed))
            .map(|i| format!("Speeding past the finish line with a strength of {} is {}", i.strength, i.name))
            .unwrap(),
        tallest: info
            .iter()
            .max_by_key(|i| i.height)
            .map(|i| format!("{} is standing tall with his {} cm wide antlers", i.name, i.antler_width))
            .unwrap(),
        magician: info
            .iter()
            .max_by_key(|i| i.snow_magic_power)
            .map(|i| format!("{} could blast you away with a snow magic power of {}", i.name, i.snow_magic_power ))
            .unwrap(),
        consumer: info
            .iter()
            .max_by_key(|i| i.candies_eaten_yesterday)
            .map(|i| format!("{} ate lots of candies, but also some {}", i.name, i.favorite_food))
            .unwrap(),
    };
    info!("contest winner: {:?}", winner);
    Ok(HttpResponse::Ok().json(winner))
}
    

#[shuttle_runtime::main]
/*
async fn main() -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
*/
// added below and commented above for day 13 postgres challenge
async fn actix_web(
    #[shuttle_shared_db::Postgres (
    //local_uri = "postgres://jai:postgres@localhost:5423/"
    )] pool: PgPool,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    pool.execute(include_str!("../schema.sql"))
        .await
        .map_err(CustomError::new)?;

    let state = web::Data::new(pool);
    // custom `Json` extractor configuration
    let json_cfg = web::JsonConfig::default()
    // limit request payload size
    .limit(4096)
    // only accept text/plain content type
    .content_type(|mime| mime == mime::TEXT_PLAIN)
    // use custom error handler
    .error_handler(|err, req| {
        //error::InternalError::from_response(err, HttpResponse::Conflict().into()).into()
        error::InternalError::from_response(err, HttpResponse::BadRequest().into()).into()
    });
    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(hello_world);
        // server /-1/error handler
        cfg.service(send_internal_error);
        //cfg.service(index);
        cfg.service(index_multi);
        cfg.service(strength);
        cfg.service(contest);
        cfg.service(elf_count);
        cfg.service(decode);
        cfg.service(bake);
        cfg.service(weight);
        cfg.service(drop);
        cfg.service(assets);
        cfg.service(red_pixels);
        cfg.service(save_token);
        cfg.service(load_token);
        cfg.service(ulids);
        cfg.service(weekday);
        cfg.service(unsafe_html);
        cfg.service(safe_html);
        cfg.app_data(json_cfg)
            .service(nice)
            .service(game);

        cfg.app_data(state)
            .service(sql)
            .service(reset)
            .service(order)
            .service(total)
            .service(popular)
            .service(worldwide_reset)
            .service(worldwide_regions)
            .service(worldwide_order)
            .service(worldwide_total)
            .service(top_list);
            
        /*
            web::scope("/sql")
            .service(sql)
            .app_data(state.clone()),
        );
        */

    };
    Ok(config.into())
}
