use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
    path::PathBuf,
};

use base64::{engine::general_purpose, Engine as _};
use clap::{ArgAction, Parser};
use env_logger::Builder;
use log::LevelFilter;
use poem::{
    error::{InternalServerError, NotFoundError},
    get, handler,
    listener::TcpListener,
    middleware::AddData,
    post,
    web::{Data, Json, Path, Redirect},
    EndpointExt, Error, Route,
};
use serde::{Deserialize, Serialize};
use sled::Db;
use urlencoding::decode;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ShortURL {
    pub slug: String,
    pub url: String,
    pub hits: u64,
}

impl ShortURL {
    #[must_use]
    pub fn new(slug: String, url: String) -> Self {
        Self { slug, url, hits: 0 }
    }
}

fn url_hash(url: &str, digits: u16) -> String {
    let mut s = DefaultHasher::new();
    url.hash(&mut s);
    let hash = s.finish().to_string();

    let as_hex = &general_purpose::URL_SAFE_NO_PAD.encode(hash)[..digits as usize];
    as_hex.to_string()
}

#[handler]
fn put_url(
    Path(url): Path<String>,
    db: Data<&Db>,
    len: Data<&u16>,
) -> Result<Json<ShortURL>, Error> {
    log::info!("Trying to add shURL for '{url}'");
    let url = decode(&url).map_err(InternalServerError)?.to_string();
    log::debug!("Decoded '{url}'");
    let slug = url_hash(&url, **len);
    log::debug!("Adding slug /{slug} => {url}");

    let shurl = match db.get(slug.clone()) {
        Ok(None) => ShortURL::new(slug.clone(), url),
        Ok(Some(bytes)) => serde_cbor::from_slice(&bytes).map_err(InternalServerError)?,
        Err(e) => return Err(InternalServerError(e)),
    };
    match db.insert(
        slug,
        serde_cbor::to_vec(&shurl).map_err(InternalServerError)?,
    ) {
        Ok(_) => Ok(Json(shurl)),
        Err(e) => Err(InternalServerError(e)),
    }
}

#[handler]
fn get_url(Path(slug): Path<String>, db: Data<&Db>) -> Result<Json<ShortURL>, Error> {
    log::info!("Trying to get metadata for slug '{slug}'");

    match db.get(slug.clone()) {
        Ok(None) => Err(NotFoundError.into()),
        Ok(Some(bytes)) => Ok(Json(
            serde_cbor::from_slice(&bytes).map_err(InternalServerError)?,
        )),
        Err(e) => Err(InternalServerError(e)),
    }
}

#[handler]
fn del_url(Path(slug): Path<String>, db: Data<&Db>) -> Result<(), Error> {
    log::info!("Trying to delete shURL for slug '{slug}'");

    match db.remove(slug.clone()) {
        Ok(None) => Err(NotFoundError.into()),
        Ok(Some(_)) => Ok(()),
        Err(e) => Err(InternalServerError(e)),
    }
}

#[handler]
fn get_tiny_url(Path(slug): Path<String>, db: Data<&Db>) -> Result<Redirect, Error> {
    log::info!("Getting shURL for slug '{slug}'");

    match db.get(slug.clone()) {
        Ok(None) => Err(NotFoundError.into()),
        Ok(Some(bytes)) => {
            let mut shurl: ShortURL =
                serde_cbor::from_slice(&bytes).map_err(InternalServerError)?;
            shurl.hits += 1;
            match db.insert(
                slug,
                serde_cbor::to_vec(&shurl).map_err(InternalServerError)?,
            ) {
                Ok(_) => Ok(Redirect::temporary(shurl.url)),
                Err(e) => Err(InternalServerError(e)),
            }
        }
        Err(e) => Err(InternalServerError(e)),
    }
}

#[derive(Parser)]
struct Args {
    /// Database file
    #[arg(short, long, default_value = "shurl.db", env = "SHURL_DATABASE")]
    database: PathBuf,

    /// Address on which the server will listen
    #[arg(short = 'H', long, default_value = "127.0.0.1", env = "SHURL_HOST")]
    host: IpAddr,

    /// Port on which the server will listen
    #[arg(short, long, default_value = "8080", env = "SHURL_PORT")]
    port: u16,

    /// Number of hex digits to use for shortened urls (8-32)
    #[arg(short = 'l', long, env = "SHURL_URL_LENGTH", value_parser = 8..=32, default_value_t = 8)]
    url_length: u16,

    /// Increase verbosity
    #[arg(short, long, action=ArgAction::Count, env = "SHURL_VERBOSITY")]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    Builder::from_default_env()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp(None)
        .init();

    let db = sled::Config::default()
        .path(args.database)
        .mode(sled::Mode::HighThroughput)
        .open()?;

    let app = Route::new()
        .at("/url/:id", post(put_url).get(get_url).delete(del_url))
        .nest("/", Route::new().at("/:hash", get(get_tiny_url)))
        .with(AddData::new(db))
        .with(AddData::new(args.url_length));

    let listen_endpoint = format!("{}:{}", args.host, args.port);
    log::info!("listening on http://{}", listen_endpoint);

    poem::Server::new(TcpListener::bind(&listen_endpoint))
        .run(app)
        .await
}
