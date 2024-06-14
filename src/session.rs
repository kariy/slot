use std::{fs, path::PathBuf};

use anyhow::Context;
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tower_http::cors::CorsLayer;
use tracing::trace;
use url::Url;

use crate::credential::{Credentials, SLOT_DIR};
use crate::{browser, server::LocalServer};

const SESSION_FILE_BASE_NAME: &str = "session.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// The target contract address.
    pub target: FieldElement,
    /// The method name.
    pub method: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// The expiration date of the session.
    pub expires_at: String,
    /// The policies that the session is allowed to execute.
    pub policies: Vec<Policy>,
    pub credentials: SessionCredentials,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCredentials {
    /// The signing key of the session.
    pub private_key: String,
    pub authorization: Vec<String>,
}

/// Retrieves the session for the given chain id.
pub fn get(chain_id: FieldElement) -> anyhow::Result<Session> {
    let credentials = Credentials::load()?;
    let username = credentials.account.expect("id must exist").id;
    let contents = fs::read_to_string(&get_file_path(&username, chain_id))?;
    Ok(serde_json::from_str(&contents)?)
}

/// Stores the session on-disk.
pub fn store(chain_id: FieldElement, session: Session) -> anyhow::Result<()> {
    // TODO: maybe can store the authenticated user in a global variable so that
    // we don't have to call load again if we already did it before.
    let credentials = Credentials::load()?;
    let username = credentials.account.expect("id must exist").id;
    let path = get_file_path(&username, chain_id);

    // Create the parent directories if they don't yet exist.
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            trace!(path = %parent.display(), "Creating parent directories.");
            fs::create_dir_all(&path)?;
        }
    }

    let contents = serde_json::to_string_pretty(&session)?;
    fs::write(&path, contents)?;
    trace!(path = %path.display(), "Session token stored successfully.");

    Ok(())
}

#[tracing::instrument(level = "trace", skip(rpc_url), fields(policies = policies.len()))]
pub async fn create<U>(rpc_url: U, policies: &[Policy]) -> anyhow::Result<Session>
where
    U: Into<Url>,
{
    let credentials = Credentials::load()?;
    let username = credentials.account.expect("id must exist").id;

    let rpc_url: Url = rpc_url.into();
    let mut rx = open_session_creation_page(&username, rpc_url.as_str(), policies)?;

    Ok(rx.recv().await.context("Channel dropped.")?)
}

/// Starts the session creation process by opening the browser to the Cartridge keychain to prompt
/// the user to approve the session creation.
fn open_session_creation_page(
    username: &str,
    rpc_url: &str,
    policies: &[Policy],
) -> anyhow::Result<Receiver<Session>> {
    let params = prepare_query_params(username, rpc_url, policies)?;
    let url = format!("https://x.cartridge.gg/slot/session?{params}");

    let (tx, rx) = channel::<Session>(1);
    let server = callback_server(tx)?;

    // get the callback server url
    let port = server.local_addr()?.port();
    let mut url = Url::parse(&url)?;

    // append the callback uri to the query params
    let callback_uri = format!("http://localhost:{port}/callback");
    url.query_pairs_mut()
        .append_pair("callback_uri", &callback_uri);

    browser::open(&url.as_str())?;
    tokio::spawn(server.start());

    Ok(rx)
}

fn prepare_query_params(
    username: &str,
    rpc_url: &str,
    policies: &[Policy],
) -> Result<String, serde_json::Error> {
    let policies = policies
        .iter()
        .map(serde_json::to_string)
        .map(|p| Ok(urlencoding::encode(&p?).into_owned()))
        .collect::<Result<Vec<String>, _>>()?
        .join(",");

    Ok(format!(
        "username={username}&rpc_url={rpc_url}&policies=[{policies}]",
    ))
}

/// Create the callback server that will receive the session token from the browser.
fn callback_server(tx: Sender<Session>) -> anyhow::Result<LocalServer> {
    let handler = move |State(tx): State<Sender<Session>>, Json(session): Json<Session>| async move {
        trace!("Received session token from the browser.");
        tx.send(session).await.expect("qed; channel closed");
    };

    let router = Router::new()
        .route("/callback", post(handler))
        .with_state(tx);

    Ok(LocalServer::new(router)?.cors(CorsLayer::permissive()))
}

fn get_file_path(username: &str, chain_id: FieldElement) -> PathBuf {
    // eg 0x12345-session.json
    let file_name = format!("{chain_id:#x}-{}", SESSION_FILE_BASE_NAME);
    let mut path = dirs::config_local_dir().expect("unsupported OS");
    path.extend([SLOT_DIR, username, &file_name]);
    path
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_session() {}

    #[test]
    fn store_session() {}
}
