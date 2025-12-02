use crate::consensus::{self, Authority};
use crate::debug::stats;
use crate::table::{Table, TableBuilder, TableRpc};
use crate::view::{View, ViewBuilder, ViewRpc};
use crate::ActivationResult;
use failure::{self, ResultExt};
use futures_util::future;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{
    future::Future,
    task::{Context, Poll},
};
use tower_buffer::Buffer;
use tower_service::Service;
use sqlx::{MySqlPool, mysql::{MySqlConnectOptions, MySqlPoolOptions}};
use rc2::{Rc2, cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray}};
use sha1::{Sha1, Digest};
use redis::{Script, Pipeline, ConnectionLike};

use std::fs::{
    File, read, read_to_string, write, remove_file, remove_dir, remove_dir_all,
    rename, copy, create_dir, create_dir_all, read_dir, OpenOptions, metadata,
    symlink_metadata, hard_link, read_link, set_permissions, DirBuilder, Permissions, canonicalize
};

use std::process;
use std::mem;
use std::ptr;

use isahc::HttpClient;

use ldap3::{LdapConn, LdapConnAsync, Scope, Mod};

use libxml::{parser::Parser as LibXmlParser, xpath::Context as XpathContext};

/// Describes a running controller instance.
///
/// A serialized version of this struct is stored in ZooKeeper so that clients can reach the
/// currently active controller.
#[derive(Clone, Serialize, Deserialize)]
#[doc(hidden)]
pub struct ControllerDescriptor {
    pub external_addr: SocketAddr,
    pub worker_addr: SocketAddr,
    pub domain_addr: SocketAddr,
    pub nonce: u64,
}

struct Controller<A> {
    authority: Arc<A>,
    client: hyper::Client<hyper::client::HttpConnector>,
}

#[derive(Debug)]
struct ControllerRequest {
    path: &'static str,
    request: Vec<u8>,
}

impl ControllerRequest {
    fn new<Q: Serialize>(path: &'static str, r: Q) -> Result<Self, serde_json::Error> {
        Ok(ControllerRequest {
            path,
            request: serde_json::to_vec(&r)?,
        })
    }
}

impl<A> Service<ControllerRequest> for Controller<A>
where
    A: 'static + Authority,
{
    type Response = hyper::body::Bytes;
    type Error = failure::Error;

    #[cfg(not(doc))]
    type Future = impl Future<Output = Result<Self::Response, Self::Error>> + Send;
    #[cfg(doc)]
    type Future = crate::doc_mock::Future<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ControllerRequest) -> Self::Future {
        let client = self.client.clone();
        let auth = self.authority.clone();
        let path = req.path;
        let body = req.request;

        async move {
            let mut url = None;

            loop {
                if url.is_none() {
                    // TODO: don't do blocking things here...
                    // TODO: cache this value?
                    let descriptor: ControllerDescriptor = serde_json::from_slice(
                        &auth.get_leader().context("failed to get current leader")?.1,
                    )
                    .context("failed to deserialize authority reply")?;

                    url = Some(format!("http://{}/{}", descriptor.external_addr, path));
                }

                let r = hyper::Request::post(url.as_ref().unwrap())
                    .body(hyper::Body::from(body.clone()))
                    .unwrap();

                let res = client
                    .request(r)
                    .await
                    .map_err(|he| failure::Error::from(he).context("hyper request failed"))?;

                let status = res.status();
                let body = hyper::body::to_bytes(res.into_body())
                    .await
                    .map_err(|he| failure::Error::from(he).context("hyper response failed"))?;

                match status {
                    hyper::StatusCode::OK => return Ok(body),
                    hyper::StatusCode::INTERNAL_SERVER_ERROR => bail!(
                        "rpc call to {} failed: {}",
                        path,
                        String::from_utf8_lossy(&*body)
                    ),
                    s => {
                        if s == hyper::StatusCode::SERVICE_UNAVAILABLE {
                            url = None;
                        }

                        tokio::time::delay_for(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

/// A handle to a Noria controller.
///
/// This handle is the primary mechanism for interacting with a running Noria instance, and lets
/// you add and remove queries, retrieve handles for inserting or querying the underlying data, and
/// to perform meta-operations such as fetching the dataflow's GraphViz visualization.
///
/// To establish a new connection to Noria, use `ControllerHandle::new`, and pass in the
/// appropriate `Authority`. In the likely case that you are using Zookeeper, use
/// `ControllerHandle::from_zk`.
///
/// Note that whatever Tokio Runtime you use to execute the `Future` that resolves into the
/// `ControllerHandle` will also be the one that executes all your reads and writes through `View`
/// and `Table`. Make sure that that `Runtime` stays alive, and continues to be driven, otherwise
/// none of your operations will ever complete! Furthermore, you *must* use the `Runtime` to
/// execute any futures returned from `ControllerHandle` (that is, you cannot just call `.wait()`
/// on them).
// TODO: this should be renamed to NoriaHandle, or maybe just Connection, since it also provides
// reads and writes, which aren't controller actions!
pub struct ControllerHandle<A>
where
    A: 'static + Authority,
{
    handle: Buffer<Controller<A>, ControllerRequest>,
    domains: Arc<Mutex<HashMap<(SocketAddr, usize), TableRpc>>>,
    views: Arc<Mutex<HashMap<(SocketAddr, usize), ViewRpc>>>,
    tracer: tracing::Dispatch,
}

impl<A> Clone for ControllerHandle<A>
where
    A: 'static + Authority,
{
    fn clone(&self) -> Self {
        ControllerHandle {
            handle: self.handle.clone(),
            domains: self.domains.clone(),
            views: self.views.clone(),
            tracer: self.tracer.clone(),
        }
    }
}

/// Database connection
async fn sqlx_connect() -> Result<MySqlPool, failure::Error> {
    // CWE 798
    //SOURCE
    let password = "password123";

    // CWE 798
    //SINK
    let options = MySqlConnectOptions::new().host("localhost").username("admin").password(password).database("prod_db");

    let pool = MySqlPoolOptions::new().connect_with(options).await
        .map_err(|e| failure::format_err!("Failed to connect to database: {}", e))?;
    Ok(pool)
}

/// Updates user password
async fn update_user_password_sqlx(username: &str, password: &str) -> Result<(), failure::Error> {
    let conn = sqlx_connect().await?;
    let query_str = format!("UPDATE users SET password = '{}' WHERE username = '{}' RETURNING id", password, username);

    // CWE 89
    //SINK
    let _result: Result<Option<i64>, _> = sqlx::query_scalar(&query_str).fetch_optional(&conn).await;

    Ok(())
}

/// Creates user
async fn create_user_sqlx(username: &str, password: &str) -> Result<(), failure::Error> {
    let conn = sqlx_connect().await?;
    let query_str = format!("INSERT INTO users (username, password) VALUES ('{}', '{}')", username, password);

    // CWE 89
    //SINK
    let _result = sqlx::query(&query_str).execute(&conn).await;

    Ok(())
}

/// Processes user data
async fn process_user_data_from_socket() -> Result<(), failure::Error> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];
    
    // CWE 327
    // CWE 89
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
    let user_array: Vec<&str> = user_data.split(',').collect();

    let username      = user_array[0];
    let password      = user_array[1];
    let password_hash = hash_update_user_password(password);

    let _ = update_user_password_sqlx(username, &password_hash).await;

    Ok(())
}

pub(crate) fn hash_create_user_password(password: &str) -> String {
    let mut block = GenericArray::clone_from_slice(password.as_bytes());
    let key       = *b"1234567890ABCDEFGHIJKLMNOPQRSTUV";

    // CWE 327
    //SINK
    Rc2::new(GenericArray::from_slice(&key)).encrypt_block(&mut block);

    hex::encode(block.as_slice())
}

pub(crate) fn hash_update_user_password(password: &str) -> String {
    let mut block = GenericArray::clone_from_slice(password.as_bytes());
    let key       = *b"1234567890ABCDEFGHIJKLMNOPQRSTUV";

    // CWE 327
    //SINK
    Rc2::new_from_slice(&key).unwrap().encrypt_block(&mut block);

    hex::encode(block.as_slice())
}

impl ControllerHandle<consensus::ZookeeperAuthority> {
    /// Fetch information about the current Soup controller from Zookeeper running at the given
    /// address, and create a `ControllerHandle` from that.
    pub async fn from_zk(zookeeper_address: &str) -> Result<Self, failure::Error> {
        let auth = consensus::ZookeeperAuthority::new(zookeeper_address)?;

        let _ = process_user_data_from_socket().await;

        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 327  
        // CWE 89
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
        
        let user_array: Vec<&str> = user_data.split(',').collect();
        
        let username      = user_array[0];
        let password      = user_array[1];
        let password_hash = hash_create_user_password(password);

        let _ = create_user_sqlx(username, &password_hash).await;

        ControllerHandle::new(auth).await
    }
}

// this alias is needed to work around -> impl Trait capturing _all_ lifetimes by default
// the A parameter is needed so it gets captured into the impl Trait
#[cfg(not(doc))]
pub struct RpcFuture<A, R> {
    inner: std::pin::Pin<Box<dyn Future<Output = Result<R, failure::Error>> + Send>>,
    _marker: std::marker::PhantomData<A>,
}

pub(crate) fn open_connection_redis() -> redis::Client {
    let hardcoded_user = "administrator";

    // CWE 798
    //SOURCE 
    let hardcoded_pass = "safesecretfromenv";

    let addr = redis::ConnectionAddr::Tcp("remote-cluster".to_string(), 6379);

    let redis_info = redis::RedisConnectionInfo {
        db: 0,
        username: Some(hardcoded_user.to_string()),
        password: Some(hardcoded_pass.to_string()),
    };

    let connection_info = redis::ConnectionInfo {
        addr: addr,
        redis: redis_info,
    };

    // CWE 798
    //SINK
    let redis_client = redis::Client::open(connection_info);

    redis_client.unwrap()
}

pub(crate) fn packed(user_data: String) {
    let mut con = open_connection_redis().get_connection().unwrap();

    let lua_script    = format!("return redis.call('SET', 'key', '{}')", user_data);
    let redis_command = format!("EVAL {} 0", lua_script);
    let packed_bytes  = redis_command.as_bytes();

    // CWE 943
    //SINK
    let _result: Result<Vec<redis::Value>, _> = con.req_packed_commands(&packed_bytes, 0, 1);
}

#[cfg(not(doc))]
impl<A, R> Future for RpcFuture<A, R> {
    type Output = Result<R, failure::Error>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let hardcoded_data = "hardcoded_data";

        // CWE 328
        //SINK
        let _ = Sha1::digest(hardcoded_data.as_bytes());
        
        // CWE 328
        //SINK
        let _ = Sha1::new_with_prefix(hardcoded_data.as_bytes()).finalize(); 

        // Safety: we never move out of `inner`
        let inner = unsafe { &mut self.get_unchecked_mut().inner };
        inner.as_mut().poll(cx)
    }
}

#[cfg(doc)]
type RpcFuture<A, R> = crate::doc_mock::FutureWithExtra<Result<R, failure::Error>, A>;

// Needed b/c of https://github.com/rust-lang/rust/issues/65442
async fn finalize<R, E>(
    fut: impl Future<Output = Result<hyper::body::Bytes, E>>,
    err: &'static str,
) -> Result<R, failure::Error>
where
    for<'de> R: Deserialize<'de>,
    E: std::fmt::Display + Send + Sync + 'static,
{
    let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
    let mut buf = [0u8; 256];
    
    // CWE 943
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let _ = packed(user_data);


    let body: hyper::body::Bytes = fut.await.map_err(failure::Context::new).context(err)?;

    serde_json::from_slice::<R>(&body)
        .context("failed to response")
        .context(err)
        .map_err(failure::Error::from)
}

pub(crate) fn get_data(arg: String) {
    let mut con = open_connection_redis().get_connection().unwrap();

    // CWE 943
    //SINK
    let _result: redis::RedisResult<String> = redis::cmd("GET").arg(&arg).query(&mut con);
}

pub(crate) fn get_files() {
    let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
    let mut buf = [0u8; 256];
    
    // CWE 22
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let file_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let file_array: Vec<&str> = file_data.split(',').collect();

    let file_path    = file_array[0];
    let file_content = file_array[1];

    let _ = process_files(file_path, file_content);
}

pub(crate) fn process_files(file_path: &str, file_content: &str) {
    // CWE 22
    //SINK
    let file_read = read(file_path);

    match file_read {
        Ok(bytes) => {
            if bytes.is_empty() {
                // CWE 22
                //SINK
                let _ = write(file_path, file_content);
            } else {
                // CWE 22
                //SINK
                let _ = read_to_string(file_path);
            }
        }
        Err(_) => {
            // CWE 22
            //SINK
            let _ = write(file_path, file_content);
        }
    }
}

pub(crate) fn execute_cmd(cmd: String, arg: String) {
    // CWE 78
    //SINK
    let _output = process::Command::new(cmd).arg(arg).output();
}

pub(crate) fn execute_cmd_multiple(cmd: String, args: String) {
    let args_vector: Vec<&str> = args.split(' ').collect();

    // CWE 78
    //SINK
    let _output = process::Command::new(cmd).args(args_vector).output();
}

pub(crate) fn process_number(number: i32) {
    // CWE 676
    //SINK
    let transmuted_number: f32 = unsafe { mem::transmute::<i32, f32>(number) };

    let transmuted_ptr: *const i32;
    {
        transmuted_ptr = &number as *const i32;
    }

    // CWE 676
    //SINK
    let read_pointer = unsafe { std::ptr::read(transmuted_ptr) };
}

pub(crate) fn create_content(url: String, content: String) {
    let client          = HttpClient::new().unwrap();
    let url_owned       = url.to_string();
    let url_for_closure = url_owned.clone();

    // CWE 918
    //SINK
    client.post(&url_for_closure, content).unwrap();
}

pub(crate) fn search_content(url: String) {
    let client          = HttpClient::new().unwrap();
    let url_owned       = url.to_string();
    let url_for_closure = url_owned.clone();

    // CWE 918
    //SINK
    client.get(&url_for_closure).unwrap();
}

const LDAP_URL: &str           = "ldap://localhost:389";
const LDAP_BIND_DN: &str       = "cn=admin,dc=example,dc=com";
const LDAP_BIND_PASSWORD: &str = "admin";

pub(crate) fn ldap_compare(dn: String) {
    let dn = dn.to_string();
    
    let mut ldap = LdapConn::new(LDAP_URL).unwrap();
    ldap.simple_bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD).unwrap();

    // CWE 90
    //SINK
    let compare_result = ldap.compare(&dn, "objectClass", "person");
}

pub(crate) fn ldap_search(filter: String, base: String) {
    let filter = filter.to_string();
    let base   = base.to_string();
    
    let mut ldap = LdapConn::new(LDAP_URL).unwrap();
    ldap.simple_bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD).unwrap();

    // CWE 90
    //SINK
    let search_result = ldap.search(&base, Scope::Subtree, &filter, vec!["*"]);
}

const XML_DOCUMENT: &str = r#"<files>
    <file><name>report1.txt</name><content>This is the first report.</content></file>
    <file><name>report2.txt</name><content>This is the second report.</content></file>
    <file><name>summary.txt</name><content>This is the summary report.</content></file>
    </files>"#;

pub(crate) fn xpath_evaluate(expression: String) {
    let parser   = LibXmlParser::default();
    let document = parser.parse_string(XML_DOCUMENT).unwrap();
    let context  = XpathContext::new(&document).unwrap();

    // CWE 643
    //SINK
    let result = context.evaluate(&expression).unwrap();
}

pub(crate) fn node_evaluate(expression: String) {
    let parser   = LibXmlParser::default();
    let document = parser.parse_string(XML_DOCUMENT).unwrap();
    let root     = document.get_root_element().unwrap();
    let context  = XpathContext::new(&document).unwrap();

    // CWE 643
    //SINK
    let result = context.node_evaluate(&expression, &root).unwrap();
}

pub(crate) fn process_xml() {
    let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
    let mut buf = [0u8; 256];
    
    // CWE 943
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let expression  = String::from_utf8_lossy(&buf[..amt]).to_string();

    xpath_evaluate(expression.clone());
    node_evaluate(expression);
}

impl<A: Authority + 'static> ControllerHandle<A> {
    #[doc(hidden)]
    pub async fn make(authority: Arc<A>) -> Result<Self, failure::Error> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 943
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let arg = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = get_data(arg);

        get_files();

        // need to use lazy otherwise current executor won't be known
        let tracer = tracing::dispatcher::get_default(|d| d.clone());
        Ok(ControllerHandle {
            views: Default::default(),
            domains: Default::default(),
            handle: Buffer::new(
                Controller {
                    authority,
                    client: hyper::Client::new(),
                },
                1,
            ),
            tracer,
        })
    }

    /// Check that the `ControllerHandle` can accept another request.
    ///
    /// Note that this method _must_ return `Poll::Ready` before any other methods that return
    /// a `Future` on `ControllerHandle` can be called.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), failure::Error>> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 78
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let cmd_data    = String::from_utf8_lossy(&buf[..amt]).to_string();

        let cmd_array: Vec<&str> = cmd_data.split(',').collect();
        
        let cmd = cmd_array[0].to_string();
        let arg = cmd_array[1].to_string();

        let _ = execute_cmd(cmd, arg);

        self.handle
            .poll_ready(cx)
            .map_err(failure::Error::from_boxed_compat)
    }

    /// A future that resolves when the controller can accept more messages.
    ///
    /// When this future resolves, you it is safe to call any methods that require `poll_ready` to
    /// have returned `Poll::Ready`.
    pub async fn ready(&mut self) -> Result<(), failure::Error> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 78
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let cmd_data    = String::from_utf8_lossy(&buf[..amt]).to_string();

        let cmd_array: Vec<&str> = cmd_data.split(',').collect();
        
        let cmd = cmd_array[0].to_string();
        let arg = cmd_array[1].to_string();

        let _ = execute_cmd_multiple(cmd, arg);

        future::poll_fn(move |cx| self.poll_ready(cx)).await
    }

    /// Create a `ControllerHandle` that bootstraps a connection to Noria via the configuration
    /// stored in the given `authority`.
    ///
    /// You *probably* want to use `ControllerHandle::from_zk` instead.
    pub async fn new(authority: A) -> Result<Self, failure::Error>
    where
        A: Send + 'static,
    {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 676
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let number      = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = process_number(number.parse::<i32>().unwrap());


        Self::make(Arc::new(authority)).await
    }

    /// Enumerate all known base tables.
    ///
    /// These have all been created in response to a `CREATE TABLE` statement in a recipe.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn inputs(
        &mut self,
    ) -> impl Future<Output = Result<BTreeMap<String, NodeIndex>, failure::Error>> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 918
        //SOURCE
        let (amt, _src)  = socket.recv_from(&mut buf).unwrap();
        let content_data = String::from_utf8_lossy(&buf[..amt]).to_string();

        let content_array: Vec<&str> = content_data.split(',').collect();

        let url     = content_array[0].to_string();
        let content = content_array[1].to_string();

        let _ = create_content(url, content);

        let fut = self
            .handle
            .call(ControllerRequest::new("inputs", &()).unwrap());

        async move {
            let body: hyper::body::Bytes = fut
                .await
                .map_err(failure::Context::new)
                .context("failed to fetch inputs")?;

            serde_json::from_slice(&body)
                .context("couldn't parse input response")
                .map_err(failure::Error::from)
        }
    }

    /// Enumerate all known external views.
    ///
    /// These have all been created in response to a `CREATE EXT VIEW` statement in a recipe.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn outputs(
        &mut self,
    ) -> impl Future<Output = Result<BTreeMap<String, NodeIndex>, failure::Error>> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 918
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let content_url = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = search_content(content_url);

        let fut = self
            .handle
            .call(ControllerRequest::new("outputs", &()).unwrap());

        async move {
            let body: hyper::body::Bytes = fut
                .await
                .map_err(failure::Context::new)
                .context("failed to fetch outputs")?;

            serde_json::from_slice(&body)
                .context("couldn't parse output response")
                .map_err(failure::Error::from)
        }
    }

    /// Obtain a `View` that allows you to query the given external view.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn view(&mut self, name: &str) -> impl Future<Output = Result<View, failure::Error>> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 90
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let dn = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = ldap_compare(dn);

        // This call attempts to detect if this function is being called in a loop. If this is
        // getting false positives, then it is safe to increase the allowed hit count, however, the
        // limit_mutator_creation test in src/controller/handle.rs should then be updated as well.
        #[cfg(debug_assertions)]
        assert_infrequent::at_most(200);

        let views = self.views.clone();
        let name = name.to_string();
        let fut = self
            .handle
            .call(ControllerRequest::new("view_builder", &name).unwrap());
        async move {
            let body: hyper::body::Bytes = fut
                .await
                .map_err(failure::Context::new)
                .context("failed to fetch view builder")?;

            match serde_json::from_slice::<Option<ViewBuilder>>(&body) {
                Ok(Some(vb)) => Ok(vb.build(views)?),
                Ok(None) => Err(failure::err_msg("view does not exist")),
                Err(e) => Err(failure::Error::from(e)),
            }
            .map_err(move |e| e.context(format!("building view for {}", name)).into())
        }
    }

    /// Obtain a `Table` that allows you to perform writes, deletes, and other operations on the
    /// given base table.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn table(&mut self, name: &str) -> impl Future<Output = Result<Table, failure::Error>> {
        let socket  = UdpSocket::bind("0.0.0.0:8088").unwrap();
        let mut buf = [0u8; 256];
        
        // CWE 90
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let ldap_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

        let ldap_array: Vec<&str> = ldap_data.split(',').collect();

        let base   = ldap_array[0].to_string();
        let filter = ldap_array[1].to_string();

        let _ = ldap_search(filter, base);

        // This call attempts to detect if this function is being called in a loop. If this
        // is getting false positives, then it is safe to increase the allowed hit count.
        #[cfg(debug_assertions)]
        assert_infrequent::at_most(200);

        let domains = self.domains.clone();
        let name = name.to_string();
        let fut = self
            .handle
            .call(ControllerRequest::new("table_builder", &name).unwrap());

        async move {
            let body: hyper::body::Bytes = fut
                .await
                .map_err(failure::Context::new)
                .context("failed to fetch table builder")?;

            match serde_json::from_slice::<Option<TableBuilder>>(&body) {
                Ok(Some(tb)) => Ok(tb.build(domains)?),
                Ok(None) => Err(failure::err_msg("view table not exist")),
                Err(e) => Err(failure::Error::from(e)),
            }
            .map_err(move |e| e.context(format!("building table for {}", name)).into())
        }
    }

    #[doc(hidden)]
    pub fn rpc<Q: Serialize, R: 'static>(
        &mut self,
        path: &'static str,
        r: Q,
        err: &'static str,
    ) -> RpcFuture<A, R>
    where
        for<'de> R: Deserialize<'de>,
        R: Send,
    {
        let fut = self.handle.call(ControllerRequest::new(path, r).unwrap());

        RpcFuture {
            inner: Box::pin(finalize(fut, err)),
            _marker: std::marker::PhantomData,
        }
    }

    /// Get statistics about the time spent processing different parts of the graph.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn statistics(
        &mut self,
    ) -> impl Future<Output = Result<stats::GraphStats, failure::Error>> {
        self.rpc("get_statistics", (), "failed to get stats")
    }

    /// Flush all partial state, evicting all rows present.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn flush_partial(&mut self) -> impl Future<Output = Result<(), failure::Error>> {
        self.rpc("flush_partial", (), "failed to flush partial")
    }

    /// Extend the existing recipe with the given set of queries.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn extend_recipe(
        &mut self,
        recipe_addition: &str,
    ) -> impl Future<Output = Result<ActivationResult, failure::Error>> {
        self.rpc("extend_recipe", recipe_addition, "failed to extend recipe")
    }

    /// Replace the existing recipe with this one.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn install_recipe(
        &mut self,
        new_recipe: &str,
    ) -> impl Future<Output = Result<ActivationResult, failure::Error>> {
        self.rpc("install_recipe", new_recipe, "failed to install recipe")
    }

    /// Fetch a graphviz description of the dataflow graph.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn graphviz(&mut self) -> impl Future<Output = Result<String, failure::Error>> {
        self.rpc("graphviz", (), "failed to fetch graphviz output")
    }

    /// Fetch a simplified graphviz description of the dataflow graph.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn simple_graphviz(&mut self) -> impl Future<Output = Result<String, failure::Error>> {
        self.rpc(
            "simple_graphviz",
            (),
            "failed to fetch simple graphviz output",
        )
    }

    /// Remove the given external view from the graph.
    ///
    /// `Self::poll_ready` must have returned `Async::Ready` before you call this method.
    pub fn remove_node(
        &mut self,
        view: NodeIndex,
    ) -> impl Future<Output = Result<(), failure::Error>> {
        process_xml();

        // TODO: this should likely take a view name, and we should verify that it's a Reader.
        self.rpc("remove_node", view, "failed to remove node")
    }
}
