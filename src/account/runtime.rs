use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use url::Url;

use super::error::{AccountError, AccountResult};
use super::model::DeviceAuthorizationPrompt;
use super::secret::SecretString;

pub trait AccountRuntime: Send + Sync {
    fn now_unix(&self) -> u64;
    fn fill_random(&self, output: &mut [u8]) -> AccountResult<()>;
    fn sleep(&self, duration: Duration);
    fn cancelled(&self) -> bool;
}

#[derive(Default)]
pub struct SystemRuntime;

impl AccountRuntime for SystemRuntime {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn fill_random(&self, output: &mut [u8]) -> AccountResult<()> {
        rand::rngs::OsRng.fill_bytes(output);
        Ok(())
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn cancelled(&self) -> bool {
        false
    }
}

pub(crate) fn fresh_secret(runtime: &dyn AccountRuntime) -> AccountResult<SecretString> {
    let mut bytes = [0_u8; 32];
    runtime.fill_random(&mut bytes)?;
    Ok(SecretString::new(URL_SAFE_NO_PAD.encode(bytes)))
}

pub struct PkceCallback {
    pub(crate) redirect_uri: Url,
    pub(crate) code: SecretString,
    pub(crate) state: SecretString,
}

impl std::fmt::Debug for PkceCallback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkceCallback")
            .field("redirect_uri", &self.redirect_uri)
            .field("code", &"<redacted>")
            .field("state", &"<redacted>")
            .finish()
    }
}

pub trait PkceInteraction: Send + Sync {
    fn prepare_redirect(&self, callback_path: &str) -> AccountResult<Url>;

    fn authorize(
        &self,
        authorization_url: &Url,
        deadline_unix: u64,
        runtime: &dyn AccountRuntime,
    ) -> AccountResult<PkceCallback>;
}

pub trait DeviceInteraction: Send + Sync {
    fn display(&self, prompt: &DeviceAuthorizationPrompt) -> AccountResult<()>;
}

pub trait LinkInteraction: Send + Sync {
    fn open(&self, verification_uri: &Url) -> AccountResult<()>;
}

#[derive(Default)]
pub struct ConsoleDeviceInteraction;

impl DeviceInteraction for ConsoleDeviceInteraction {
    fn display(&self, prompt: &DeviceAuthorizationPrompt) -> AccountResult<()> {
        eprintln!(
            "Open {} and enter code {} for {} on {}",
            prompt.verification_uri,
            prompt.user_code,
            prompt.display.product_name,
            prompt.display.device_label
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct BrowserLinkInteraction;

impl LinkInteraction for BrowserLinkInteraction {
    fn open(&self, verification_uri: &Url) -> AccountResult<()> {
        launch_browser(verification_uri)
    }
}

#[derive(Default)]
pub struct NativeLoopbackInteraction {
    listener: Mutex<Option<TcpListener>>,
}

impl PkceInteraction for NativeLoopbackInteraction {
    fn prepare_redirect(&self, callback_path: &str) -> AccountResult<Url> {
        validate_callback_path(callback_path)?;
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|_| AccountError::InteractionUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AccountError::InteractionUnavailable)?;
        let address = listener
            .local_addr()
            .map_err(|_| AccountError::InteractionUnavailable)?;
        let redirect = Url::parse(&format!("http://{address}{callback_path}"))
            .map_err(|_| AccountError::InteractionUnavailable)?;
        let mut slot = self
            .listener
            .lock()
            .map_err(|_| AccountError::InteractionUnavailable)?;
        if slot.is_some() {
            return Err(AccountError::InteractionUnavailable);
        }
        *slot = Some(listener);
        Ok(redirect)
    }

    fn authorize(
        &self,
        authorization_url: &Url,
        deadline_unix: u64,
        runtime: &dyn AccountRuntime,
    ) -> AccountResult<PkceCallback> {
        launch_browser(authorization_url)?;
        let listener = self
            .listener
            .lock()
            .map_err(|_| AccountError::InteractionUnavailable)?
            .take()
            .ok_or(AccountError::InteractionUnavailable)?;
        let address = listener
            .local_addr()
            .map_err(|_| AccountError::InteractionUnavailable)?;
        loop {
            if runtime.cancelled() {
                return Err(AccountError::Cancelled);
            }
            if runtime.now_unix() >= deadline_unix {
                return Err(AccountError::DeadlineExceeded);
            }
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let callback = read_callback(&mut stream, address)?;
                    let message = b"Authentication received. You may close this window.";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        message.len(),
                        String::from_utf8_lossy(message)
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return Ok(callback);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    runtime.sleep(Duration::from_millis(50));
                }
                Err(_) => return Err(AccountError::InteractionUnavailable),
            }
        }
    }
}

fn read_callback(
    stream: &mut std::net::TcpStream,
    listener_address: SocketAddr,
) -> AccountResult<PkceCallback> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| AccountError::InvalidPkceCallback)?;
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|_| AccountError::InvalidPkceCallback)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 8192 {
            return Err(AccountError::InvalidPkceCallback);
        }
    }
    parse_callback_request(&bytes, listener_address)
}

pub(crate) fn parse_callback_request(
    bytes: &[u8],
    listener_address: SocketAddr,
) -> AccountResult<PkceCallback> {
    let request = std::str::from_utf8(bytes).map_err(|_| AccountError::InvalidPkceCallback)?;
    let first_line = request
        .split("\r\n")
        .next()
        .ok_or(AccountError::InvalidPkceCallback)?;
    let mut parts = first_line.split(' ');
    let method = parts.next();
    let target = parts.next();
    let version = parts.next();
    if method != Some("GET")
        || version != Some("HTTP/1.1")
        || parts.next().is_some()
        || !target.is_some_and(|value| value.starts_with('/'))
    {
        return Err(AccountError::InvalidPkceCallback);
    }
    let target = target.ok_or(AccountError::InvalidPkceCallback)?;
    let parsed = Url::parse(&format!("http://{listener_address}{target}"))
        .map_err(|_| AccountError::InvalidPkceCallback)?;
    if parsed.fragment().is_some() {
        return Err(AccountError::InvalidPkceCallback);
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in parsed.query_pairs() {
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(AccountError::InvalidPkceCallback);
        }
    }
    if error.as_deref() == Some("access_denied") && code.is_none() {
        return Err(AccountError::AuthorizationDenied);
    }
    if error.is_some() || code.is_none() || state.is_none() {
        return Err(AccountError::InvalidPkceCallback);
    }
    let mut redirect_uri = parsed;
    redirect_uri.set_query(None);
    Ok(PkceCallback {
        redirect_uri,
        code: SecretString::new(code.expect("checked above")),
        state: SecretString::new(state.expect("checked above")),
    })
}

fn validate_callback_path(path: &str) -> AccountResult<()> {
    if !path.starts_with('/')
        || path.len() > 120
        || path.contains(['?', '#'])
        || path.contains("..")
    {
        return Err(AccountError::InteractionUnavailable);
    }
    Ok(())
}

fn launch_browser(url: &Url) -> AccountResult<()> {
    let mut command = platform_browser_command(url)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear();
    add_browser_bootstrap_environment(&mut command);
    command
        .spawn()
        .map(|_| ())
        .map_err(|_| AccountError::InteractionUnavailable)
}

#[allow(clippy::unnecessary_wraps)] // Unsupported targets return a closed error in their cfg arm.
fn platform_browser_command(url: &Url) -> AccountResult<Command> {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/open");
        command.arg(url.as_str());
        Ok(command)
    }
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/xdg-open");
        command.arg(url.as_str());
        Ok(command)
    }
    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("rundll32.exe");
        command.arg("url.dll,FileProtocolHandler").arg(url.as_str());
        Ok(command)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        Err(AccountError::InteractionUnavailable)
    }
}

fn add_browser_bootstrap_environment(command: &mut Command) {
    command.env("PATH", "/usr/bin:/bin");
    #[cfg(target_os = "linux")]
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(target_os = "windows")]
    for name in ["SystemRoot", "WINDIR", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152);

    #[test]
    fn callback_parser_accepts_one_exact_code_and_state() {
        let callback = parse_callback_request(
            b"GET /callback?code=auth-code&state=expected-state HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n",
            ADDRESS,
        )
        .unwrap();
        assert_eq!(
            callback.redirect_uri.as_str(),
            "http://127.0.0.1:49152/callback"
        );
        assert_eq!(callback.code.expose(), "auth-code");
        assert_eq!(callback.state.expose(), "expected-state");
    }

    #[test]
    fn callback_parser_rejects_injection_duplicates_and_denial() {
        for request in [
            b"POST /callback?code=a&state=b HTTP/1.1\r\n\r\n".as_slice(),
            b"GET https://attacker.invalid/callback?code=a&state=b HTTP/1.1\r\n\r\n",
            b"GET /callback?code=a&code=b&state=c HTTP/1.1\r\n\r\n",
            b"GET /callback?code=a&state=b&error=access_denied HTTP/1.1\r\n\r\n",
            b"GET /callback?code=a HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                parse_callback_request(request, ADDRESS).unwrap_err(),
                AccountError::InvalidPkceCallback
            );
        }
        assert_eq!(
            parse_callback_request(
                b"GET /callback?error=access_denied&state=b HTTP/1.1\r\n\r\n",
                ADDRESS
            )
            .unwrap_err(),
            AccountError::AuthorizationDenied
        );
    }
}
