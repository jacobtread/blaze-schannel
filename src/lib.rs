//! Bindings to the Windows SChannel APIs.
#![cfg(windows)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate lazy_static;

use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::Credentials;
use windows_sys::Win32::Security::Authentication::Identity;
use windows_sys::Win32::Security::Cryptography;

use std::{fmt, io, ptr, mem};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ops::Deref;
use std::slice;
use std::ffi::c_void;
use std::any::Any;
use std::cmp;
use std::error::Error;
use std::io::{BufRead, Cursor, Read, Write};
use std::sync::Arc;

macro_rules! inner {
    ($t:path, $raw:ty) => {
        impl crate::Inner<$raw> for $t {
            unsafe fn from_inner(t: $raw) -> Self {
                $t(t)
            }

            fn as_inner(&self) -> $raw {
                self.0
            }

            fn get_mut(&mut self) -> &mut $raw {
                &mut self.0
            }
        }

        impl crate::RawPointer for $t {
            unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> $t {
                $t(t as _)
            }

            unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void {
                self.0 as *mut _
            }
        }
    };
}

const ACCEPT_REQUESTS: u32 = Identity::ASC_REQ_ALLOCATE_MEMORY
    | Identity::ASC_REQ_CONFIDENTIALITY
    | Identity::ASC_REQ_SEQUENCE_DETECT
    | Identity::ASC_REQ_STREAM
    | Identity::ASC_REQ_REPLAY_DETECT;


/// Wrapper of a winapi certificate, or a `PCCERT_CONTEXT`.
#[derive(Debug)]
pub struct CertContext(*const Cryptography::CERT_CONTEXT);

unsafe impl Sync for CertContext {}

unsafe impl Send for CertContext {}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            Cryptography::CertFreeCertificateContext(self.0);
        }
    }
}

impl Clone for CertContext {
    fn clone(&self) -> CertContext {
        unsafe { CertContext(Cryptography::CertDuplicateCertificateContext(self.0)) }
    }
}

inner!(CertContext, *const Cryptography::CERT_CONTEXT);

/// Representation of certificate store on Windows, wrapping a `HCERTSTORE`.
pub struct CertStore(Cryptography::HCERTSTORE);


inner!(CertStore, Cryptography::HCERTSTORE);

unsafe impl Sync for CertStore {}

unsafe impl Send for CertStore {}

impl fmt::Debug for CertStore {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("CertStore").finish()
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            Cryptography::CertCloseStore(self.0, 0);
        }
    }
}

impl Clone for CertStore {
    fn clone(&self) -> CertStore {
        unsafe { CertStore(Cryptography::CertDuplicateStore(self.0)) }
    }
}

impl CertStore {
    pub fn import_pkcs12(data: &[u8], password: Option<&str>) -> io::Result<CertStore> {
        unsafe {
            let blob = Cryptography::CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let password = password.map(|s| {
                OsStr::new(s)
                    .encode_wide()
                    .chain(Some(0))
                    .collect::<Vec<_>>()
            });
            let password = password.as_ref().map(|s| s.as_ptr());
            let password = password.unwrap_or(ptr::null());
            let res = Cryptography::PFXImportCertStore(
                &blob,
                password,
                Cryptography::CRYPT_KEY_FLAGS::default(),
            );
            if !res.is_null() {
                Ok(CertStore(res))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn first(&self) -> Option<CertContext> {
        unsafe {
            let value = Cryptography::CertEnumCertificatesInStore(self.0, ptr::null_mut());
            if value.is_null() {
                None
            } else {
                let next = CertContext::from_inner(value);
                Some(next)
            }
        }
    }
}


pub struct ContextBuffer(pub Identity::SecBuffer);

impl Drop for ContextBuffer {
    fn drop(&mut self) {
        unsafe {
            Identity::FreeContextBuffer(self.0.pvBuffer);
        }
    }
}

impl Deref for ContextBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
    }
}


pub struct SecurityContext(Credentials::SecHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe {
            Identity::DeleteSecurityContext(&self.0);
        }
    }
}

impl Inner<Credentials::SecHandle> for SecurityContext {
    unsafe fn from_inner(inner: Credentials::SecHandle) -> SecurityContext {
        SecurityContext(inner)
    }

    fn as_inner(&self) -> Credentials::SecHandle {
        self.0
    }

    fn get_mut(&mut self) -> &mut Credentials::SecHandle {
        &mut self.0
    }
}

impl SecurityContext {

    pub fn new() -> SecurityContext{
        unsafe { return SecurityContext(mem::zeroed()); }
    }

    unsafe fn attribute<T>(&self, attr: Identity::SECPKG_ATTR) -> io::Result<T> {
        let mut value = mem::zeroed();
        let status =
            Identity::QueryContextAttributesW(&self.0, attr, &mut value as *mut _ as *mut _);
        match status {
            Foundation::SEC_E_OK => Ok(value),
            err => Err(io::Error::from_raw_os_error(err)),
        }
    }

    pub fn stream_sizes(&self) -> io::Result<Identity::SecPkgContext_StreamSizes> {
        unsafe { self.attribute(Identity::SECPKG_ATTR_STREAM_SIZES) }
    }
}


lazy_static! {
    static ref szOID_PKIX_KP_SERVER_AUTH: Vec<u8> = Cryptography::szOID_PKIX_KP_SERVER_AUTH
        .bytes()
        .chain(Some(0))
        .collect();
    static ref szOID_SERVER_GATED_CRYPTO: Vec<u8> = Cryptography::szOID_SERVER_GATED_CRYPTO
        .bytes()
        .chain(Some(0))
        .collect();
    static ref szOID_SGC_NETSCAPE: Vec<u8> = Cryptography::szOID_SGC_NETSCAPE
        .bytes()
        .chain(Some(0))
        .collect();
}

enum State {
    Initializing {
        needs_flush: bool,
        more_calls: bool,
        shutting_down: bool,
    },
    Streaming {
        sizes: Identity::SecPkgContext_StreamSizes,
    },
    Shutdown,
}

pub struct TlsStream<S> {
    cred: SchannelCred,
    context: SecurityContext,
    stream: S,
    state: State,
    accept_first: bool,
    needs_read: usize,
    dec_in: Cursor<Vec<u8>>,
    enc_in: Cursor<Vec<u8>>,
    out_buf: Cursor<Vec<u8>>,
    last_write_len: usize,
}

impl<S> TlsStream<S> {
    pub fn new(
        cred: SchannelCred,
        stream: S,
    ) -> Result<TlsStream<S>, HandshakeError<S>>
        where
            S: Read + Write,
    {
        let context = SecurityContext::new();
        let stream = TlsStream {
            cred,
            context,
            stream,
            accept_first: true,
            state: State::Initializing {
                needs_flush: false,
                more_calls: true,
                shutting_down: false,
            },
            needs_read: 1,
            dec_in: Cursor::new(Vec::new()),
            enc_in: Cursor::new(Vec::new()),
            out_buf: Cursor::new(Vec::new()),
            last_write_len: 0,
        };

        MidHandshakeTlsStream { inner: stream }.handshake()
    }
}


/// ensures that a TlsStream is always Sync/Send
fn _is_sync() {
    fn sync<T: Sync + Send>() {}
    sync::<TlsStream<()>>();
}

#[derive(Debug)]
pub enum HandshakeError<S> {
    IO(io::Error),
    Interrupted(MidHandshakeTlsStream<S>),
}

impl<S: fmt::Debug + Any> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            HandshakeError::IO(ref e) => Some(e),
            HandshakeError::Interrupted(_) => None,
        }
    }
}

impl<S: fmt::Debug + Any> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = match *self {
            HandshakeError::IO(_) => "failed to perform handshake",
            HandshakeError::Interrupted(_) => "interrupted performing handshake",
        };
        write!(f, "{}", desc)?;
        if let Some(e) = self.source() {
            write!(f, ": {}", e)?;
        }
        Ok(())
    }
}

/// A stream which has not yet completed its handshake.
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S> {
    inner: TlsStream<S>,
}

impl<S> fmt::Debug for TlsStream<S>
    where
        S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S> TlsStream<S> {
    /// Returns a reference to the wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S> TlsStream<S>
    where
        S: Read + Write,
{

    /// Returns a reference to the buffer of pending data.
    ///
    /// Like `BufRead::fill_buf` except that it will return an empty slice
    /// rather than reading from the wrapped stream if there is no buffered
    /// data.
    pub fn get_buf(&self) -> &[u8] {
        &self.dec_in.get_ref()[self.dec_in.position() as usize..]
    }

    /// Shuts the TLS session down.
    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.state {
            State::Shutdown => return Ok(()),
            State::Initializing {
                shutting_down: true,
                ..
            } => {}
            _ => {
                unsafe {
                    let mut token = Identity::SCHANNEL_SHUTDOWN;
                    let ptr = &mut token as *mut _ as *mut u8;
                    let size = mem::size_of_val(&token);
                    let token = slice::from_raw_parts_mut(ptr, size);
                    let mut buf = [secbuf(Identity::SECBUFFER_TOKEN, Some(token))];
                    let desc = secbuf_desc(&mut buf);

                    match Identity::ApplyControlToken(self.context.get_mut(), &desc) {
                        Foundation::SEC_E_OK => {}
                        err => return Err(io::Error::from_raw_os_error(err)),
                    }
                }

                self.state = State::Initializing {
                    needs_flush: false,
                    more_calls: true,
                    shutting_down: true,
                };
                self.needs_read = 0;
            }
        }

        self.initialize().map(|_| ())
    }

    fn step_initialize(&mut self) -> io::Result<()> {
        unsafe {
            let pos = self.enc_in.position() as usize;
            let mut inbufs = vec![
                secbuf(
                    Identity::SECBUFFER_TOKEN,
                    Some(&mut self.enc_in.get_mut()[..pos]),
                ),
                secbuf(Identity::SECBUFFER_EMPTY, None),
            ];
            let inbuf_desc = secbuf_desc(&mut inbufs[..]);

            let mut outbufs = [
                secbuf(Identity::SECBUFFER_TOKEN, None),
                secbuf(Identity::SECBUFFER_ALERT, None),
                secbuf(Identity::SECBUFFER_EMPTY, None),
            ];
            let mut outbuf_desc = secbuf_desc(&mut outbufs);

            let mut attributes = 0;

            let status = {
                let ptr = if self.accept_first {
                    ptr::null_mut()
                } else {
                    self.context.get_mut()
                };
                Identity::AcceptSecurityContext(
                    &self.cred.as_inner(),
                    ptr,
                    &inbuf_desc,
                    ACCEPT_REQUESTS,
                    0,
                    self.context.get_mut(),
                    &mut outbuf_desc,
                    &mut attributes,
                    ptr::null_mut(),
                )
            };

            for buf in &outbufs[1..] {
                if !buf.pvBuffer.is_null() {
                    Identity::FreeContextBuffer(buf.pvBuffer);
                }
            }

            match status {
                Foundation::SEC_E_OK => {
                    let nread = if inbufs[1].BufferType == Identity::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - inbufs[1].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    let to_write = if outbufs[0].pvBuffer.is_null() {
                        None
                    } else {
                        Some(ContextBuffer(outbufs[0]))
                    };

                    self.consume_enc_in(nread);
                    self.needs_read = (self.enc_in.position() == 0) as usize;
                    if let Some(to_write) = to_write {
                        self.out_buf.get_mut().extend_from_slice(&to_write);
                    }
                    if self.enc_in.position() != 0 {
                        self.decrypt()?;
                    }
                    if let State::Initializing {
                        ref mut more_calls, ..
                    } = self.state
                    {
                        *more_calls = false;
                    }
                }
                Foundation::SEC_I_CONTINUE_NEEDED => {
                    // Windows apparently doesn't like AcceptSecurityContext
                    // being called as if it were the second time unless the
                    // first call to AcceptSecurityContext succeeded with
                    // CONTINUE_NEEDED.
                    //
                    // In other words, if we were to set `accept_first` to
                    // `false` after the literal first call to
                    // `AcceptSecurityContext` while the call returned
                    // INCOMPLETE_MESSAGE, the next call would return an error.
                    //
                    // For that reason we only set `accept_first` to false here
                    // once we've actually successfully received the full
                    // "token" from the client.
                    self.accept_first = false;
                    let nread = if inbufs[1].BufferType == Identity::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - inbufs[1].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    let to_write = ContextBuffer(outbufs[0]);

                    self.consume_enc_in(nread);
                    self.needs_read = (self.enc_in.position() == 0) as usize;
                    self.out_buf.get_mut().extend_from_slice(&to_write);
                }
                Foundation::SEC_E_INCOMPLETE_MESSAGE => {
                    self.needs_read = if inbufs[1].BufferType == Identity::SECBUFFER_MISSING {
                        inbufs[1].cbBuffer as usize
                    } else {
                        1
                    };
                }
                err => return Err(io::Error::from_raw_os_error(err)),
            }
            Ok(())
        }
    }

    fn initialize(&mut self) -> io::Result<Option<Identity::SecPkgContext_StreamSizes>> {
        loop {
            match self.state {
                State::Initializing {
                    mut needs_flush,
                    more_calls,
                    shutting_down,
                } => {
                    if self.write_out()? > 0 {
                        needs_flush = true;
                        if let State::Initializing {
                            ref mut needs_flush,
                            ..
                        } = self.state
                        {
                            *needs_flush = true;
                        }
                    }

                    if needs_flush {
                        self.stream.flush()?;
                        if let State::Initializing {
                            ref mut needs_flush,
                            ..
                        } = self.state
                        {
                            *needs_flush = false;
                        }
                    }

                    if !more_calls {
                        self.state = if shutting_down {
                            State::Shutdown
                        } else {
                            State::Streaming {
                                sizes: self.context.stream_sizes()?,
                            }
                        };
                        continue;
                    }

                    if self.needs_read > 0 && self.read_in()? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF during handshake",
                        ));
                    }

                    self.step_initialize()?;
                }
                State::Streaming { sizes } => return Ok(Some(sizes)),
                State::Shutdown => return Ok(None),
            }
        }
    }

    fn write_out(&mut self) -> io::Result<usize> {
        let mut out = 0;
        while self.out_buf.position() as usize != self.out_buf.get_ref().len() {
            let position = self.out_buf.position() as usize;
            let nwritten = self.stream.write(&self.out_buf.get_ref()[position..])?;
            out += nwritten;
            self.out_buf.set_position((position + nwritten) as u64);
        }

        Ok(out)
    }

    fn read_in(&mut self) -> io::Result<usize> {
        let mut sum_nread = 0;

        while self.needs_read > 0 {
            let existing_len = self.enc_in.position() as usize;
            let min_len = cmp::max(cmp::max(1024, 2 * existing_len), self.needs_read);
            if self.enc_in.get_ref().len() < min_len {
                self.enc_in.get_mut().resize(min_len, 0);
            }
            let nread = {
                let buf = &mut self.enc_in.get_mut()[existing_len..];
                self.stream.read(buf)?
            };
            self.enc_in.set_position((existing_len + nread) as u64);
            self.needs_read = self.needs_read.saturating_sub(nread);
            if nread == 0 {
                break;
            }
            sum_nread += nread;
        }

        Ok(sum_nread)
    }

    fn consume_enc_in(&mut self, nread: usize) {
        let size = self.enc_in.position() as usize;
        assert!(size >= nread);
        let count = size - nread;

        if count > 0 {
            self.enc_in.get_mut().drain(..nread);
        }

        self.enc_in.set_position(count as u64);
    }

    fn decrypt(&mut self) -> io::Result<bool> {
        unsafe {
            let position = self.enc_in.position() as usize;
            let mut bufs = [
                secbuf(
                    Identity::SECBUFFER_DATA,
                    Some(&mut self.enc_in.get_mut()[..position]),
                ),
                secbuf(Identity::SECBUFFER_EMPTY, None),
                secbuf(Identity::SECBUFFER_EMPTY, None),
                secbuf(Identity::SECBUFFER_EMPTY, None),
            ];
            let bufdesc = secbuf_desc(&mut bufs);

            match Identity::DecryptMessage(self.context.get_mut(), &bufdesc, 0, ptr::null_mut()) {
                Foundation::SEC_E_OK => {
                    let start = bufs[1].pvBuffer as usize - self.enc_in.get_ref().as_ptr() as usize;
                    let end = start + bufs[1].cbBuffer as usize;
                    self.dec_in.get_mut().clear();
                    self.dec_in
                        .get_mut()
                        .extend_from_slice(&self.enc_in.get_ref()[start..end]);
                    self.dec_in.set_position(0);

                    let nread = if bufs[3].BufferType == Identity::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - bufs[3].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    self.consume_enc_in(nread);
                    self.needs_read = (self.enc_in.position() == 0) as usize;
                    Ok(false)
                }
                Foundation::SEC_E_INCOMPLETE_MESSAGE => {
                    self.needs_read = if bufs[1].BufferType == Identity::SECBUFFER_MISSING {
                        bufs[1].cbBuffer as usize
                    } else {
                        1
                    };
                    Ok(false)
                }
                Foundation::SEC_I_CONTEXT_EXPIRED => Ok(true),
                Foundation::SEC_I_RENEGOTIATE => {
                    self.state = State::Initializing {
                        needs_flush: false,
                        more_calls: true,
                        shutting_down: false,
                    };

                    let nread = if bufs[3].BufferType == Identity::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - bufs[3].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    self.consume_enc_in(nread);
                    self.needs_read = 0;
                    Ok(false)
                }
                err => Err(io::Error::from_raw_os_error(err)),
            }
        }
    }

    fn encrypt(&mut self, buf: &[u8], sizes: &Identity::SecPkgContext_StreamSizes, ) -> io::Result<()> {
        assert!(buf.len() <= sizes.cbMaximumMessage as usize);

        unsafe {
            let len = sizes.cbHeader as usize + buf.len() + sizes.cbTrailer as usize;

            if self.out_buf.get_ref().len() < len {
                self.out_buf.get_mut().resize(len, 0);
            }

            let message_start = sizes.cbHeader as usize;
            self.out_buf.get_mut()[message_start..message_start + buf.len()].clone_from_slice(buf);

            let mut bufs = {
                let out_buf = self.out_buf.get_mut();
                let size = sizes.cbHeader as usize;

                let header = secbuf(
                    Identity::SECBUFFER_STREAM_HEADER,
                    Some(&mut out_buf[..size]),
                );
                let data = secbuf(
                    Identity::SECBUFFER_DATA,
                    Some(&mut out_buf[size..size + buf.len()]),
                );
                let trailer = secbuf(
                    Identity::SECBUFFER_STREAM_TRAILER,
                    Some(&mut out_buf[size + buf.len()..]),
                );
                let empty = secbuf(Identity::SECBUFFER_EMPTY, None);
                [header, data, trailer, empty]
            };
            let bufdesc = secbuf_desc(&mut bufs);

            match Identity::EncryptMessage(self.context.get_mut(), 0, &bufdesc, 0) {
                Foundation::SEC_E_OK => {
                    let len = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
                    self.out_buf.get_mut().truncate(len as usize);
                    self.out_buf.set_position(0);
                    Ok(())
                }
                err => Err(io::Error::from_raw_os_error(err)),
            }
        }
    }
}

impl<S> MidHandshakeTlsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }
}

impl<S> MidHandshakeTlsStream<S>
    where
        S: Read + Write,
{
    /// Restarts the handshake process.
    pub fn handshake(mut self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self.inner.initialize() {
            Ok(_) => Ok(self.inner),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(HandshakeError::Interrupted(self))
            }
            Err(e) => Err(HandshakeError::IO(e)),
        }
    }
}

impl<S> Write for TlsStream<S>
    where
        S: Read + Write,
{
    /// In the case of a WouldBlock error, we expect another call
    /// starting with the same input data
    /// This is similar to the use of ACCEPT_MOVING_WRITE_BUFFER in openssl
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sizes = match self.initialize()? {
            Some(sizes) => sizes,
            None => {
                return Err(io::Error::from_raw_os_error(
                    Foundation::SEC_E_CONTEXT_EXPIRED as i32,
                ));
            }
        };

        // if we have pending output data, it must have been because a previous
        // attempt to send this part of the data ran into an error.
        if self.out_buf.position() == self.out_buf.get_ref().len() as u64 {
            let len = cmp::min(buf.len(), sizes.cbMaximumMessage as usize);
            self.encrypt(&buf[..len], &sizes)?;
            self.last_write_len = len;
        }
        self.write_out()?;

        Ok(self.last_write_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Make sure the write buffer is emptied
        self.write_out()?;
        self.stream.flush()
    }
}

impl<S> Read for TlsStream<S>
    where
        S: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = {
            let read_buf = self.fill_buf()?;
            let nread = cmp::min(buf.len(), read_buf.len());
            buf[..nread].copy_from_slice(&read_buf[..nread]);
            nread
        };
        self.consume(nread);
        Ok(nread)
    }
}


impl<S> BufRead for TlsStream<S>
    where
        S: Read + Write,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.get_buf().is_empty() {
            if self.initialize()?.is_none() {
                break;
            }

            if self.needs_read > 0 {
                if self.read_in()? == 0 {
                    break;
                }
                self.needs_read = 0;
            }

            let eof = self.decrypt()?;
            if eof {
                break;
            }
        }

        Ok(self.get_buf())
    }

    fn consume(&mut self, amt: usize) {
        let pos = self.dec_in.position() + amt as u64;
        assert!(pos <= self.dec_in.get_ref().len() as u64);
        self.dec_in.set_position(pos);
    }
}


lazy_static! {
    static ref UNISP_NAME: Vec<u8> = Identity::UNISP_NAME.bytes().chain(Some(0)).collect();
}

#[derive(Clone)]
pub struct SchannelCred(Arc<RawCredHandle>);

struct RawCredHandle(Credentials::SecHandle);

impl Drop for RawCredHandle {
    fn drop(&mut self) {
        unsafe {
            Identity::FreeCredentialsHandle(&self.0);
        }
    }
}

impl SchannelCred {
    pub fn new(cert: CertContext) -> io::Result<SchannelCred> {
        unsafe {
            let mut handle: Credentials::SecHandle = mem::zeroed();
            let mut cred_data: Identity::SCHANNEL_CRED = mem::zeroed();
            cred_data.dwVersion = Identity::SCHANNEL_CRED_VERSION;
            cred_data.dwFlags = Identity::SCH_CRED_NO_DEFAULT_CREDS;

            // Enable all protocols
            cred_data.grbitEnabledProtocols = Identity::SP_PROT_SSL3_SERVER |
                Identity::SP_PROT_TLS1_0_SERVER |
                Identity::SP_PROT_TLS1_1_SERVER |
                Identity::SP_PROT_TLS1_2_SERVER |
                Identity::SP_PROT_TLS1_3_SERVER;

            let mut certs = vec![cert];
            cred_data.cCreds = certs.len() as u32;
            cred_data.paCred = certs.as_mut_ptr() as _;

            match Identity::AcquireCredentialsHandleA(
                ptr::null(),
                UNISP_NAME.as_ptr(),
                Identity::SECPKG_CRED_INBOUND,
                ptr::null_mut(),
                &mut cred_data as *const _ as *const _,
                None,
                ptr::null_mut(),
                &mut handle,
                ptr::null_mut(),
            ) {
                Foundation::SEC_E_OK => Ok(SchannelCred::from_inner(handle)),
                err => Err(io::Error::from_raw_os_error(err)),
            }
        }
    }

    unsafe fn from_inner(inner: Credentials::SecHandle) -> SchannelCred {
        SchannelCred(Arc::new(RawCredHandle(inner)))
    }

    pub(crate) fn as_inner(&self) -> Credentials::SecHandle {
        self.0.as_ref().0
    }
}

/// Allows access to the underlying schannel API representation of a wrapped data type
///
/// Performing actions with internal handles might lead to the violation of internal assumptions
/// and therefore is inherently unsafe.
pub trait RawPointer {
    /// Constructs an instance of this type from its handle / pointer.
    /// # Safety
    /// This function is unsafe
    unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> Self;

    /// Get a raw pointer from the underlying handle / pointer.
    /// # Safety
    /// This function is unsafe
    unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void;
}


trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    fn get_mut(&mut self) -> &mut T;
}

unsafe fn secbuf(buftype: u32, bytes: Option<&mut [u8]>) -> Identity::SecBuffer {
    let (ptr, len) = match bytes {
        Some(bytes) => (bytes.as_mut_ptr(), bytes.len() as u32),
        None => (ptr::null_mut(), 0),
    };
    Identity::SecBuffer {
        BufferType: buftype,
        cbBuffer: len,
        pvBuffer: ptr as *mut c_void,
    }
}

unsafe fn secbuf_desc(bufs: &mut [Identity::SecBuffer]) -> Identity::SecBufferDesc {
    Identity::SecBufferDesc {
        ulVersion: Identity::SECBUFFER_VERSION,
        cBuffers: bufs.len() as u32,
        pBuffers: bufs.as_mut_ptr(),
    }
}