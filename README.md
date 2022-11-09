# Blaze Schannel

> This library is a fork of [schannel-rs](https://github.com/steffengy/schannel-rs) library that is stripped down and specifically intended for
> use with the Mass Effect 3 redirector server to support the outdated SSLv3 requirements of the redirector server. 

# Deprecation Notice

This library is now deprecated in favor of my custom SSL implementation https://github.com/jacobtread/blaze-ssl which doesn't depend on the
Windows SChannel library and allows the server to have redirection without being restricted to Windows
