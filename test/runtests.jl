using Test
using OpenSSL
using Sockets
using MozillaCACerts_jll

# Verifies calling into OpenSSL library.
@testset "OpenSSL" begin
    @test OpenSSL.OPEN_SSL_INIT.x.result == 1
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_create_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_destroy_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_read_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_write_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_puts_ptr != C_NULL
    @test OpenSSL.BIO_STREAM_CALLBACKS.x.on_bio_ctrl_ptr != C_NULL
end

file_handle = open(MozillaCACerts_jll.cacert)
pem = String(read(file_handle))
close(file_handle)

start_line = "==========\n"

cert = "-----BEGIN CERTIFICATE-----\nMIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx\nGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds\nb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV\nBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD\nVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa\nDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc\nTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb\nKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP\nc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX\ngzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF\nAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj\nY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG\nj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH\nhm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC\nX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n-----END CERTIFICATE-----"
certs_pem = split(pem, start_line; keepempty = false)
x509_cert = OpenSSL.X509Certificate(cert)
@show x509_cert
x509_name = OpenSSL.get_subject_name(x509_cert)
@show x509_name
@show OpenSSL.string(x509_name)


#@show OpenSSL.__init__()

cs = connect("www.nghttp2.org", 443)

ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
result = OpenSSL.set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION)

bio_read_write = OpenSSL.BIO(cs)

ssl = OpenSSL.SSL(ssl_ctx, bio_read_write, bio_read_write)
@show result = OpenSSL.connect(ssl)
@show OpenSSL.get_error()

# Create SSL stream.
ssl_stream = SSLStream(ssl)

r = "GET / HTTP/1.1\r\nHost: www.nghttp2.org\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"

#ssl_stream = connect("www.nghttp2.org", 80)

written = unsafe_write(ssl_stream, pointer(r), length(r))

@show eof(cs)
@show bytesavailable(cs)
#@show eof(ssl_stream)
#@show bytesavailable(ssl_stream)
res = read(ssl_stream)
@show String(res)
# Htt

