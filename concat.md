---
title: "mbuf.h"
symbol_kind: "intro"
decl_name: "mbuf.h"
items:
  - { name: mbuf_append.md }
  - { name: mbuf_append_and_free.md }
  - { name: mbuf_clear.md }
  - { name: mbuf_free.md }
  - { name: mbuf_init.md }
  - { name: mbuf_insert.md }
  - { name: mbuf_move.md }
  - { name: mbuf_remove.md }
  - { name: mbuf_resize.md }
  - { name: mbuf_trim.md }
  - { name: struct_mbuf.md }
---

Mbufs are mutable/growing memory buffers, like C++ strings.
Mbuf can append data to the end of a buffer or insert data into arbitrary
position in the middle of a buffer. The buffer grows automatically when
needed.

---
title: "mbuf_append()"
decl_name: "mbuf_append"
symbol_kind: "func"
signature: |
  size_t mbuf_append(struct mbuf *, const void *data, size_t data_size);
---

Appends data to the Mbuf.

Returns the number of bytes appended or 0 if out of memory. 

---
title: "mbuf_append_and_free()"
decl_name: "mbuf_append_and_free"
symbol_kind: "func"
signature: |
  size_t mbuf_append_and_free(struct mbuf *, void *data, size_t data_size);
---

Appends data to the Mbuf and frees it (data must be heap-allocated).

Returns the number of bytes appended or 0 if out of memory.
data is freed irrespective of return value. 

---
title: "mbuf_clear()"
decl_name: "mbuf_clear"
symbol_kind: "func"
signature: |
  void mbuf_clear(struct mbuf *);
---

Removes all the data from mbuf (if any). 

---
title: "mbuf_free()"
decl_name: "mbuf_free"
symbol_kind: "func"
signature: |
  void mbuf_free(struct mbuf *);
---

Frees the space allocated for the mbuffer and resets the mbuf structure. 

---
title: "mbuf_init()"
decl_name: "mbuf_init"
symbol_kind: "func"
signature: |
  void mbuf_init(struct mbuf *, size_t initial_capacity);
---

Initialises an Mbuf.
`initial_capacity` specifies the initial capacity of the mbuf. 

---
title: "mbuf_insert()"
decl_name: "mbuf_insert"
symbol_kind: "func"
signature: |
  size_t mbuf_insert(struct mbuf *, size_t, const void *, size_t);
---

Inserts data at a specified offset in the Mbuf.

Existing data will be shifted forwards and the buffer will
be grown if necessary.
Returns the number of bytes inserted. 

---
title: "mbuf_move()"
decl_name: "mbuf_move"
symbol_kind: "func"
signature: |
  void mbuf_move(struct mbuf *from, struct mbuf *to);
---

Moves the state from one mbuf to the other. 

---
title: "mbuf_remove()"
decl_name: "mbuf_remove"
symbol_kind: "func"
signature: |
  void mbuf_remove(struct mbuf *, size_t data_size);
---

Removes `data_size` bytes from the beginning of the buffer. 

---
title: "mbuf_resize()"
decl_name: "mbuf_resize"
symbol_kind: "func"
signature: |
  void mbuf_resize(struct mbuf *, size_t new_size);
---

Resizes an Mbuf.

If `new_size` is smaller than buffer's `len`, the
resize is not performed. 

---
title: "mbuf_trim()"
decl_name: "mbuf_trim"
symbol_kind: "func"
signature: |
  void mbuf_trim(struct mbuf *);
---

Shrinks an Mbuf by resizing its `size` to `len`. 

---
title: "struct mbuf"
decl_name: "struct mbuf"
symbol_kind: "struct"
signature: |
  struct mbuf {
    char *buf;   /* Buffer pointer */
    size_t len;  /* Data length. Data is located between offset 0 and len. */
    size_t size; /* Buffer size allocated by realloc(1). Must be >= len */
  };
---

Memory buffer descriptor 

---
title: "CoAP API reference"
symbol_kind: "intro"
decl_name: "mg_coap.h"
items:
  - { name: mg_coap_add_option.md }
  - { name: mg_coap_compose.md }
  - { name: mg_coap_free_options.md }
  - { name: mg_coap_parse.md }
  - { name: mg_coap_send_ack.md }
  - { name: mg_coap_send_message.md }
  - { name: mg_set_protocol_coap.md }
  - { name: struct_mg_coap_message.md }
  - { name: struct_mg_coap_option.md }
---

CoAP message format:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|Ver| T | TKL | Code | Message ID | Token (if any, TKL bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
| Options (if any) ...            |1 1 1 1 1 1 1 1| Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
```

---
title: "mg_coap_add_option()"
decl_name: "mg_coap_add_option"
symbol_kind: "func"
signature: |
  struct mg_coap_option *mg_coap_add_option(struct mg_coap_message *cm,
                                            uint32_t number, char *value,
                                            size_t len);
---

Adds a new option to mg_coap_message structure.
Returns pointer to the newly created option.
Note: options must be freed by using mg_coap_free_options 

---
title: "mg_coap_compose()"
decl_name: "mg_coap_compose"
symbol_kind: "func"
signature: |
  uint32_t mg_coap_compose(struct mg_coap_message *cm, struct mbuf *io);
---

Composes CoAP message from mg_coap_message structure.
This is a helper function.
Return value: see `mg_coap_send_message()` 

---
title: "mg_coap_free_options()"
decl_name: "mg_coap_free_options"
symbol_kind: "func"
signature: |
  void mg_coap_free_options(struct mg_coap_message *cm);
---

Frees the memory allocated for options.
If the cm parameter doesn't contain any option it does nothing. 

---
title: "mg_coap_parse()"
decl_name: "mg_coap_parse"
symbol_kind: "func"
signature: |
  uint32_t mg_coap_parse(struct mbuf *io, struct mg_coap_message *cm);
---

Parses CoAP message and fills mg_coap_message and returns cm->flags.
This is a helper function.

NOTE: usually CoAP works over UDP, so lack of data means format error.
But, in theory, it is possible to use CoAP over TCP (according to RFC)

The caller has to check results and treat COAP_NOT_ENOUGH_DATA according to
underlying protocol:

- in case of UDP COAP_NOT_ENOUGH_DATA means COAP_FORMAT_ERROR,
- in case of TCP client can try to receive more data

Return value: see `mg_coap_send_message()` 

---
title: "mg_coap_send_ack()"
decl_name: "mg_coap_send_ack"
symbol_kind: "func"
signature: |
  uint32_t mg_coap_send_ack(struct mg_connection *nc, uint16_t msg_id);
---

Composes CoAP acknowledgement from `mg_coap_message`
and sends it into `nc` connection.
Return value: see `mg_coap_send_message()` 

---
title: "mg_coap_send_message()"
decl_name: "mg_coap_send_message"
symbol_kind: "func"
signature: |
  uint32_t mg_coap_send_message(struct mg_connection *nc,
                                struct mg_coap_message *cm);
---

Composes a CoAP message from `mg_coap_message`
and sends it into `nc` connection.
Returns 0 on success. On error, it is a bitmask:

- `#define MG_COAP_ERROR 0x10000`
- `#define MG_COAP_FORMAT_ERROR (MG_COAP_ERROR | 0x20000)`
- `#define MG_COAP_IGNORE (MG_COAP_ERROR | 0x40000)`
- `#define MG_COAP_NOT_ENOUGH_DATA (MG_COAP_ERROR | 0x80000)`
- `#define MG_COAP_NETWORK_ERROR (MG_COAP_ERROR | 0x100000)` 

---
title: "mg_set_protocol_coap()"
decl_name: "mg_set_protocol_coap"
symbol_kind: "func"
signature: |
  int mg_set_protocol_coap(struct mg_connection *nc);
---

Sets CoAP protocol handler - triggers CoAP specific events. 

---
title: "struct mg_coap_message"
decl_name: "struct mg_coap_message"
symbol_kind: "struct"
signature: |
  struct mg_coap_message {
    uint32_t flags;
    uint8_t msg_type;
    uint8_t code_class;
    uint8_t code_detail;
    uint16_t msg_id;
    struct mg_str token;
    struct mg_coap_option *options;
    struct mg_str payload;
    struct mg_coap_option *optiomg_tail;
  };
---

CoAP message. See RFC 7252 for details. 

---
title: "struct mg_coap_option"
decl_name: "struct mg_coap_option"
symbol_kind: "struct"
signature: |
  struct mg_coap_option {
    struct mg_coap_option *next;
    uint32_t number;
    struct mg_str value;
  };
---

CoAP options.
Use mg_coap_add_option and mg_coap_free_options
for creation and destruction. 

---
title: "DNS API reference"
symbol_kind: "intro"
decl_name: "mg_dns.h"
items:
  - { name: mg_dns_copy_questions.md }
  - { name: mg_dns_encode_name.md }
  - { name: mg_dns_encode_record.md }
  - { name: mg_dns_insert_header.md }
  - { name: mg_dns_parse_record_data.md }
  - { name: mg_dns_uncompress_name.md }
  - { name: mg_parse_dns.md }
  - { name: mg_send_dns_query.md }
  - { name: mg_set_protocol_dns.md }
  - { name: struct_mg_dns_message.md }
  - { name: struct_mg_dns_resource_record.md }
---



---
title: "mg_dns_copy_questions()"
decl_name: "mg_dns_copy_questions"
symbol_kind: "func"
signature: |
  int mg_dns_copy_questions(struct mbuf *io, struct mg_dns_message *msg);
---

Appends already encoded questions from an existing message.

This is useful when generating a DNS reply message which includes
all question records.

Returns the number of appended bytes. 

---
title: "mg_dns_encode_name()"
decl_name: "mg_dns_encode_name"
symbol_kind: "func"
signature: |
  int mg_dns_encode_name(struct mbuf *io, const char *name, size_t len);
---

Encodes a DNS name. 

---
title: "mg_dns_encode_record()"
decl_name: "mg_dns_encode_record"
symbol_kind: "func"
signature: |
  int mg_dns_encode_record(struct mbuf *io, struct mg_dns_resource_record *rr,
                           const char *name, size_t nlen, const void *rdata,
                           size_t rlen);
---

Encodes and appends a DNS resource record to an IO buffer.

The record metadata is taken from the `rr` parameter, while the name and data
are taken from the parameters, encoded in the appropriate format depending on
record type and stored in the IO buffer. The encoded values might contain
offsets within the IO buffer. It's thus important that the IO buffer doesn't
get trimmed while a sequence of records are encoded while preparing a DNS
reply.

This function doesn't update the `name` and `rdata` pointers in the `rr`
struct because they might be invalidated as soon as the IO buffer grows
again.

Returns the number of bytes appended or -1 in case of error. 

---
title: "mg_dns_insert_header()"
decl_name: "mg_dns_insert_header"
symbol_kind: "func"
signature: |
  int mg_dns_insert_header(struct mbuf *io, size_t pos,
                           struct mg_dns_message *msg);
---

Inserts a DNS header to an IO buffer.

Returns the number of bytes inserted. 

---
title: "mg_dns_parse_record_data()"
decl_name: "mg_dns_parse_record_data"
symbol_kind: "func"
signature: |
  int mg_dns_parse_record_data(struct mg_dns_message *msg,
                               struct mg_dns_resource_record *rr, void *data,
                               size_t data_len);
---

Parses the record data from a DNS resource record.

 - A:     struct in_addr *ina
 - AAAA:  struct in6_addr *ina
 - CNAME: char buffer

Returns -1 on error.

TODO(mkm): MX 

---
title: "mg_dns_uncompress_name()"
decl_name: "mg_dns_uncompress_name"
symbol_kind: "func"
signature: |
  size_t mg_dns_uncompress_name(struct mg_dns_message *msg, struct mg_str *name,
                                char *dst, int dst_len);
---

Uncompresses a DNS compressed name.

The containing DNS message is required because of the compressed encoding
and reference suffixes present elsewhere in the packet.

If the name is less than `dst_len` characters long, the remainder
of `dst` is terminated with `\0` characters. Otherwise, `dst` is not
terminated.

If `dst_len` is 0 `dst` can be NULL.
Returns the uncompressed name length. 

---
title: "mg_parse_dns()"
decl_name: "mg_parse_dns"
symbol_kind: "func"
signature: |
  int mg_parse_dns(const char *buf, int len, struct mg_dns_message *msg);
---

Low-level: parses a DNS response. 

---
title: "mg_send_dns_query()"
decl_name: "mg_send_dns_query"
symbol_kind: "func"
signature: |
  void mg_send_dns_query(struct mg_connection *nc, const char *name,
                         int query_type);
---

Sends a DNS query to the remote end. 

---
title: "mg_set_protocol_dns()"
decl_name: "mg_set_protocol_dns"
symbol_kind: "func"
signature: |
  void mg_set_protocol_dns(struct mg_connection *nc);
---

Attaches a built-in DNS event handler to the given listening connection.

The DNS event handler parses the incoming UDP packets, treating them as DNS
requests. If an incoming packet gets successfully parsed by the DNS event
handler, a user event handler will receive an `MG_DNS_REQUEST` event, with
`ev_data` pointing to the parsed `struct mg_dns_message`.

See
[captive_dns_server](https://github.com/cesanta/mongoose/tree/master/examples/captive_dns_server)
example on how to handle DNS request and send DNS reply. 

---
title: "struct mg_dns_message"
decl_name: "struct mg_dns_message"
symbol_kind: "struct"
signature: |
  struct mg_dns_message {
    struct mg_str pkt; /* packet body */
    uint16_t flags;
    uint16_t transaction_id;
    int num_questions;
    int num_answers;
    struct mg_dns_resource_record questions[MG_MAX_DNS_QUESTIONS];
    struct mg_dns_resource_record answers[MG_MAX_DNS_ANSWERS];
  };
---

DNS message (request and response). 

---
title: "struct mg_dns_resource_record"
decl_name: "struct mg_dns_resource_record"
symbol_kind: "struct"
signature: |
  struct mg_dns_resource_record {
    struct mg_str name; /* buffer with compressed name */
    int rtype;
    int rclass;
    int ttl;
    enum mg_dns_resource_record_kind kind;
    struct mg_str rdata; /* protocol data (can be a compressed name) */
  };
---

DNS resource record. 

---
title: "DNS server API reference"
symbol_kind: "intro"
decl_name: "mg_dns_server.h"
items:
  - { name: mg_dns_create_reply.md }
  - { name: mg_dns_reply_record.md }
  - { name: mg_dns_send_reply.md }
---

Disabled by default; enable with `-DMG_ENABLE_DNS_SERVER`.

---
title: "mg_dns_create_reply()"
decl_name: "mg_dns_create_reply"
symbol_kind: "func"
signature: |
  struct mg_dns_reply mg_dns_create_reply(struct mbuf *io,
                                          struct mg_dns_message *msg);
---

Creates a DNS reply.

The reply will be based on an existing query message `msg`.
The query body will be appended to the output buffer.
"reply + recursion allowed" will be added to the message flags and the
message's num_answers will be set to 0.

Answer records can be appended with `mg_dns_send_reply` or by lower
level function defined in the DNS API.

In order to send a reply use `mg_dns_send_reply`.
It's possible to use a connection's send buffer as reply buffer,
and it will work for both UDP and TCP connections.

Example:

```c
reply = mg_dns_create_reply(&nc->send_mbuf, msg);
for (i = 0; i < msg->num_questions; i++) {
  rr = &msg->questions[i];
  if (rr->rtype == MG_DNS_A_RECORD) {
    mg_dns_reply_record(&reply, rr, 3600, &dummy_ip_addr, 4);
  }
}
mg_dns_send_reply(nc, &reply);
``` 

---
title: "mg_dns_reply_record()"
decl_name: "mg_dns_reply_record"
symbol_kind: "func"
signature: |
  int mg_dns_reply_record(struct mg_dns_reply *reply,
                          struct mg_dns_resource_record *question,
                          const char *name, int rtype, int ttl, const void *rdata,
                          size_t rdata_len);
---

Appends a DNS reply record to the IO buffer and to the DNS message.

The message's num_answers field will be incremented. It's the caller's duty
to ensure num_answers is properly initialised.

Returns -1 on error. 

---
title: "mg_dns_send_reply()"
decl_name: "mg_dns_send_reply"
symbol_kind: "func"
signature: |
  void mg_dns_send_reply(struct mg_connection *nc, struct mg_dns_reply *r);
---

Sends a DNS reply through a connection.

The DNS data is stored in an IO buffer pointed by reply structure in `r`.
This function mutates the content of that buffer in order to ensure that
the DNS header reflects the size and flags of the message, that might have
been updated either with `mg_dns_reply_record` or by direct manipulation of
`r->message`.

Once sent, the IO buffer will be trimmed unless the reply IO buffer
is the connection's send buffer and the connection is not in UDP mode. 

---
title: "Common API reference"
symbol_kind: "intro"
decl_name: "mg_http.h"
items:
  - { name: mg_connect_ws.md }
  - { name: mg_connect_ws_opt.md }
  - { name: mg_http_is_authorized.md }
  - { name: mg_http_send_digest_auth_request.md }
  - { name: mg_printf_websocket_frame.md }
  - { name: mg_send_websocket_frame.md }
  - { name: mg_send_websocket_framev.md }
  - { name: mg_send_websocket_handshake.md }
  - { name: mg_send_websocket_handshake2.md }
  - { name: mg_send_websocket_handshake3.md }
  - { name: mg_send_websocket_handshake3v.md }
  - { name: mg_set_protocol_http_websocket.md }
  - { name: mg_url_decode.md }
  - { name: struct_http_message.md }
  - { name: struct_mg_http_multipart_part.md }
  - { name: struct_mg_ssi_call_ctx.md }
  - { name: struct_websocket_message.md }
---



---
title: "mg_connect_ws()"
decl_name: "mg_connect_ws"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect_ws(struct mg_mgr *mgr,
                                      MG_CB(mg_event_handler_t event_handler,
                                            void *user_data);
---

Helper function that creates an outbound WebSocket connection.

`url` is a URL to connect to. It must be properly URL-encoded, e.g. have
no spaces, etc. By default, `mg_connect_ws()` sends Connection and
Host headers. `extra_headers` is an extra HTTP header to send, e.g.
`"User-Agent: my-app\r\n"`.
If `protocol` is not NULL, then a `Sec-WebSocket-Protocol` header is sent.

Examples:

```c
  nc1 = mg_connect_ws(mgr, ev_handler_1, "ws://echo.websocket.org", NULL,
                      NULL);
  nc2 = mg_connect_ws(mgr, ev_handler_1, "wss://echo.websocket.org", NULL,
                      NULL);
  nc3 = mg_connect_ws(mgr, ev_handler_1, "ws://api.cesanta.com",
                      "clubby.cesanta.com", NULL);
``` 

---
title: "mg_connect_ws_opt()"
decl_name: "mg_connect_ws_opt"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect_ws_opt(
      struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data);
---

Helper function that creates an outbound WebSocket connection

Mostly identical to `mg_connect_ws`, but allows to provide extra parameters
(for example, SSL parameters) 

---
title: "mg_http_is_authorized()"
decl_name: "mg_http_is_authorized"
symbol_kind: "func"
signature: |
  int mg_http_is_authorized(struct http_message *hm, struct mg_str path,
                            const char *domain, const char *passwords_file,
                            int flags);
---

Checks whether an http request is authorized. `domain` is the authentication
realm, `passwords_file` is a htdigest file (can be created e.g. with
`htdigest` utility). If either `domain` or `passwords_file` is NULL, this
function always returns 1; otherwise checks the authentication in the
http request and returns 1 only if there is a match; 0 otherwise. 

---
title: "mg_http_send_digest_auth_request()"
decl_name: "mg_http_send_digest_auth_request"
symbol_kind: "func"
signature: |
  void mg_http_send_digest_auth_request(struct mg_connection *c,
                                        const char *domain);
---

Sends 401 Unauthorized response. 

---
title: "mg_printf_websocket_frame()"
decl_name: "mg_printf_websocket_frame"
symbol_kind: "func"
signature: |
  void mg_printf_websocket_frame(struct mg_connection *nc, int op_and_flags,
                                 const char *fmt, ...);
---

Sends WebSocket frame to the remote end.

Like `mg_send_websocket_frame()`, but allows to create formatted messages
with `printf()`-like semantics. 

---
title: "mg_send_websocket_frame()"
decl_name: "mg_send_websocket_frame"
symbol_kind: "func"
signature: |
  void mg_send_websocket_frame(struct mg_connection *nc, int op_and_flags,
                               const void *data, size_t data_len);
---

Send WebSocket frame to the remote end.

`op_and_flags` specifies the frame's type. It's one of:

- WEBSOCKET_OP_CONTINUE
- WEBSOCKET_OP_TEXT
- WEBSOCKET_OP_BINARY
- WEBSOCKET_OP_CLOSE
- WEBSOCKET_OP_PING
- WEBSOCKET_OP_PONG

Orred with one of the flags:

- WEBSOCKET_DONT_FIN: Don't set the FIN flag on the frame to be sent.

`data` and `data_len` contain frame data. 

---
title: "mg_send_websocket_framev()"
decl_name: "mg_send_websocket_framev"
symbol_kind: "func"
signature: |
  void mg_send_websocket_framev(struct mg_connection *nc, int op_and_flags,
                                const struct mg_str *strings, int num_strings);
---

Like `mg_send_websocket_frame()`, but composes a single frame from multiple
buffers. 

---
title: "mg_send_websocket_handshake()"
decl_name: "mg_send_websocket_handshake"
symbol_kind: "func"
signature: |
  void mg_send_websocket_handshake(struct mg_connection *nc, const char *uri,
                                   const char *extra_headers);
---

Send websocket handshake to the server.

`nc` must be a valid connection, connected to a server. `uri` is an URI
to fetch, extra_headers` is extra HTTP headers to send or `NULL`.

This function is intended to be used by websocket client.

Note that the Host header is mandatory in HTTP/1.1 and must be
included in `extra_headers`. `mg_send_websocket_handshake2` offers
a better API for that.

Deprecated in favour of `mg_send_websocket_handshake2` 

---
title: "mg_send_websocket_handshake2()"
decl_name: "mg_send_websocket_handshake2"
symbol_kind: "func"
signature: |
  void mg_send_websocket_handshake2(struct mg_connection *nc, const char *path,
                                    const char *host, const char *protocol,
                                    const char *extra_headers);
---

Send websocket handshake to the server.

`nc` must be a valid connection, connected to a server. `uri` is an URI
to fetch, `host` goes into the `Host` header, `protocol` goes into the
`Sec-WebSocket-Proto` header (NULL to omit), extra_headers` is extra HTTP
headers to send or `NULL`.

This function is intended to be used by websocket client. 

---
title: "mg_send_websocket_handshake3()"
decl_name: "mg_send_websocket_handshake3"
symbol_kind: "func"
signature: |
  void mg_send_websocket_handshake3(struct mg_connection *nc, const char *path,
                                    const char *host, const char *protocol,
                                    const char *extra_headers, const char *user,
                                    const char *pass);
---

Like mg_send_websocket_handshake2 but also passes basic auth header 

---
title: "mg_send_websocket_handshake3v()"
decl_name: "mg_send_websocket_handshake3v"
symbol_kind: "func"
signature: |
  void mg_send_websocket_handshake3v(struct mg_connection *nc,
                                     const struct mg_str path,
                                     const struct mg_str host,
                                     const struct mg_str protocol,
                                     const struct mg_str extra_headers,
                                     const struct mg_str user,
                                     const struct mg_str pass);
---

Same as mg_send_websocket_handshake3 but with strings not necessarily
NUL-temrinated 

---
title: "mg_set_protocol_http_websocket()"
decl_name: "mg_set_protocol_http_websocket"
symbol_kind: "func"
signature: |
  void mg_set_protocol_http_websocket(struct mg_connection *nc);
---

Attaches a built-in HTTP event handler to the given connection.
The user-defined event handler will receive following extra events:

- MG_EV_HTTP_REQUEST: HTTP request has arrived. Parsed HTTP request
 is passed as
  `struct http_message` through the handler's `void *ev_data` pointer.
- MG_EV_HTTP_REPLY: The HTTP reply has arrived. The parsed HTTP reply is
  passed as `struct http_message` through the handler's `void *ev_data`
  pointer.
- MG_EV_HTTP_CHUNK: The HTTP chunked-encoding chunk has arrived.
  The parsed HTTP reply is passed as `struct http_message` through the
  handler's `void *ev_data` pointer. `http_message::body` would contain
  incomplete, reassembled HTTP body.
  It will grow with every new chunk that arrives, and it can
  potentially consume a lot of memory. An event handler may process
  the body as chunks are coming, and signal Mongoose to delete processed
  body by setting `MG_F_DELETE_CHUNK` in `mg_connection::flags`. When
  the last zero chunk is received,
  Mongoose sends `MG_EV_HTTP_REPLY` event with
  full reassembled body (if handler did not signal to delete chunks) or
  with empty body (if handler did signal to delete chunks).
- MG_EV_WEBSOCKET_HANDSHAKE_REQUEST: server has received the WebSocket
  handshake request. `ev_data` contains parsed HTTP request.
- MG_EV_WEBSOCKET_HANDSHAKE_DONE: server has completed the WebSocket
  handshake. `ev_data` is a `struct http_message` containing the
  client's request (server mode) or server's response (client).
  In client mode handler can examine `resp_code`, which should be 101.
- MG_EV_WEBSOCKET_FRAME: new WebSocket frame has arrived. `ev_data` is
  `struct websocket_message *`

When compiled with MG_ENABLE_HTTP_STREAMING_MULTIPART, Mongoose parses
multipart requests and splits them into separate events:
- MG_EV_HTTP_MULTIPART_REQUEST: Start of the request.
  This event is sent before body is parsed. After this, the user
  should expect a sequence of PART_BEGIN/DATA/END requests.
  This is also the last time when headers and other request fields are
  accessible.
- MG_EV_HTTP_PART_BEGIN: Start of a part of a multipart message.
  Argument: mg_http_multipart_part with var_name and file_name set
  (if present). No data is passed in this message.
- MG_EV_HTTP_PART_DATA: new portion of data from the multipart message.
  Argument: mg_http_multipart_part. var_name and file_name are preserved,
  data is available in mg_http_multipart_part.data.
- MG_EV_HTTP_PART_END: End of the current part. var_name, file_name are
  the same, no data in the message. If status is 0, then the part is
  properly terminated with a boundary, status < 0 means that connection
  was terminated.
- MG_EV_HTTP_MULTIPART_REQUEST_END: End of the multipart request.
  Argument: mg_http_multipart_part, var_name and file_name are NULL,
  status = 0 means request was properly closed, < 0 means connection
  was terminated (note: in this case both PART_END and REQUEST_END are
  delivered). 

---
title: "mg_url_decode()"
decl_name: "mg_url_decode"
symbol_kind: "func"
signature: |
  int mg_url_decode(const char *src, int src_len, char *dst, int dst_len,
                    int is_form_url_encoded);
---

Decodes a URL-encoded string.

Source string is specified by (`src`, `src_len`), and destination is
(`dst`, `dst_len`). If `is_form_url_encoded` is non-zero, then
`+` character is decoded as a blank space character. This function
guarantees to NUL-terminate the destination. If destination is too small,
then the source string is partially decoded and `-1` is returned.
*Otherwise,
a length of the decoded string is returned, not counting final NUL. 

---
title: "struct http_message"
decl_name: "struct http_message"
symbol_kind: "struct"
signature: |
  struct http_message {
    struct mg_str message; /* Whole message: request line + headers + body */
    struct mg_str body;    /* Message body. 0-length for requests with no body */
  
    /* HTTP Request line (or HTTP response line) */
    struct mg_str method; /* "GET" */
    struct mg_str uri;    /* "/my_file.html" */
    struct mg_str proto;  /* "HTTP/1.1" -- for both request and response */
  
    /* For responses, code and response status message are set */
    int resp_code;
    struct mg_str resp_status_msg;
  
    /*
     * Query-string part of the URI. For example, for HTTP request
     *    GET /foo/bar?param1=val1&param2=val2
     *    |    uri    |     query_string     |
     *
     * Note that question mark character doesn't belong neither to the uri,
     * nor to the query_string
     */
    struct mg_str query_string;
  
    /* Headers */
    struct mg_str header_names[MG_MAX_HTTP_HEADERS];
    struct mg_str header_values[MG_MAX_HTTP_HEADERS];
  };
---

HTTP message 

---
title: "struct mg_http_multipart_part"
decl_name: "struct mg_http_multipart_part"
symbol_kind: "struct"
signature: |
  struct mg_http_multipart_part {
    const char *file_name;
    const char *var_name;
    struct mg_str data;
    int status; /* <0 on error */
    void *user_data;
    /*
     * User handler can indicate how much of the data was consumed
     * by setting this variable. By default, it is assumed that all
     * data has been consumed by the handler.
     * If not all data was consumed, user's handler will be invoked again later
     * with the remainder.
     */
    size_t num_data_consumed;
  };
---

HTTP multipart part 

---
title: "struct mg_ssi_call_ctx"
decl_name: "struct mg_ssi_call_ctx"
symbol_kind: "struct"
signature: |
  struct mg_ssi_call_ctx {
    struct http_message *req; /* The request being processed. */
    struct mg_str file;       /* Filesystem path of the file being processed. */
    struct mg_str arg; /* The argument passed to the tag: <!-- call arg -->. */
  };
---

SSI call context 

---
title: "struct websocket_message"
decl_name: "struct websocket_message"
symbol_kind: "struct"
signature: |
  struct websocket_message {
    unsigned char *data;
    size_t size;
    unsigned char flags;
  };
---

WebSocket message 

---
title: "Client API reference"
symbol_kind: "intro"
decl_name: "mg_http_client.h"
items:
  - { name: mg_connect_http.md }
  - { name: mg_connect_http_opt.md }
  - { name: mg_http_create_digest_auth_header.md }
---



---
title: "mg_connect_http()"
decl_name: "mg_connect_http"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect_http(
      struct mg_mgr *mgr,
      MG_CB(mg_event_handler_t event_handler, void *user_data);
---

Helper function that creates an outbound HTTP connection.

`url` is the URL to fetch. It must be properly URL-encoded, e.g. have
no spaces, etc. By default, `mg_connect_http()` sends the Connection and
Host headers. `extra_headers` is an extra HTTP header to send, e.g.
`"User-Agent: my-app\r\n"`.
If `post_data` is NULL, then a GET request is created. Otherwise, a POST
request is created with the specified POST data. Note that if the data being
posted is a form submission, the `Content-Type` header should be set
accordingly (see example below).

Examples:

```c
  nc1 = mg_connect_http(mgr, ev_handler_1, "http://www.google.com", NULL,
                        NULL);
  nc2 = mg_connect_http(mgr, ev_handler_1, "https://github.com", NULL, NULL);
  nc3 = mg_connect_http(
      mgr, ev_handler_1, "my_server:8000/form_submit/",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "var_1=value_1&var_2=value_2");
``` 

---
title: "mg_connect_http_opt()"
decl_name: "mg_connect_http_opt"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect_http_opt(
      struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data);
---

Helper function that creates an outbound HTTP connection.

Mostly identical to mg_connect_http, but allows you to provide extra
*parameters
(for example, SSL parameters) 

---
title: "mg_http_create_digest_auth_header()"
decl_name: "mg_http_create_digest_auth_header"
symbol_kind: "func"
signature: |
  int mg_http_create_digest_auth_header(char *buf, size_t buf_len,
                                        const char *method, const char *uri,
                                        const char *auth_domain, const char *user,
                                        const char *passwd, const char *nonce);
---

Creates digest authentication header for a client request. 

---
title: "Server API reference"
symbol_kind: "intro"
decl_name: "mg_http_server.h"
items:
  - { name: mg_check_digest_auth.md }
  - { name: mg_file_upload_handler.md }
  - { name: mg_get_http_basic_auth.md }
  - { name: mg_get_http_header.md }
  - { name: mg_get_http_var.md }
  - { name: mg_http_check_digest_auth.md }
  - { name: mg_http_parse_header.md }
  - { name: mg_http_parse_header2.md }
  - { name: mg_http_reverse_proxy.md }
  - { name: mg_http_send_error.md }
  - { name: mg_http_send_redirect.md }
  - { name: mg_http_serve_file.md }
  - { name: mg_parse_http.md }
  - { name: mg_parse_http_basic_auth.md }
  - { name: mg_parse_multipart.md }
  - { name: mg_printf_html_escape.md }
  - { name: mg_printf_http_chunk.md }
  - { name: mg_register_http_endpoint.md }
  - { name: mg_send_head.md }
  - { name: mg_send_http_chunk.md }
  - { name: mg_send_response_line.md }
  - { name: mg_serve_http.md }
  - { name: mg_fu_fname_fn.md }
  - { name: struct_mg_serve_http_opts.md }
---



---
title: "mg_check_digest_auth()"
decl_name: "mg_check_digest_auth"
symbol_kind: "func"
signature: |
  int mg_check_digest_auth(struct mg_str method, struct mg_str uri,
                           struct mg_str username, struct mg_str cnonce,
                           struct mg_str response, struct mg_str qop,
                           struct mg_str nc, struct mg_str nonce,
                           struct mg_str auth_domain, FILE *fp);
---

Authenticates given response params against an opened password file.
Returns 1 if authenticated, 0 otherwise.

It's used by mg_http_check_digest_auth(). 

---
title: "mg_file_upload_handler()"
decl_name: "mg_file_upload_handler"
symbol_kind: "func"
signature: |
  void mg_file_upload_handler(struct mg_connection *nc, int ev, void *ev_data,
                              mg_fu_fname_fn local_name_fn
                                  MG_UD_ARG(void *user_data);
---

File upload handler.
This handler can be used to implement file uploads with minimum code.
This handler will process MG_EV_HTTP_PART_* events and store file data into
a local file.
`local_name_fn` will be invoked with whatever name was provided by the client
and will expect the name of the local file to open. A return value of NULL
will abort file upload (client will get a "403 Forbidden" response). If
non-null, the returned string must be heap-allocated and will be freed by
the caller.
Exception: it is ok to return the same string verbatim.

Example:

```c
struct mg_str upload_fname(struct mg_connection *nc, struct mg_str fname) {
  // Just return the same filename. Do not actually do this except in test!
  // fname is user-controlled and needs to be sanitized.
  return fname;
}
void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  switch (ev) {
    ...
    case MG_EV_HTTP_PART_BEGIN:
    case MG_EV_HTTP_PART_DATA:
    case MG_EV_HTTP_PART_END:
      mg_file_upload_handler(nc, ev, ev_data, upload_fname);
      break;
  }
}
``` 

---
title: "mg_fu_fname_fn"
decl_name: "mg_fu_fname_fn"
symbol_kind: "typedef"
signature: |
  typedef struct mg_str (*mg_fu_fname_fn)(struct mg_connection *nc,
                                          struct mg_str fname);
---

Callback prototype for `mg_file_upload_handler()`. 

---
title: "mg_get_http_basic_auth()"
decl_name: "mg_get_http_basic_auth"
symbol_kind: "func"
signature: |
  int mg_get_http_basic_auth(struct http_message *hm, char *user, size_t user_len,
                             char *pass, size_t pass_len);
---

Gets and parses the Authorization: Basic header
Returns -1 if no Authorization header is found, or if
mg_parse_http_basic_auth
fails parsing the resulting header. 

---
title: "mg_get_http_header()"
decl_name: "mg_get_http_header"
symbol_kind: "func"
signature: |
  struct mg_str *mg_get_http_header(struct http_message *hm, const char *name);
---

Searches and returns the header `name` in parsed HTTP message `hm`.
If header is not found, NULL is returned. Example:

    struct mg_str *host_hdr = mg_get_http_header(hm, "Host"); 

---
title: "mg_get_http_var()"
decl_name: "mg_get_http_var"
symbol_kind: "func"
signature: |
  int mg_get_http_var(const struct mg_str *buf, const char *name, char *dst,
                      size_t dst_len);
---

Fetches a HTTP form variable.

Fetches a variable `name` from a `buf` into a buffer specified by `dst`,
`dst_len`. The destination is always zero-terminated. Returns the length of
a fetched variable. If not found, 0 is returned. `buf` must be valid
url-encoded buffer. If destination is too small or an error occured,
negative number is returned. 

---
title: "mg_http_check_digest_auth()"
decl_name: "mg_http_check_digest_auth"
symbol_kind: "func"
signature: |
  int mg_http_check_digest_auth(struct http_message *hm, const char *auth_domain,
                                FILE *fp);
---

Authenticates a HTTP request against an opened password file.
Returns 1 if authenticated, 0 otherwise. 

---
title: "mg_http_parse_header()"
decl_name: "mg_http_parse_header"
symbol_kind: "func"
signature: |
  int mg_http_parse_header(struct mg_str *hdr, const char *var_name, char *buf,
                           size_t buf_size);
---

DEPRECATED: use mg_http_parse_header2() instead.

Same as mg_http_parse_header2(), but takes buffer as a `char *` (instead of
`char **`), and thus it cannot allocate a new buffer if the provided one
is not enough, and just returns 0 in that case. 

---
title: "mg_http_parse_header2()"
decl_name: "mg_http_parse_header2"
symbol_kind: "func"
signature: |
  int mg_http_parse_header2(struct mg_str *hdr, const char *var_name, char **buf,
                            size_t buf_size);
---

Parses the HTTP header `hdr`. Finds variable `var_name` and stores its value
in the buffer `*buf`, `buf_size`. If the buffer size is not enough,
allocates a buffer of required size and writes it to `*buf`, similar to
asprintf(). The caller should always check whether the buffer was updated,
and free it if so.

This function is supposed to parse cookies, authentication headers, etc.
Example (error handling omitted):

    char user_buf[20];
    char *user = user_buf;
    struct mg_str *hdr = mg_get_http_header(hm, "Authorization");
    mg_http_parse_header2(hdr, "username", &user, sizeof(user_buf));
    // ... do something useful with user
    if (user != user_buf) {
      free(user);
    }

Returns the length of the variable's value. If variable is not found, 0 is
returned. 

---
title: "mg_http_reverse_proxy()"
decl_name: "mg_http_reverse_proxy"
symbol_kind: "func"
signature: |
  void mg_http_reverse_proxy(struct mg_connection *nc,
                             const struct http_message *hm, struct mg_str mount,
                             struct mg_str upstream);
---

Proxies a given request to a given upstream http server. The path prefix
in `mount` will be stripped of the path requested to the upstream server,
e.g. if mount is /api and upstream is http://localhost:8001/foo
then an incoming request to /api/bar will cause a request to
http://localhost:8001/foo/bar

EXPERIMENTAL API. Please use http_serve_http + url_rewrites if a static
mapping is good enough. 

---
title: "mg_http_send_error()"
decl_name: "mg_http_send_error"
symbol_kind: "func"
signature: |
  void mg_http_send_error(struct mg_connection *nc, int code, const char *reason);
---

Sends an error response. If reason is NULL, the message will be inferred
from the error code (if supported). 

---
title: "mg_http_send_redirect()"
decl_name: "mg_http_send_redirect"
symbol_kind: "func"
signature: |
  void mg_http_send_redirect(struct mg_connection *nc, int status_code,
                             const struct mg_str location,
                             const struct mg_str extra_headers);
---

Sends a redirect response.
`status_code` should be either 301 or 302 and `location` point to the
new location.
If `extra_headers` is not empty, then `extra_headers` are also sent
after the response line. `extra_headers` must NOT end end with new line.

Example:

     mg_http_send_redirect(nc, 302, mg_mk_str("/login"), mg_mk_str(NULL)); 

---
title: "mg_http_serve_file()"
decl_name: "mg_http_serve_file"
symbol_kind: "func"
signature: |
  void mg_http_serve_file(struct mg_connection *nc, struct http_message *hm,
                          const char *path, const struct mg_str mime_type,
                          const struct mg_str extra_headers);
---

Serves a specific file with a given MIME type and optional extra headers.

Example code snippet:

```c
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  switch (ev) {
    case MG_EV_HTTP_REQUEST: {
      struct http_message *hm = (struct http_message *) ev_data;
      mg_http_serve_file(nc, hm, "file.txt",
                         mg_mk_str("text/plain"), mg_mk_str(""));
      break;
    }
    ...
  }
}
``` 

---
title: "mg_parse_http()"
decl_name: "mg_parse_http"
symbol_kind: "func"
signature: |
  int mg_parse_http(const char *s, int n, struct http_message *hm, int is_req);
---

Parses a HTTP message.

`is_req` should be set to 1 if parsing a request, 0 if reply.

Returns the number of bytes parsed. If HTTP message is
incomplete `0` is returned. On parse error, a negative number is returned. 

---
title: "mg_parse_http_basic_auth()"
decl_name: "mg_parse_http_basic_auth"
symbol_kind: "func"
signature: |
  int mg_parse_http_basic_auth(struct mg_str *hdr, char *user, size_t user_len,
                               char *pass, size_t pass_len);
---

Parses the Authorization: Basic header
Returns -1 iif the authorization type is not "Basic" or any other error such
as incorrectly encoded base64 user password pair. 

---
title: "mg_parse_multipart()"
decl_name: "mg_parse_multipart"
symbol_kind: "func"
signature: |
  size_t mg_parse_multipart(const char *buf, size_t buf_len, char *var_name,
                            size_t var_name_len, char *file_name,
                            size_t file_name_len, const char **chunk,
                            size_t *chunk_len);
---

Parses the buffer `buf`, `buf_len` that contains multipart form data chunks.
Stores the chunk name in a `var_name`, `var_name_len` buffer.
If a chunk is an uploaded file, then `file_name`, `file_name_len` is
filled with an uploaded file name. `chunk`, `chunk_len`
points to the chunk data.

Return: number of bytes to skip to the next chunk or 0 if there are
        no more chunks.

Usage example:

```c
   static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
     switch(ev) {
       case MG_EV_HTTP_REQUEST: {
         struct http_message *hm = (struct http_message *) ev_data;
         char var_name[100], file_name[100];
         const char *chunk;
         size_t chunk_len, n1, n2;

         n1 = n2 = 0;
         while ((n2 = mg_parse_multipart(hm->body.p + n1,
                                         hm->body.len - n1,
                                         var_name, sizeof(var_name),
                                         file_name, sizeof(file_name),
                                         &chunk, &chunk_len)) > 0) {
           printf("var: %s, file_name: %s, size: %d, chunk: [%.*s]\n",
                  var_name, file_name, (int) chunk_len,
                  (int) chunk_len, chunk);
           n1 += n2;
         }
       }
       break;
``` 

---
title: "mg_printf_html_escape()"
decl_name: "mg_printf_html_escape"
symbol_kind: "func"
signature: |
  void mg_printf_html_escape(struct mg_connection *nc, const char *fmt, ...);
---

Sends a printf-formatted HTTP chunk, escaping HTML tags. 

---
title: "mg_printf_http_chunk()"
decl_name: "mg_printf_http_chunk"
symbol_kind: "func"
signature: |
  void mg_printf_http_chunk(struct mg_connection *nc, const char *fmt, ...);
---

Sends a printf-formatted HTTP chunk.
Functionality is similar to `mg_send_http_chunk()`. 

---
title: "mg_register_http_endpoint()"
decl_name: "mg_register_http_endpoint"
symbol_kind: "func"
signature: |
  void mg_register_http_endpoint(struct mg_connection *nc, const char *uri_path,
                                 MG_CB(mg_event_handler_t handler,
                                       void *user_data);
---

Registers a callback for a specified http endpoint
Note: if callback is registered it is called instead of the
callback provided in mg_bind

Example code snippet:

```c
static void handle_hello1(struct mg_connection *nc, int ev, void *ev_data) {
  (void) ev; (void) ev_data;
  mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[I am Hello1]");
 nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void handle_hello2(struct mg_connection *nc, int ev, void *ev_data) {
 (void) ev; (void) ev_data;
  mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[I am Hello2]");
 nc->flags |= MG_F_SEND_AND_CLOSE;
}

void init() {
  nc = mg_bind(&mgr, local_addr, cb1);
  mg_register_http_endpoint(nc, "/hello1", handle_hello1);
  mg_register_http_endpoint(nc, "/hello1/hello2", handle_hello2);
}
``` 

---
title: "mg_send_head()"
decl_name: "mg_send_head"
symbol_kind: "func"
signature: |
  void mg_send_head(struct mg_connection *n, int status_code,
                    int64_t content_length, const char *extra_headers);
---

Sends the response line and headers.
This function sends the response line with the `status_code`, and
automatically
sends one header: either "Content-Length" or "Transfer-Encoding".
If `content_length` is negative, then "Transfer-Encoding: chunked" header
is sent, otherwise, "Content-Length" header is sent.

NOTE: If `Transfer-Encoding` is `chunked`, then message body must be sent
using `mg_send_http_chunk()` or `mg_printf_http_chunk()` functions.
Otherwise, `mg_send()` or `mg_printf()` must be used.
Extra headers could be set through `extra_headers`. Note `extra_headers`
must NOT be terminated by a new line. 

---
title: "mg_send_http_chunk()"
decl_name: "mg_send_http_chunk"
symbol_kind: "func"
signature: |
  void mg_send_http_chunk(struct mg_connection *nc, const char *buf, size_t len);
---

Sends buffer `buf` of size `len` to the client using chunked HTTP encoding.
This function sends the buffer size as hex number + newline first, then
the buffer itself, then the newline. For example,
`mg_send_http_chunk(nc, "foo", 3)` will append the `3\r\nfoo\r\n` string
to the `nc->send_mbuf` output IO buffer.

NOTE: The HTTP header "Transfer-Encoding: chunked" should be sent prior to
using this function.

NOTE: do not forget to send an empty chunk at the end of the response,
to tell the client that everything was sent. Example:

```
  mg_printf_http_chunk(nc, "%s", "my response!");
  mg_send_http_chunk(nc, "", 0); // Tell the client we're finished
``` 

---
title: "mg_send_response_line()"
decl_name: "mg_send_response_line"
symbol_kind: "func"
signature: |
  void mg_send_response_line(struct mg_connection *nc, int status_code,
                             const char *extra_headers);
---

Sends the response status line.
If `extra_headers` is not NULL, then `extra_headers` are also sent
after the response line. `extra_headers` must NOT end end with new line.
Example:

     mg_send_response_line(nc, 200, "Access-Control-Allow-Origin: *");

Will result in:

     HTTP/1.1 200 OK\r\n
     Access-Control-Allow-Origin: *\r\n 

---
title: "mg_serve_http()"
decl_name: "mg_serve_http"
symbol_kind: "func"
signature: |
  void mg_serve_http(struct mg_connection *nc, struct http_message *hm,
                     struct mg_serve_http_opts opts);
---

Serves given HTTP request according to the `options`.

Example code snippet:

```c
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  struct mg_serve_http_opts opts = { .document_root = "/var/www" };  // C99

  switch (ev) {
    case MG_EV_HTTP_REQUEST:
      mg_serve_http(nc, hm, opts);
      break;
    default:
      break;
  }
}
``` 

---
title: "struct mg_serve_http_opts"
decl_name: "struct mg_serve_http_opts"
symbol_kind: "struct"
signature: |
  struct mg_serve_http_opts {
    /* Path to web root directory */
    const char *document_root;
  
    /* List of index files. Default is "" */
    const char *index_files;
  
    /*
     * Leave as NULL to disable authentication.
     * To enable directory protection with authentication, set this to ".htpasswd"
     * Then, creating ".htpasswd" file in any directory automatically protects
     * it with digest authentication.
     * Use `mongoose` web server binary, or `htdigest` Apache utility to
     * create/manipulate passwords file.
     * Make sure `auth_domain` is set to a valid domain name.
     */
    const char *per_directory_auth_file;
  
    /* Authorization domain (domain name of this web server) */
    const char *auth_domain;
  
    /*
     * Leave as NULL to disable authentication.
     * Normally, only selected directories in the document root are protected.
     * If absolutely every access to the web server needs to be authenticated,
     * regardless of the URI, set this option to the path to the passwords file.
     * Format of that file is the same as ".htpasswd" file. Make sure that file
     * is located outside document root to prevent people fetching it.
     */
    const char *global_auth_file;
  
    /* Set to "no" to disable directory listing. Enabled by default. */
    const char *enable_directory_listing;
  
    /*
     * SSI files pattern. If not set, "**.shtml$|**.shtm$" is used.
     *
     * All files that match ssi_pattern are treated as SSI.
     *
     * Server Side Includes (SSI) is a simple interpreted server-side scripting
     * language which is most commonly used to include the contents of a file
     * into a web page. It can be useful when it is desirable to include a common
     * piece of code throughout a website, for example, headers and footers.
     *
     * In order for a webpage to recognize an SSI-enabled HTML file, the
     * filename should end with a special extension, by default the extension
     * should be either .shtml or .shtm
     *
     * Unknown SSI directives are silently ignored by Mongoose. Currently,
     * the following SSI directives are supported:
     *    &lt;!--#include FILE_TO_INCLUDE --&gt;
     *    &lt;!--#exec "COMMAND_TO_EXECUTE" --&gt;
     *    &lt;!--#call COMMAND --&gt;
     *
     * Note that &lt;!--#include ...> directive supports three path
     *specifications:
     *
     * &lt;!--#include virtual="path" --&gt;  Path is relative to web server root
     * &lt;!--#include abspath="path" --&gt;  Path is absolute or relative to the
     *                                  web server working dir
     * &lt;!--#include file="path" --&gt;,    Path is relative to current document
     * &lt;!--#include "path" --&gt;
     *
     * The include directive may be used to include the contents of a file or
     * the result of running a CGI script.
     *
     * The exec directive is used to execute
     * a command on a server, and show command's output. Example:
     *
     * &lt;!--#exec "ls -l" --&gt;
     *
     * The call directive is a way to invoke a C handler from the HTML page.
     * On each occurence of &lt;!--#call COMMAND OPTIONAL_PARAMS> directive,
     * Mongoose calls a registered event handler with MG_EV_SSI_CALL event,
     * and event parameter will point to the COMMAND OPTIONAL_PARAMS string.
     * An event handler can output any text, for example by calling
     * `mg_printf()`. This is a flexible way of generating a web page on
     * server side by calling a C event handler. Example:
     *
     * &lt;!--#call foo --&gt; ... &lt;!--#call bar --&gt;
     *
     * In the event handler:
     *    case MG_EV_SSI_CALL: {
     *      const char *param = (const char *) ev_data;
     *      if (strcmp(param, "foo") == 0) {
     *        mg_printf(c, "hello from foo");
     *      } else if (strcmp(param, "bar") == 0) {
     *        mg_printf(c, "hello from bar");
     *      }
     *      break;
     *    }
     */
    const char *ssi_pattern;
  
    /* IP ACL. By default, NULL, meaning all IPs are allowed to connect */
    const char *ip_acl;
  
  #if MG_ENABLE_HTTP_URL_REWRITES
    /* URL rewrites.
     *
     * Comma-separated list of `uri_pattern=url_file_or_directory_path` rewrites.
     * When HTTP request is received, Mongoose constructs a file name from the
     * requested URI by combining `document_root` and the URI. However, if the
     * rewrite option is used and `uri_pattern` matches requested URI, then
     * `document_root` is ignored. Instead, `url_file_or_directory_path` is used,
     * which should be a full path name or a path relative to the web server's
     * current working directory. It can also be an URI (http:// or https://)
     * in which case mongoose will behave as a reverse proxy for that destination.
     *
     * Note that `uri_pattern`, as all Mongoose patterns, is a prefix pattern.
     *
     * If uri_pattern starts with `@` symbol, then Mongoose compares it with the
     * HOST header of the request. If they are equal, Mongoose sets document root
     * to `file_or_directory_path`, implementing virtual hosts support.
     * Example: `@foo.com=/document/root/for/foo.com`
     *
     * If `uri_pattern` starts with `%` symbol, then Mongoose compares it with
     * the listening port. If they match, then Mongoose issues a 301 redirect.
     * For example, to redirect all HTTP requests to the
     * HTTPS port, do `%80=https://my.site.com`. Note that the request URI is
     * automatically appended to the redirect location.
     */
    const char *url_rewrites;
  #endif
  
    /* DAV document root. If NULL, DAV requests are going to fail. */
    const char *dav_document_root;
  
    /*
     * DAV passwords file. If NULL, DAV requests are going to fail.
     * If passwords file is set to "-", then DAV auth is disabled.
     */
    const char *dav_auth_file;
  
    /* Glob pattern for the files to hide. */
    const char *hidden_file_pattern;
  
    /* Set to non-NULL to enable CGI, e.g. **.cgi$|**.php$" */
    const char *cgi_file_pattern;
  
    /* If not NULL, ignore CGI script hashbang and use this interpreter */
    const char *cgi_interpreter;
  
    /*
     * Comma-separated list of Content-Type overrides for path suffixes, e.g.
     * ".txt=text/plain; charset=utf-8,.c=text/plain"
     */
    const char *custom_mime_types;
  
    /*
     * Extra HTTP headers to add to each server response.
     * Example: to enable CORS, set this to "Access-Control-Allow-Origin: *".
     */
    const char *extra_headers;
  };
---

This structure defines how `mg_serve_http()` works.
Best practice is to set only required settings, and leave the rest as NULL. 

---
title: "MQTT API reference"
symbol_kind: "intro"
decl_name: "mg_mqtt.h"
items:
  - { name: mg_mqtt_connack.md }
  - { name: mg_mqtt_disconnect.md }
  - { name: mg_mqtt_match_topic_expression.md }
  - { name: mg_mqtt_next_subscribe_topic.md }
  - { name: mg_mqtt_ping.md }
  - { name: mg_mqtt_pong.md }
  - { name: mg_mqtt_puback.md }
  - { name: mg_mqtt_pubcomp.md }
  - { name: mg_mqtt_publish.md }
  - { name: mg_mqtt_pubrec.md }
  - { name: mg_mqtt_pubrel.md }
  - { name: mg_mqtt_suback.md }
  - { name: mg_mqtt_subscribe.md }
  - { name: mg_mqtt_unsuback.md }
  - { name: mg_mqtt_unsubscribe.md }
  - { name: mg_mqtt_vmatch_topic_expression.md }
  - { name: mg_send_mqtt_handshake.md }
  - { name: mg_send_mqtt_handshake_opt.md }
  - { name: mg_set_protocol_mqtt.md }
  - { name: struct_mg_mqtt_proto_data.md }
---



---
title: "mg_mqtt_connack()"
decl_name: "mg_mqtt_connack"
symbol_kind: "func"
signature: |
  void mg_mqtt_connack(struct mg_connection *nc, uint8_t return_code);
---

Sends a CONNACK command with a given `return_code`. 

---
title: "mg_mqtt_disconnect()"
decl_name: "mg_mqtt_disconnect"
symbol_kind: "func"
signature: |
  void mg_mqtt_disconnect(struct mg_connection *nc);
---

Sends a DISCONNECT command. 

---
title: "mg_mqtt_match_topic_expression()"
decl_name: "mg_mqtt_match_topic_expression"
symbol_kind: "func"
signature: |
  int mg_mqtt_match_topic_expression(struct mg_str exp, struct mg_str topic);
---

Matches a topic against a topic expression

Returns 1 if it matches; 0 otherwise. 

---
title: "mg_mqtt_next_subscribe_topic()"
decl_name: "mg_mqtt_next_subscribe_topic"
symbol_kind: "func"
signature: |
  int mg_mqtt_next_subscribe_topic(struct mg_mqtt_message *msg,
                                   struct mg_str *topic, uint8_t *qos, int pos);
---

Extracts the next topic expression from a SUBSCRIBE command payload.

The topic expression name will point to a string in the payload buffer.
Returns the pos of the next topic expression or -1 when the list
of topics is exhausted. 

---
title: "mg_mqtt_ping()"
decl_name: "mg_mqtt_ping"
symbol_kind: "func"
signature: |
  void mg_mqtt_ping(struct mg_connection *nc);
---

Sends a PINGREQ command. 

---
title: "mg_mqtt_pong()"
decl_name: "mg_mqtt_pong"
symbol_kind: "func"
signature: |
  void mg_mqtt_pong(struct mg_connection *nc);
---

Sends a PINGRESP command. 

---
title: "mg_mqtt_puback()"
decl_name: "mg_mqtt_puback"
symbol_kind: "func"
signature: |
  void mg_mqtt_puback(struct mg_connection *nc, uint16_t message_id);
---

Sends a PUBACK command with a given `message_id`. 

---
title: "mg_mqtt_pubcomp()"
decl_name: "mg_mqtt_pubcomp"
symbol_kind: "func"
signature: |
  void mg_mqtt_pubcomp(struct mg_connection *nc, uint16_t message_id);
---

Sends a PUBCOMP command with a given `message_id`. 

---
title: "mg_mqtt_publish()"
decl_name: "mg_mqtt_publish"
symbol_kind: "func"
signature: |
  void mg_mqtt_publish(struct mg_connection *nc, const char *topic,
                       uint16_t message_id, int flags, const void *data,
                       size_t len);
---

Publishes a message to a given topic. 

---
title: "mg_mqtt_pubrec()"
decl_name: "mg_mqtt_pubrec"
symbol_kind: "func"
signature: |
  void mg_mqtt_pubrec(struct mg_connection *nc, uint16_t message_id);
---

Sends a PUBREC command with a given `message_id`. 

---
title: "mg_mqtt_pubrel()"
decl_name: "mg_mqtt_pubrel"
symbol_kind: "func"
signature: |
  void mg_mqtt_pubrel(struct mg_connection *nc, uint16_t message_id);
---

Sends a PUBREL command with a given `message_id`. 

---
title: "mg_mqtt_suback()"
decl_name: "mg_mqtt_suback"
symbol_kind: "func"
signature: |
  void mg_mqtt_suback(struct mg_connection *nc, uint8_t *qoss, size_t qoss_len,
                      uint16_t message_id);
---

Sends a SUBACK command with a given `message_id`
and a sequence of granted QoSs. 

---
title: "mg_mqtt_subscribe()"
decl_name: "mg_mqtt_subscribe"
symbol_kind: "func"
signature: |
  void mg_mqtt_subscribe(struct mg_connection *nc,
                         const struct mg_mqtt_topic_expression *topics,
                         size_t topics_len, uint16_t message_id);
---

Subscribes to a bunch of topics. 

---
title: "mg_mqtt_unsuback()"
decl_name: "mg_mqtt_unsuback"
symbol_kind: "func"
signature: |
  void mg_mqtt_unsuback(struct mg_connection *nc, uint16_t message_id);
---

Sends a UNSUBACK command with a given `message_id`. 

---
title: "mg_mqtt_unsubscribe()"
decl_name: "mg_mqtt_unsubscribe"
symbol_kind: "func"
signature: |
  void mg_mqtt_unsubscribe(struct mg_connection *nc, char **topics,
                           size_t topics_len, uint16_t message_id);
---

Unsubscribes from a bunch of topics. 

---
title: "mg_mqtt_vmatch_topic_expression()"
decl_name: "mg_mqtt_vmatch_topic_expression"
symbol_kind: "func"
signature: |
  int mg_mqtt_vmatch_topic_expression(const char *exp, struct mg_str topic);
---

Same as `mg_mqtt_match_topic_expression()`, but takes `exp` as a
NULL-terminated string. 

---
title: "mg_send_mqtt_handshake()"
decl_name: "mg_send_mqtt_handshake"
symbol_kind: "func"
signature: |
  void mg_send_mqtt_handshake(struct mg_connection *nc, const char *client_id);
---

Sends an MQTT handshake. 

---
title: "mg_send_mqtt_handshake_opt()"
decl_name: "mg_send_mqtt_handshake_opt"
symbol_kind: "func"
signature: |
  void mg_send_mqtt_handshake_opt(struct mg_connection *nc, const char *client_id,
                                  struct mg_send_mqtt_handshake_opts);
---

Sends an MQTT handshake with optional parameters. 

---
title: "mg_set_protocol_mqtt()"
decl_name: "mg_set_protocol_mqtt"
symbol_kind: "func"
signature: |
  void mg_set_protocol_mqtt(struct mg_connection *nc);
---

Attaches a built-in MQTT event handler to the given connection.

The user-defined event handler will receive following extra events:

- MG_EV_MQTT_CONNACK
- MG_EV_MQTT_PUBLISH
- MG_EV_MQTT_PUBACK
- MG_EV_MQTT_PUBREC
- MG_EV_MQTT_PUBREL
- MG_EV_MQTT_PUBCOMP
- MG_EV_MQTT_SUBACK 

---
title: "struct mg_mqtt_proto_data"
decl_name: "struct mg_mqtt_proto_data"
symbol_kind: "struct"
signature: |
  struct mg_mqtt_proto_data {
    uint16_t keep_alive;
    double last_control_time;
  };
---

mg_mqtt_proto_data should be in header to allow external access to it 

---
title: "MQTT Server API reference"
symbol_kind: "intro"
decl_name: "mg_mqtt_server.h"
items:
  - { name: LIST_ENTRY.md }
  - { name: struct_mg_mqtt_broker.md }
  - { name: struct_mg_mqtt_session.md }
---



---
title: "LIST_ENTRY()"
decl_name: "LIST_ENTRY"
symbol_kind: "func"
signature: |
    LIST_ENTRY(mg_mqtt_session);
---

Broker 

---
title: "struct mg_mqtt_broker"
decl_name: "struct mg_mqtt_broker"
symbol_kind: "struct"
signature: |
  struct mg_mqtt_broker {
    LIST_HEAD(_mg_sesshead, mg_mqtt_session) sessions; /* Session list */
    void *user_data;                                   /* User data */
  };
---

MQTT broker. 

---
title: "struct mg_mqtt_session"
decl_name: "struct mg_mqtt_session"
symbol_kind: "struct"
signature: |
  struct mg_mqtt_session {
    struct mg_mqtt_broker *brk;       /* Broker */
    LIST_ENTRY(mg_mqtt_session) link; /* mg_mqtt_broker::sessions linkage */
    struct mg_connection *nc;         /* Connection with the client */
    size_t num_subscriptions;         /* Size of `subscriptions` array */
    void *user_data;                  /* User data */
    struct mg_mqtt_topic_expression *subscriptions;
  };
---

MQTT session (Broker side). 

---
title: "Core API: TCP/UDP/SSL"
symbol_kind: "intro"
decl_name: "mg_net.h"
items:
  - { name: mg_add_sock.md }
  - { name: mg_add_sock_opt.md }
  - { name: mg_bind.md }
  - { name: mg_bind_opt.md }
  - { name: mg_broadcast.md }
  - { name: mg_check_ip_acl.md }
  - { name: mg_connect.md }
  - { name: mg_connect_opt.md }
  - { name: mg_mgr_free.md }
  - { name: mg_mgr_init.md }
  - { name: mg_mgr_init_opt.md }
  - { name: mg_mgr_poll.md }
  - { name: mg_next.md }
  - { name: mg_printf.md }
  - { name: mg_resolve.md }
  - { name: mg_send.md }
  - { name: mg_set_ssl.md }
  - { name: mg_set_timer.md }
  - { name: mg_socketpair.md }
  - { name: mg_time.md }
  - { name: mg_vprintf.md }
  - { name: mg_event_handler_t.md }
  - { name: struct_mg_add_sock_opts.md }
  - { name: struct_mg_bind_opts.md }
  - { name: struct_mg_connect_opts.md }
  - { name: struct_mg_connection.md }
  - { name: struct_mg_mgr.md }
  - { name: struct_mg_mgr_init_opts.md }
---

NOTE: Mongoose manager is single threaded. It does not protect
its data structures by mutexes, therefore all functions that are dealing
with a particular event manager should be called from the same thread,
with exception of the `mg_broadcast()` function. It is fine to have different
event managers handled by different threads.

---
title: "mg_add_sock()"
decl_name: "mg_add_sock"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_add_sock(struct mg_mgr *mgr, sock_t sock,
                                    MG_CB(mg_event_handler_t handler,
                                          void *user_data);
---

Creates a connection, associates it with the given socket and event handler
and adds it to the manager.

For more options see the `mg_add_sock_opt` variant. 

---
title: "mg_add_sock_opt()"
decl_name: "mg_add_sock_opt"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_add_sock_opt(struct mg_mgr *mgr, sock_t sock,
                                        MG_CB(mg_event_handler_t handler,
                                              void *user_data);
---

Creates a connection, associates it with the given socket and event handler
and adds to the manager.

See the `mg_add_sock_opts` structure for a description of the options. 

---
title: "mg_bind()"
decl_name: "mg_bind"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_bind(struct mg_mgr *mgr, const char *address,
                                MG_CB(mg_event_handler_t handler,
                                      void *user_data);
---

Creates a listening connection.

See `mg_bind_opt` for full documentation. 

---
title: "mg_bind_opt()"
decl_name: "mg_bind_opt"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_bind_opt(struct mg_mgr *mgr, const char *address,
                                    MG_CB(mg_event_handler_t handler,
                                          void *user_data);
---

Creates a listening connection.

The `address` parameter specifies which address to bind to. It's format is
the same as for the `mg_connect()` call, where `HOST` part is optional.
`address` can be just a port number, e.g. `:8000`. To bind to a specific
interface, an IP address can be specified, e.g. `1.2.3.4:8000`. By default,
a TCP connection is created. To create UDP connection, prepend `udp://`
prefix, e.g. `udp://:8000`. To summarize, `address` parameter has following
format: `[PROTO://][IP_ADDRESS]:PORT`, where `PROTO` could be `tcp` or
`udp`.

See the `mg_bind_opts` structure for a description of the optional
parameters.

Returns a new listening connection or `NULL` on error.
NOTE: The connection remains owned by the manager, do not free(). 

---
title: "mg_broadcast()"
decl_name: "mg_broadcast"
symbol_kind: "func"
signature: |
  void mg_broadcast(struct mg_mgr *mgr, mg_event_handler_t cb, void *data,
                    size_t len);
---

Passes a message of a given length to all connections.

Must be called from a thread that does NOT call `mg_mgr_poll()`.
Note that `mg_broadcast()` is the only function
that can be, and must be, called from a different (non-IO) thread.

`func` callback function will be called by the IO thread for each
connection. When called, the event will be `MG_EV_POLL`, and a message will
be passed as the `ev_data` pointer. Maximum message size is capped
by `MG_CTL_MSG_MESSAGE_SIZE` which is set to 8192 bytes by default. 

---
title: "mg_check_ip_acl()"
decl_name: "mg_check_ip_acl"
symbol_kind: "func"
signature: |
  int mg_check_ip_acl(const char *acl, uint32_t remote_ip);
---

Verify given IP address against the ACL.

`remote_ip` - an IPv4 address to check, in host byte order
`acl` - a comma separated list of IP subnets: `x.x.x.x/x` or `x.x.x.x`.
Each subnet is
prepended by either a - or a + sign. A plus sign means allow, where a
minus sign means deny. If a subnet mask is omitted, such as `-1.2.3.4`,
it means that only that single IP address is denied.
Subnet masks may vary from 0 to 32, inclusive. The default setting
is to allow all access. On each request the full list is traversed,
and the last match wins. Example:

`-0.0.0.0/0,+192.168/16` - deny all accesses, only allow 192.168/16 subnet

To learn more about subnet masks, see this
link:https://en.wikipedia.org/wiki/Subnetwork[Wikipedia page on Subnetwork].

Returns -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed. 

---
title: "mg_connect()"
decl_name: "mg_connect"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect(struct mg_mgr *mgr, const char *address,
                                   MG_CB(mg_event_handler_t handler,
                                         void *user_data);
---

Connects to a remote host.

See `mg_connect_opt()` for full documentation. 

---
title: "mg_connect_opt()"
decl_name: "mg_connect_opt"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_connect_opt(struct mg_mgr *mgr, const char *address,
                                       MG_CB(mg_event_handler_t handler,
                                             void *user_data);
---

Connects to a remote host.

The `address` format is `[PROTO://]HOST:PORT`. `PROTO` could be `tcp` or
`udp`. `HOST` could be an IP address,
IPv6 address (if Mongoose is compiled with `-DMG_ENABLE_IPV6`) or a host
name. If `HOST` is a name, Mongoose will resolve it asynchronously. Examples
of valid addresses: `google.com:80`, `udp://1.2.3.4:53`, `10.0.0.1:443`,
`[::1]:80`

See the `mg_connect_opts` structure for a description of the optional
parameters.

Returns a new outbound connection or `NULL` on error.

NOTE: The connection remains owned by the manager, do not free().

NOTE: To enable IPv6 addresses `-DMG_ENABLE_IPV6` should be specified
in the compilation flags.

NOTE: The new connection will receive `MG_EV_CONNECT` as its first event
which will report the connect success status.
If the asynchronous resolution fails or the `connect()` syscall fails for
whatever reason (e.g. with `ECONNREFUSED` or `ENETUNREACH`), then
`MG_EV_CONNECT` event will report failure. Code example below:

```c
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  int connect_status;

  switch (ev) {
    case MG_EV_CONNECT:
      connect_status = * (int *) ev_data;
      if (connect_status == 0) {
        // Success
      } else  {
        // Error
        printf("connect() error: %s\n", strerror(connect_status));
      }
      break;
    ...
  }
}

  ...
  mg_connect(mgr, "my_site.com:80", ev_handler);
``` 

---
title: "mg_event_handler_t"
decl_name: "mg_event_handler_t"
symbol_kind: "typedef"
signature: |
  typedef void (*mg_event_handler_t)(struct mg_connection *nc, int ev,
                                     void *ev_data MG_UD_ARG(void *user_data));
---

Callback function (event handler) prototype. Must be defined by the user.
Mongoose calls the event handler, passing the events defined below. 

---
title: "mg_mgr_free()"
decl_name: "mg_mgr_free"
symbol_kind: "func"
signature: |
  void mg_mgr_free(struct mg_mgr *mgr);
---

De-initialises Mongoose manager.

Closes and deallocates all active connections. 

---
title: "mg_mgr_init()"
decl_name: "mg_mgr_init"
symbol_kind: "func"
signature: |
  void mg_mgr_init(struct mg_mgr *mgr, void *user_data);
---

Initialise Mongoose manager. Side effect: ignores SIGPIPE signal.
`mgr->user_data` field will be initialised with a `user_data` parameter.
That is an arbitrary pointer, where the user code can associate some data
with the particular Mongoose manager. For example, a C++ wrapper class
could be written in which case `user_data` can hold a pointer to the
class instance. 

---
title: "mg_mgr_init_opt()"
decl_name: "mg_mgr_init_opt"
symbol_kind: "func"
signature: |
  void mg_mgr_init_opt(struct mg_mgr *mgr, void *user_data,
                       struct mg_mgr_init_opts opts);
---

Like `mg_mgr_init` but with more options.

Notably, this allows you to create a manger and choose
dynamically which networking interface implementation to use. 

---
title: "mg_mgr_poll()"
decl_name: "mg_mgr_poll"
symbol_kind: "func"
signature: |
  int mg_mgr_poll(struct mg_mgr *mgr, int milli);
---

This function performs the actual IO and must be called in a loop
(an event loop). It returns number of user events generated (except POLLs).
`milli` is the maximum number of milliseconds to sleep.
`mg_mgr_poll()` checks all connections for IO readiness. If at least one
of the connections is IO-ready, `mg_mgr_poll()` triggers the respective
event handlers and returns. 

---
title: "mg_next()"
decl_name: "mg_next"
symbol_kind: "func"
signature: |
  struct mg_connection *mg_next(struct mg_mgr *mgr, struct mg_connection *c);
---

Iterates over all active connections.

Returns the next connection from the list
of active connections or `NULL` if there are no more connections. Below
is the iteration idiom:

```c
for (c = mg_next(srv, NULL); c != NULL; c = mg_next(srv, c)) {
  // Do something with connection `c`
}
``` 

---
title: "mg_printf()"
decl_name: "mg_printf"
symbol_kind: "func"
signature: |
  int mg_printf(struct mg_connection *, const char *fmt, ...);
---

Sends `printf`-style formatted data to the connection.

See `mg_send` for more details on send semantics. 

---
title: "mg_resolve()"
decl_name: "mg_resolve"
symbol_kind: "func"
signature: |
  int mg_resolve(const char *domain_name, char *ip_addr_buf, size_t buf_len);
---

Convert domain name into IP address.

This is a utility function. If compilation flags have
`-DMG_ENABLE_GETADDRINFO`, then `getaddrinfo()` call is used for name
resolution. Otherwise, `gethostbyname()` is used.

CAUTION: this function can block.
Return 1 on success, 0 on failure. 

---
title: "mg_send()"
decl_name: "mg_send"
symbol_kind: "func"
signature: |
  void mg_send(struct mg_connection *, const void *buf, int len);
---

Sends data to the connection.

Note that sending functions do not actually push data to the socket.
They just append data to the output buffer. MG_EV_SEND will be delivered when
the data has actually been pushed out. 

---
title: "mg_set_ssl()"
decl_name: "mg_set_ssl"
symbol_kind: "func"
signature: |
  const char *mg_set_ssl(struct mg_connection *nc, const char *cert,
                         const char *ca_cert);
---

Note: This function is deprecated. Please, use SSL options in
mg_connect_opt.

Enables SSL for a given connection.
`cert` is a server certificate file name for a listening connection
or a client certificate file name for an outgoing connection.
The certificate files must be in PEM format. The server certificate file
must contain a certificate, concatenated with a private key, optionally
concatenated with DH parameters.
`ca_cert` is a CA certificate or NULL if peer verification is not
required.
Return: NULL on success or error message on error. 

---
title: "mg_set_timer()"
decl_name: "mg_set_timer"
symbol_kind: "func"
signature: |
  double mg_set_timer(struct mg_connection *c, double timestamp);
---

Schedules an MG_EV_TIMER event to be delivered at `timestamp` time.
`timestamp` is UNIX time (the number of seconds since Epoch). It is
`double` instead of `time_t` to allow for sub-second precision.
Returns the old timer value.

Example: set the connect timeout to 1.5 seconds:

```
 c = mg_connect(&mgr, "cesanta.com", ev_handler);
 mg_set_timer(c, mg_time() + 1.5);
 ...

 void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
 switch (ev) {
   case MG_EV_CONNECT:
     mg_set_timer(c, 0);  // Clear connect timer
     break;
   case MG_EV_TIMER:
     log("Connect timeout");
     c->flags |= MG_F_CLOSE_IMMEDIATELY;
     break;
``` 

---
title: "mg_socketpair()"
decl_name: "mg_socketpair"
symbol_kind: "func"
signature: |
  int mg_socketpair(sock_t[2], int sock_type);
---

Creates a socket pair.
`sock_type` can be either `SOCK_STREAM` or `SOCK_DGRAM`.
Returns 0 on failure and 1 on success. 

---
title: "mg_time()"
decl_name: "mg_time"
symbol_kind: "func"
signature: |
  double mg_time(void);
---

A sub-second precision version of time(). 

---
title: "mg_vprintf()"
decl_name: "mg_vprintf"
symbol_kind: "func"
signature: |
  int mg_vprintf(struct mg_connection *, const char *fmt, va_list ap);
---

Same as `mg_printf()`, but takes `va_list ap` as an argument. 

---
title: "struct mg_add_sock_opts"
decl_name: "struct mg_add_sock_opts"
symbol_kind: "struct"
signature: |
  struct mg_add_sock_opts {
    void *user_data;           /* Initial value for connection's user_data */
    unsigned int flags;        /* Initial connection flags */
    const char **error_string; /* Placeholder for the error string */
    struct mg_iface *iface;    /* Interface instance */
  };
---

Optional parameters to `mg_add_sock_opt()`.

`flags` is an initial `struct mg_connection::flags` bitmask to set,
see `MG_F_*` flags definitions. 

---
title: "struct mg_bind_opts"
decl_name: "struct mg_bind_opts"
symbol_kind: "struct"
signature: |
  struct mg_bind_opts {
    void *user_data;           /* Initial value for connection's user_data */
    unsigned int flags;        /* Extra connection flags */
    const char **error_string; /* Placeholder for the error string */
    struct mg_iface *iface;    /* Interface instance */
  #if MG_ENABLE_SSL
    /*
     * SSL settings.
     *
     * Server certificate to present to clients or client certificate to
     * present to tunnel dispatcher (for tunneled connections).
     */
    const char *ssl_cert;
    /* Private key corresponding to the certificate. If ssl_cert is set but
     * ssl_key is not, ssl_cert is used. */
    const char *ssl_key;
    /* CA bundle used to verify client certificates or tunnel dispatchers. */
    const char *ssl_ca_cert;
    /* Colon-delimited list of acceptable cipher suites.
     * Names depend on the library used, for example:
     *
     * ECDH-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256 (OpenSSL)
     * TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
     *   (mbedTLS)
     *
     * For OpenSSL the list can be obtained by running "openssl ciphers".
     * For mbedTLS, names can be found in library/ssl_ciphersuites.c
     * If NULL, a reasonable default is used.
     */
    const char *ssl_cipher_suites;
  #endif
  };
---

Optional parameters to `mg_bind_opt()`.

`flags` is an initial `struct mg_connection::flags` bitmask to set,
see `MG_F_*` flags definitions. 

---
title: "struct mg_connection"
decl_name: "struct mg_connection"
symbol_kind: "struct"
signature: |
  struct mg_connection {
    struct mg_connection *next, *prev; /* mg_mgr::active_connections linkage */
    struct mg_connection *listener;    /* Set only for accept()-ed connections */
    struct mg_mgr *mgr;                /* Pointer to containing manager */
  
    sock_t sock; /* Socket to the remote peer */
    int err;
    union socket_address sa; /* Remote peer address */
    size_t recv_mbuf_limit;  /* Max size of recv buffer */
    struct mbuf recv_mbuf;   /* Received data */
    struct mbuf send_mbuf;   /* Data scheduled for sending */
    time_t last_io_time;     /* Timestamp of the last socket IO */
    double ev_timer_time;    /* Timestamp of the future MG_EV_TIMER */
    mg_event_handler_t proto_handler; /* Protocol-specific event handler */
    void *proto_data;                 /* Protocol-specific data */
    void (*proto_data_destructor)(void *proto_data);
    mg_event_handler_t handler; /* Event handler function */
    void *user_data;            /* User-specific data */
    union {
      void *v;
      /*
       * the C standard is fussy about fitting function pointers into
       * void pointers, since some archs might have fat pointers for functions.
       */
      mg_event_handler_t f;
    } priv_1;
    void *priv_2;
    void *mgr_data; /* Implementation-specific event manager's data. */
    struct mg_iface *iface;
    unsigned long flags;
  /* Flags set by Mongoose */
  #define MG_F_LISTENING (1 << 0)          /* This connection is listening */
  #define MG_F_UDP (1 << 1)                /* This connection is UDP */
  #define MG_F_RESOLVING (1 << 2)          /* Waiting for async resolver */
  #define MG_F_CONNECTING (1 << 3)         /* connect() call in progress */
  #define MG_F_SSL (1 << 4)                /* SSL is enabled on the connection */
  #define MG_F_SSL_HANDSHAKE_DONE (1 << 5) /* SSL hanshake has completed */
  #define MG_F_WANT_READ (1 << 6)          /* SSL specific */
  #define MG_F_WANT_WRITE (1 << 7)         /* SSL specific */
  #define MG_F_IS_WEBSOCKET (1 << 8)       /* Websocket specific */
  #define MG_F_RECV_AND_CLOSE (1 << 9) /* Drain rx and close the connection. */
  
  /* Flags that are settable by user */
  #define MG_F_SEND_AND_CLOSE (1 << 10)      /* Push remaining data and close  */
  #define MG_F_CLOSE_IMMEDIATELY (1 << 11)   /* Disconnect */
  
  /* Flags for protocol handlers */
  #define MG_F_PROTO_1 (1 << 12)
  #define MG_F_PROTO_2 (1 << 13)
  #define MG_F_ENABLE_BROADCAST (1 << 14)    /* Allow broadcast address usage */
  
  /* Flags left for application */
  #define MG_F_USER_1 (1 << 20)
  #define MG_F_USER_2 (1 << 21)
  #define MG_F_USER_3 (1 << 22)
  #define MG_F_USER_4 (1 << 23)
  #define MG_F_USER_5 (1 << 24)
  #define MG_F_USER_6 (1 << 25)
  
  #if MG_ENABLE_SSL
    void *ssl_if_data; /* SSL library data. */
  #else
    void *unused_ssl_if_data; /* To keep the size of the structure the same. */
  #endif
  };
---

Mongoose connection. 

---
title: "struct mg_connect_opts"
decl_name: "struct mg_connect_opts"
symbol_kind: "struct"
signature: |
  struct mg_connect_opts {
    void *user_data;           /* Initial value for connection's user_data */
    unsigned int flags;        /* Extra connection flags */
    const char **error_string; /* Placeholder for the error string */
    struct mg_iface *iface;    /* Interface instance */
    const char *nameserver;    /* DNS server to use, NULL for default */
  #if MG_ENABLE_SSL
    /*
     * SSL settings.
     * Client certificate to present to the server.
     */
    const char *ssl_cert;
    /*
     * Private key corresponding to the certificate.
     * If ssl_cert is set but ssl_key is not, ssl_cert is used.
     */
    const char *ssl_key;
    /*
     * Verify server certificate using this CA bundle. If set to "*", then SSL
     * is enabled but no cert verification is performed.
     */
    const char *ssl_ca_cert;
    /* Colon-delimited list of acceptable cipher suites.
     * Names depend on the library used, for example:
     *
     * ECDH-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256 (OpenSSL)
     * TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
     *   (mbedTLS)
     *
     * For OpenSSL the list can be obtained by running "openssl ciphers".
     * For mbedTLS, names can be found in library/ssl_ciphersuites.c
     * If NULL, a reasonable default is used.
     */
    const char *ssl_cipher_suites;
    /*
     * Server name verification. If ssl_ca_cert is set and the certificate has
     * passed verification, its subject will be verified against this string.
     * By default (if ssl_server_name is NULL) hostname part of the address will
     * be used. Wildcard matching is supported. A special value of "*" disables
     * name verification.
     */
    const char *ssl_server_name;
    /*
     * PSK identity and key. Identity is a NUL-terminated string and key is a hex
     * string. Key must be either 16 or 32 bytes (32 or 64 hex digits) for AES-128
     * or AES-256 respectively.
     * Note: Default list of cipher suites does not include PSK suites, if you
     * want to use PSK you will need to set ssl_cipher_suites as well.
     */
    const char *ssl_psk_identity;
    const char *ssl_psk_key;
  #endif
  };
---

Optional parameters to `mg_connect_opt()` 

---
title: "struct mg_mgr"
decl_name: "struct mg_mgr"
symbol_kind: "struct"
signature: |
  struct mg_mgr {
    struct mg_connection *active_connections;
  #if MG_ENABLE_HEXDUMP
    const char *hexdump_file; /* Debug hexdump file path */
  #endif
  #if MG_ENABLE_BROADCAST
    sock_t ctl[2]; /* Socketpair for mg_broadcast() */
  #endif
    void *user_data; /* User data */
    int num_ifaces;
    int num_calls;
    struct mg_iface **ifaces; /* network interfaces */
    const char *nameserver;   /* DNS server to use */
  };
---

Mongoose event manager. 

---
title: "struct mg_mgr_init_opts"
decl_name: "struct mg_mgr_init_opts"
symbol_kind: "struct"
signature: |
  struct mg_mgr_init_opts {
    const struct mg_iface_vtable *main_iface;
    int num_ifaces;
    const struct mg_iface_vtable **ifaces;
    const char *nameserver;
  };
---

Optional parameters to `mg_mgr_init_opt()`.

If `main_iface` is not NULL, it will be used as the main interface in the
default interface set. The pointer will be free'd by `mg_mgr_free`.
Otherwise, the main interface will be autodetected based on the current
platform.

If `num_ifaces` is 0 and `ifaces` is NULL, the default interface set will be
used.
This is an advanced option, as it requires you to construct a full interface
set, including special networking interfaces required by some optional
features such as TCP tunneling. Memory backing `ifaces` and each of the
`num_ifaces` pointers it contains will be reclaimed by `mg_mgr_free`. 

---
title: "API reference"
symbol_kind: "intro"
decl_name: "mg_resolv.h"
items:
  - { name: mg_resolve_async.md }
  - { name: mg_resolve_async_opt.md }
  - { name: mg_resolve_from_hosts_file.md }
  - { name: mg_set_nameserver.md }
  - { name: struct_mg_resolve_async_opts.md }
---



---
title: "mg_resolve_async()"
decl_name: "mg_resolve_async"
symbol_kind: "func"
signature: |
  int mg_resolve_async(struct mg_mgr *mgr, const char *name, int query,
                       mg_resolve_callback_t cb, void *data);
---

See `mg_resolve_async_opt()` 

---
title: "mg_resolve_async_opt()"
decl_name: "mg_resolve_async_opt"
symbol_kind: "func"
signature: |
  int mg_resolve_async_opt(struct mg_mgr *mgr, const char *name, int query,
                           mg_resolve_callback_t cb, void *data,
                           struct mg_resolve_async_opts opts);
---

Resolved a DNS name asynchronously.

Upon successful resolution, the user callback will be invoked
with the full DNS response message and a pointer to the user's
context `data`.

In case of timeout while performing the resolution the callback
will receive a NULL `msg`.

The DNS answers can be extracted with `mg_next_record` and
`mg_dns_parse_record_data`:

[source,c]
----
struct in_addr ina;
struct mg_dns_resource_record *rr = mg_next_record(msg, MG_DNS_A_RECORD,
  NULL);
mg_dns_parse_record_data(msg, rr, &ina, sizeof(ina));
---- 

---
title: "mg_resolve_from_hosts_file()"
decl_name: "mg_resolve_from_hosts_file"
symbol_kind: "func"
signature: |
  int mg_resolve_from_hosts_file(const char *host, union socket_address *usa);
---

Resolve a name from `/etc/hosts`.

Returns 0 on success, -1 on failure. 

---
title: "mg_set_nameserver()"
decl_name: "mg_set_nameserver"
symbol_kind: "func"
signature: |
  void mg_set_nameserver(struct mg_mgr *mgr, const char *nameserver);
---

Set default DNS server 

---
title: "struct mg_resolve_async_opts"
decl_name: "struct mg_resolve_async_opts"
symbol_kind: "struct"
signature: |
  struct mg_resolve_async_opts {
    const char *nameserver;
    int max_retries;    /* defaults to 2 if zero */
    int timeout;        /* in seconds; defaults to 5 if zero */
    int accept_literal; /* pseudo-resolve literal ipv4 and ipv6 addrs */
    int only_literal;   /* only resolves literal addrs; sync cb invocation */
    struct mg_connection **dns_conn; /* return DNS connection */
  };
---

Options for `mg_resolve_async_opt`. 

---
title: "URI"
symbol_kind: "intro"
decl_name: "mg_uri.h"
items:
  - { name: mg_assemble_uri.md }
  - { name: mg_parse_uri.md }
---



---
title: "mg_assemble_uri()"
decl_name: "mg_assemble_uri"
symbol_kind: "func"
signature: |
  int mg_assemble_uri(const struct mg_str *scheme, const struct mg_str *user_info,
                      const struct mg_str *host, unsigned int port,
                      const struct mg_str *path, const struct mg_str *query,
                      const struct mg_str *fragment, int normalize_path,
                      struct mg_str *uri);
---

Assemble URI from parts. Any of the inputs can be NULL or zero-length mg_str.

If normalize_path is true, path is normalized by resolving relative refs.

Result is a heap-allocated string (uri->p must be free()d after use).

Returns 0 on success, -1 on error. 

---
title: "mg_parse_uri()"
decl_name: "mg_parse_uri"
symbol_kind: "func"
signature: |
  int mg_parse_uri(const struct mg_str uri, struct mg_str *scheme,
                   struct mg_str *user_info, struct mg_str *host,
                   unsigned int *port, struct mg_str *path, struct mg_str *query,
                   struct mg_str *fragment);
---

Parses an URI and fills string chunks with locations of the respective
uri components within the input uri string. NULL pointers will be
ignored.

General syntax:

    [scheme://[user_info@]]host[:port][/path][?query][#fragment]

Example:

    foo.com:80
    tcp://foo.com:1234
    http://foo.com:80/bar?baz=1
    https://user:pw@foo.com:443/blah

`path` will include the leading slash. `query` won't include the leading `?`.
`host` can contain embedded colons if surrounded by square brackets in order
to support IPv6 literal addresses.


Returns 0 on success, -1 on error. 

---
title: "Utility API"
symbol_kind: "intro"
decl_name: "mg_util.h"
items:
  - { name: mg_base64_decode.md }
  - { name: mg_base64_encode.md }
  - { name: mg_basic_auth_header.md }
  - { name: mg_conn_addr_to_str.md }
  - { name: mg_fopen.md }
  - { name: mg_fread.md }
  - { name: mg_fwrite.md }
  - { name: mg_hexdump.md }
  - { name: mg_hexdump_connection.md }
  - { name: mg_hexdumpf.md }
  - { name: mg_is_big_endian.md }
  - { name: mg_mbuf_append_base64.md }
  - { name: mg_mbuf_append_base64_putc.md }
  - { name: mg_open.md }
  - { name: mg_skip.md }
  - { name: mg_sock_addr_to_str.md }
  - { name: mg_sock_to_str.md }
  - { name: mg_start_thread.md }
  - { name: mg_stat.md }
  - { name: mg_url_encode.md }
---



---
title: "mg_base64_decode()"
decl_name: "mg_base64_decode"
symbol_kind: "func"
signature: |
  int mg_base64_decode(const unsigned char *s, int len, char *dst);
---

Decodes base64-encoded string `s`, `len` into the destination `dst`.
The destination has to have enough space to hold the decoded buffer.
Decoding stops either when all strings have been decoded or invalid an
character appeared.
Destination is '\0'-terminated.
Returns the number of decoded characters. On success, that should be equal
to `len`. On error (invalid character) the return value is smaller then
`len`. 

---
title: "mg_base64_encode()"
decl_name: "mg_base64_encode"
symbol_kind: "func"
signature: |
  void mg_base64_encode(const unsigned char *src, int src_len, char *dst);
---

Base64-encode chunk of memory `src`, `src_len` into the destination `dst`.
Destination has to have enough space to hold encoded buffer.
Destination is '\0'-terminated. 

---
title: "mg_basic_auth_header()"
decl_name: "mg_basic_auth_header"
symbol_kind: "func"
signature: |
  void mg_basic_auth_header(const struct mg_str user, const struct mg_str pass,
                            struct mbuf *buf);
---

Generate a Basic Auth header and appends it to buf.
If pass is NULL, then user is expected to contain the credentials pair
already encoded as `user:pass`. 

---
title: "mg_conn_addr_to_str()"
decl_name: "mg_conn_addr_to_str"
symbol_kind: "func"
signature: |
  int mg_conn_addr_to_str(struct mg_connection *c, char *buf, size_t len,
                          int flags);
---

Converts a connection's local or remote address into string.

The `flags` parameter is a bit mask that controls the behaviour,
see `MG_SOCK_STRINGIFY_*` definitions.

- MG_SOCK_STRINGIFY_IP - print IP address
- MG_SOCK_STRINGIFY_PORT - print port number
- MG_SOCK_STRINGIFY_REMOTE - print remote peer's IP/port, not local address

If both port number and IP address are printed, they are separated by `:`.
If compiled with `-DMG_ENABLE_IPV6`, IPv6 addresses are supported.
Return length of the stringified address. 

---
title: "mg_fopen()"
decl_name: "mg_fopen"
symbol_kind: "func"
signature: |
  FILE *mg_fopen(const char *path, const char *mode);
---

Opens the given file and returns a file stream.

`path` and `mode` should be UTF8 encoded.

Return value is the same as for the `fopen()` call. 

---
title: "mg_fread()"
decl_name: "mg_fread"
symbol_kind: "func"
signature: |
  size_t mg_fread(void *ptr, size_t size, size_t count, FILE *f);
---

Reads data from the given file stream.

Return value is a number of bytes readen. 

---
title: "mg_fwrite()"
decl_name: "mg_fwrite"
symbol_kind: "func"
signature: |
  size_t mg_fwrite(const void *ptr, size_t size, size_t count, FILE *f);
---

Writes data to the given file stream.

Return value is a number of bytes wtitten. 

---
title: "mg_hexdump()"
decl_name: "mg_hexdump"
symbol_kind: "func"
signature: |
  int mg_hexdump(const void *buf, int len, char *dst, int dst_len);
---

Generates a human-readable hexdump of memory chunk.

Takes a memory buffer `buf` of length `len` and creates a hex dump of that
buffer in `dst`. The generated output is a-la hexdump(1).
Returns the length of generated string, excluding terminating `\0`. If
returned length is bigger than `dst_len`, the overflow bytes are discarded. 

---
title: "mg_hexdumpf()"
decl_name: "mg_hexdumpf"
symbol_kind: "func"
signature: |
  void mg_hexdumpf(FILE *fp, const void *buf, int len);
---

Same as mg_hexdump, but with output going to file instead of a buffer. 

---
title: "mg_hexdump_connection()"
decl_name: "mg_hexdump_connection"
symbol_kind: "func"
signature: |
  void mg_hexdump_connection(struct mg_connection *nc, const char *path,
                             const void *buf, int num_bytes, int ev);
---

Generates human-readable hexdump of the data sent or received by the
connection. `path` is a file name where hexdump should be written.
`num_bytes` is a number of bytes sent/received. `ev` is one of the `MG_*`
events sent to an event handler. This function is supposed to be called from
the event handler. 

---
title: "mg_is_big_endian()"
decl_name: "mg_is_big_endian"
symbol_kind: "func"
signature: |
  int mg_is_big_endian(void);
---

Returns true if target platform is big endian. 

---
title: "mg_mbuf_append_base64()"
decl_name: "mg_mbuf_append_base64"
symbol_kind: "func"
signature: |
  void mg_mbuf_append_base64(struct mbuf *mbuf, const void *data, size_t len);
---

Encode `len` bytes starting at `data` as base64 and append them to an mbuf. 

---
title: "mg_mbuf_append_base64_putc()"
decl_name: "mg_mbuf_append_base64_putc"
symbol_kind: "func"
signature: |
  void mg_mbuf_append_base64_putc(char ch, void *user_data);
---

Use with cs_base64_init/update/finish in order to write out base64 in chunks. 

---
title: "mg_open()"
decl_name: "mg_open"
symbol_kind: "func"
signature: |
  int mg_open(const char *path, int flag, int mode);
---

Opens the given file and returns a file stream.

`path` should be UTF8 encoded.

Return value is the same as for the `open()` syscall. 

---
title: "mg_skip()"
decl_name: "mg_skip"
symbol_kind: "func"
signature: |
  const char *mg_skip(const char *s, const char *end_string,
                      const char *delimiters, struct mg_str *v);
---

Fetches substring from input string `s`, `end` into `v`.
Skips initial delimiter characters. Records first non-delimiter character
at the beginning of substring `v`. Then scans the rest of the string
until a delimiter character or end-of-string is found.
`delimiters` is a 0-terminated string containing delimiter characters.
Either one of `delimiters` or `end_string` terminates the search.
Returns an `s` pointer, advanced forward where parsing has stopped. 

---
title: "mg_sock_addr_to_str()"
decl_name: "mg_sock_addr_to_str"
symbol_kind: "func"
signature: |
  int mg_sock_addr_to_str(const union socket_address *sa, char *buf, size_t len,
                          int flags);
---

Convert the socket's address into string.

`flags` is MG_SOCK_STRINGIFY_IP and/or MG_SOCK_STRINGIFY_PORT. 

---
title: "mg_sock_to_str()"
decl_name: "mg_sock_to_str"
symbol_kind: "func"
signature: |
  void mg_sock_to_str(sock_t sock, char *buf, size_t len, int flags);
---

Legacy interface. 

---
title: "mg_start_thread()"
decl_name: "mg_start_thread"
symbol_kind: "func"
signature: |
  void *mg_start_thread(void *(*thread_func);
---

Starts a new detached thread.
Arguments and semantics are the same as pthead's `pthread_create()`.
`thread_func` is a thread function, `thread_func_param` is a parameter
that is passed to the thread function. 

---
title: "mg_stat()"
decl_name: "mg_stat"
symbol_kind: "func"
signature: |
  int mg_stat(const char *path, cs_stat_t *st);
---

Performs a 64-bit `stat()` call against a given file.

`path` should be UTF8 encoded.

Return value is the same as for `stat()` syscall. 

---
title: "mg_url_encode()"
decl_name: "mg_url_encode"
symbol_kind: "func"
signature: |
  struct mg_str mg_url_encode(const struct mg_str src);
---

Same as `mg_url_encode_opt(src, "._-$,;~()/", 0)`. 

---
title: CoAP client example
---

To create a CoAP client, follow this pattern:

1. Create an outbound connection by calling `mg_connect`
2. Call `mg_set_protocol_coap` for created connection
3. Create an event handler function that handles the following events:
- `MG_EV_COAP_CON`
- `MG_EV_COAP_NOC`
- `MG_EV_COAP_ACK`
- `MG_EV_COAP_RST`

Here's an example of the simplest CoAP client.
Error checking is omitted for the sake of clarity:

```c
#include "mongoose.h"

static int s_time_to_exit = 0;
static char *s_default_address = "udp://coap.me:5683";

static void coap_handler(struct mg_connection *nc, int ev, void *p) {
  switch (ev) {
    case MG_EV_CONNECT: {
      struct mg_coap_message cm;

      memset(&cm, 0, sizeof(cm));
      cm.msg_id = 1;
      cm.msg_type = MG_COAP_MSG_CON;
      mg_coap_send_message(nc, &cm);
      break;
    }
    case MG_EV_COAP_ACK:
    case MG_EV_COAP_RST: {
      struct mg_coap_message *cm = (struct mg_coap_message *) p;
      printf("ACK/RST for message with msg_id = %d received\n", cm->msg_id);
      s_time_to_exit = 1;
      break;
    }
    case MG_EV_CLOSE: {
      if (s_time_to_exit == 0) {
        printf("Server closed connection\n");
        s_time_to_exit = 1;
      }
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;
  struct mg_connection *nc;

  mg_mgr_init(&mgr, 0);

  nc = mg_connect(&mgr, s_default_address, coap_handler);

  mg_set_protocol_coap(nc);

  while (!s_time_to_exit) {
    mg_mgr_poll(&mgr, 1000000);
  }

  mg_mgr_free(&mgr);

  return 0;
}
```

See full source code at [CoAP client example](https://github.com/cesanta/mongoose/tree/master/examples/coap_client).
---
title: CoAP server example
---

To create a CoAP server, follow this pattern:
1. Create a listening connection by calling `mg_bind()` or `mg_bind_opt()`
2. 2. Call `mg_set_protocol_coap()` for that listening connection.
3. Create an event handler function that handles the following events:
- `MG_EV_COAP_CON`
- `MG_EV_COAP_NOC`
- `MG_EV_COAP_ACK`
- `MG_EV_COAP_RST`

Here's an example of the simplest CoAP server. Error checking is omitted for the sake of clarity:

```c
#include "mongoose.h"

static char *s_default_address = "udp://:5683";

static void coap_handler(struct mg_connection *nc, int ev, void *p) {
  switch (ev) {
    case MG_EV_COAP_CON: {
      uint32_t res;
      struct mg_coap_message *cm = (struct mg_coap_message *) p;
      printf("CON with msg_id = %d received\n", cm->msg_id);
      res = mg_coap_send_ack(nc, cm->msg_id);
      if (res == 0) {
        printf("Successfully sent ACK for message with msg_id = %d\n",
               cm->msg_id);
      } else {
        printf("Error: %d\n", res);
      }
      break;
    }
    case MG_EV_COAP_NOC:
    case MG_EV_COAP_ACK:
    case MG_EV_COAP_RST: {
      struct mg_coap_message *cm = (struct mg_coap_message *) p;
      printf("ACK/RST/NOC with msg_id = %d received\n", cm->msg_id);
      break;
    }
  }
}

int main(void) {
  struct mg_mgr mgr;
  struct mg_connection *nc;

  mg_mgr_init(&mgr, 0);

  nc = mg_bind(&mgr, s_default_address, coap_handler);
  mg_set_protocol_coap(nc);

  while (1) {
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);
  return 0;
}
```

See full source code at [CoAP server example](https://github.com/cesanta/mongoose/tree/master/examples/coap_server).
---
title: Misc API
items:
  - { name: ../c-api/net.h }
  - { name: ../c-api/util.h }
  - { name: ../c-api/uri.h }
  - { name: ../c-api/mbuf.h }
---
# Examples


## DNS server example

To create a DNS server, follow this pattern:

1. Create a listening UDP connection by calling `mg_bind()` or `mg_bind_opt()`
2. Call `mg_set_protocol_dns()` for that listening connection.
  That attaches a built-in DNS event handler which parses incoming
  data and triggers DNS-specific events.
3. Create an event handler function.

Here is an example of a simpe DNS server. It is a captive DNS server, meaning
that it replies with the same IP address on all queries, regardless of what
exactly host name is being resolved. Error checking is omitted for
the sake of clarity:

```c
#include "mongoose.h"
#include <stdio.h>

static const char *s_listening_addr = "udp://:5353";

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct mg_dns_message *msg;
  struct mg_dns_resource_record *rr;
  struct mg_dns_reply reply;
  int i;

  switch (ev) {
    case MG_DNS_MESSAGE: {
      struct mbuf reply_buf;
      mbuf_init(&reply_buf, 512);
      msg = (struct mg_dns_message *) ev_data;
      reply = mg_dns_create_reply(&reply_buf, msg);

      for (i = 0; i < msg->num_questions; i++) {
        char rname[256];
        rr = &msg->questions[i];
        mg_dns_uncompress_name(msg, &rr->name, rname, sizeof(rname) - 1);
        fprintf(stdout, "Q type %d name %s\n", rr->rtype, rname);
        if (rr->rtype == MG_DNS_A_RECORD) {
          in_addr_t addr = inet_addr("127.0.0.1");
          mg_dns_reply_record(&reply, rr, NULL, rr->rtype, 10, &addr, 4);
        }
      }

      mg_dns_send_reply(nc, &reply);
      nc->flags |= MG_F_SEND_AND_CLOSE;
      mbuf_free(&reply_buf);
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;
  struct mg_connection *c;

  mg_mgr_init(&mgr, NULL);
  c = mg_bind(&mgr, s_listening_addr, ev_handler);
  mg_set_protocol_dns(c);

  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}
```

See full [Captive DNS server example](https://github.com/cesanta/mongoose/tree/master/examples/captive_dns_server).


## DNS client example

See https://github.com/cesanta/mongoose/blob/master/mongoose.c and search
for the `mg_resolve_async_eh()` function - that is the core of
built-in Mongoose async DNS resolver.
---
title: Async DNS resolver
items:
  - { name: overview.md }
  - { name: ../c-api/resolv.h/ }
---
---
title: Overview
---

Mongoose uses non-blocking DNS resolver. For each name to be resolved,
it first checks the `/etc/hosts` file (or, `hosts` on Windows).
If the entry is not found there, then the `8.8.8.8` DNS server is queried.
When IP address is found, Mongoose proceeds with making the connection
with the resolved IP address.
# CGI

[CGI](https://en.wikipedia.org/wiki/Common_Gateway_Interface)
is a simple mechanism to generate dynamic content.
In order to use CGI, call `mg_serve_http()` function and use
`.cgi` file extension for the CGI files. To be more precise,
all files that match `cgi_file_pattern` setting in the
`struct mg_serve_http_opts` are treated as CGI.
If `cgi_file_pattern` is NULL, `**.cgi$|**.php$` is used.

If Mongoose recognises a file as CGI, it executes it, and sends the output
back to the client. Therefore,
CGI file must be executable. Mongoose honours the shebang line - see
http://en.wikipedia.org/wiki/Shebang_(Unix).

For example, if both PHP and Perl CGIs are used, then
`#!/path/to/php-cgi.exe` and `#!/path/to/perl.exe` must be the first lines
of the respective CGI scripts.

It is possible to hardcode the path to the CGI interpreter for all
CGI scripts and disregard the shebang line. To do that, set the
`cgi_interpreter` setting in the `struct mg_serve_http_opts`.

NOTE: PHP scripts must use `php-cgi.exe` as CGI interpreter, not `php.exe`.
Example:

```c
  opts.cgi_interpreter = "C:\\ruby\\ruby.exe";
```
NOTE: In the CGI handler we don't use explicitly a system call waitpid() for
reaping zombie processes. Instead, we set the SIGCHLD handler to SIG_IGN.
It will cause zombie processes to be reaped automatically.
CAUTION: not all OSes (e.g. QNX) reap zombies if SIGCHLD is ignored.
# HTTP client example

To create an HTTP client, follow this pattern:

1. Create an outbound connection by calling `mg_connect_http()`
2. Create an event handler function that handles `MG_EV_HTTP_REPLY` event

Here's an example of the simplest HTTP client.
Error checking is omitted for the sake of clarity:

```c
#include "mongoose.h"

static const char *url = "http://www.google.com";
static int exit_flag = 0;

static void ev_handler(struct mg_connection *c, int ev, void *p) {
  if (ev == MG_EV_HTTP_REPLY) {
    struct http_message *hm = (struct http_message *)p;
    c->flags |= MG_F_CLOSE_IMMEDIATELY;
    fwrite(hm->message.p, 1, (int)hm->message.len, stdout);
    putchar('\n');
    exit_flag = 1;
  } else if (ev == MG_EV_CLOSE) {
    exit_flag = 1;
  };
}

int main(void) {
  struct mg_mgr mgr;

  mg_mgr_init(&mgr, NULL);
  mg_connect_http(&mgr, ev_handler, url, NULL, NULL);


  while (exit_flag == 0) {
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}
```

See full source code at [HTTP client example](https://github.com/cesanta/mongoose/tree/master/examples/http_client).
# Digest Authentication

Mongoose has a built-in Digest (MD5) authentication support. In order to
enable Digest authentication, create a file `.htpasswd` in the directory
you would like to protect. That file should be in the format that Apache's
`htdigest` utility.

You can use either Apache `htdigest` utility, or
Mongoose pre-build binary at https://www.cesanta.com/binary.html
to add new users into that file:

```
mongoose -A /path/to/.htdigest mydomain.com joe joes_password
```
#: HTTP events

As discussed in the overview, `mg_set_protocol_http_websocket()` function
parses incoming data, treats it as HTTP or WebSocket, and triggers high-level
HTTP or WebSocket events. Here is a list of events specific to HTTP.

- MG_EV_HTTP_REQUEST: An HTTP request has arrived. Parsed request
 is passed as
  `struct http_message` through the handler's `void *ev_data` pointer.
- MG_EV_HTTP_REPLY: An HTTP reply has arrived. Parsed reply is
  passed as `struct http_message` through the handler's `void *ev_data`
  pointer.
- MG_EV_HTTP_MULTIPART_REQUEST: A multipart POST request has arrived.
  This event is sent before body is parsed. After this, the user
  should expect a sequence of MG_EV_HTTP_PART_BEGIN/DATA/END requests.
  This is also the last time when headers and other request fields are
  accessible.
- MG_EV_HTTP_CHUNK: An HTTP chunked-encoding chunk has arrived.
  The parsed HTTP reply is passed as `struct http_message` through the
  handler's `void *ev_data` pointer. `http_message::body` would contain
  incomplete, reassembled HTTP body.
  It will grow with every new chunk that arrives, and it can
  potentially consume a lot of memory. The event handler may process
  the body as chunks are coming, and signal Mongoose to delete processed
  body by setting `MG_F_DELETE_CHUNK` in `mg_connection::flags`. When
  the last zero chunk is received,
  Mongoose sends `MG_EV_HTTP_REPLY` event with
  full reassembled body (if handler did not signal to delete chunks) or
  with empty body (if handler did signal to delete chunks).
- MG_EV_HTTP_PART_BEGIN: a new part of multipart message is started,
  extra parameters are passed in mg_http_multipart_part
- MG_EV_HTTP_PART_DATA: a new portion of data from the multiparted message
  no additional headers are available, only data and data size
- MG_EV_HTTP_PART_END: a final boundary received, analogue to maybe used to
  find the end of packet
  Note: Mongoose should be compiled with MG_ENABLE_HTTP_STREAMING_MULTIPART
  to enable multipart events.
# Serving files

API function `mg_serve_http()` makes it easy to serve files from a filesystem.
Generally speaking, that function is an implementation of the HTTP server
that serves static files, CGI and SSI. It's behavior is driven by a list
of options that are consolidated into the `struct mg_serve_http_opts`
structure. See [struct mg_serve_http_opts](#) definition for the full list
of capabilities of `mg_serve_http()`.

For example, in order to create a web server that serves static files
from the current directory, implement event handler function as follows:

```c
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_REQUEST) {
    struct mg_serve_http_opts opts;

    memset(&opts, 0, sizeof(opts);  // Reset all options to defaults
    opts.document_root = ".";       // Serve files from the current directory

    mg_serve_http(c, (struct http_message *) ev_data, s_http_server_opts);
  }
}
```

See working example at [simplest web server](https://github.com/cesanta/mongoose/tree/master/examples/simplest_web_server).

Sometimes there is no need to implement a full static web server, for example
if one works on a RESTful server. If certain endpoints must return the contents
of a static file, a simpler `mg_http_serve_file()` function can be used:

```c
  static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
   switch (ev) {
     case MG_EV_HTTP_REQUEST: {
       struct http_message *hm = (struct http_message *) ev_data;
       mg_http_serve_file(c, hm, "file.txt",
                          mg_mk_str("text/plain"), mg_mk_str(""));
       break;
     }
     ...
   }
  }
```
# HTTP server example

To create an HTTP server, follow this pattern:

1. Create a listening connection by calling `mg_bind()` or `mg_bind_opt()`
2. Call `mg_set_protocol_http_websocket()` for that listening connection.
  That attaches a built-in HTTP event handler which parses incoming
  data and triggers HTTP-specific events. For example, when an HTTP request
  is fully buffered, a built-in HTTP handler parses the request and
  calls user-defined event handler with `MG_EV_HTTP_REQUEST` event and
  parsed HTTP request as an event data.
3. Create event handler function. Note that event handler receives all
  events - low level TCP events like `MG_EV_RECV` and high-level HTTP
  events like `MG_EV_HTTP_REQUEST`. Normally, an event handler function
  should only handle `MG_EV_HTTP_REQUEST` event.

Here's an example of the simplest HTTP server. Error checking is omitted for
the sake of clarity:

```c
#include "mongoose.h"

static const char *s_http_port = "8000";

static void ev_handler(struct mg_connection *c, int ev, void *p) {
  if (ev == MG_EV_HTTP_REQUEST) {
    struct http_message *hm = (struct http_message *) p;

    // We have received an HTTP request. Parsed request is contained in `hm`.
    // Send HTTP reply to the client which shows full original request.
    mg_send_head(c, 200, hm->message.len, "Content-Type: text/plain");
    mg_printf(c, "%.*s", (int)hm->message.len, hm->message.p);
  }
}

int main(void) {
  struct mg_mgr mgr;
  struct mg_connection *c;

  mg_mgr_init(&mgr, NULL);
  c = mg_bind(&mgr, s_http_port, ev_handler);
  mg_set_protocol_http_websocket(c);

  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}
```

See full [HTTP server example](https://github.com/cesanta/mongoose/tree/master/examples/simplest_web_server).
# SSI

Server Side Includes (SSI) is a simple interpreted server-side scripting
language which is most commonly used to include the contents of a file
into a web page. It can be useful when it is desirable to include a common
piece of code throughout a website, for example, headers and footers.

In order to use SSI, call `mg_serve_http()` function and use
`.shtml` file extension for the SSI files. To be more precise,
all files that match `ssi_pattern` setting in the
`struct mg_serve_http_opts` are treated as SSI.
If `ssi_pattern` is NULL, `**.shtml$|**.shtm$` is used.

Unknown SSI directives are silently ignored by Mongoose. Currently,
the following SSI directives are supported:

- `<!--#include FILE_TO_INCLUDE -->` - inject the content of some other file
- `<!--#exec "COMMAND_TO_EXECUTE" -->` - runs a command and inject the output
- `<!--#call COMMAND -->` - triggers `MG_EV_SSI_CALL` event

Note that `<!--#include ... -->` directive supports three path specifications:

- `<!--#include virtual="path" -->`  Path is relative to web server root
- `<!--#include abspath="path" -->`  Path is absolute or relative to the
  web server working dir
- `<!--#include file="path" -->`, `<!--#include "path" -->`
  Path is relative to current document

The include directive may be used to include the contents of a file or
the result of running a CGI script.

The exec directive is used to execute a command on a server,
and show command's output. Example: `<!--#exec "ls -l" -->`

The call directive is a way to invoke a C handler from the HTML page.
On each occurrence of `<!--#call PARAMS -->` directive,
Mongoose calls a registered event handler with `MG_EV_SSI_CALL` event.
Event parameter will point to the `PARAMS` string.
An event handler can output any text, for example by calling
`mg_printf()`. This is a flexible way of generating a web page on
server side by calling a C event handler. Example:

`<!--#call foo -->  <!--#call bar -->`

In the event handler:

```c
   case MG_EV_SSI_CALL: {
     const char *param = (const char *) ev_data;
     if (strcmp(param, "foo") == 0) {
       mg_printf(c, "hello from foo");
     } else if (strcmp(param, "bar") == 0) {
       mg_printf(c, "hello from bar");
     }
     break;
   }
```
# Enabling SSL (HTTPS)

To enable SSL on the server side, please follow these steps:

- Obtain SSL certificate file and private key file
- Declare `struct mg_bind_opts`, initialize `ssl_cert` and `ssl_key`
- Use `mg_bind_opt()` to create listening socket

Example:

```c
int main(void) {
  struct mg_mgr mgr;
  struct mg_connection *c;
  struct mg_bind_opts bind_opts;

  mg_mgr_init(&mgr, NULL);

  memset(&bind_opts, 0, sizeof(bind_opts));
  bind_opts.ssl_cert = "server.pem";
  bind_opts.ssl_key = "key.pem";

  // Use bind_opts to specify SSL certificate & key file
  c = mg_bind_opt(&mgr, "443", ev_handler, bind_opts);
  mg_set_protocol_http_websocket(c);

  ...
}
```

For the full example, please see the [Simplest HTTPS server example](https://github.com/cesanta/mongoose/tree/master/examples/simplest_web_server_ssl).
# Handling file uploads

In order to handle file uploads, use the following HTML snippet:

```HTML
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" value="Upload">
</form>
```

Uploaded files will be sent to the `/upload` endpoint via the `POST` request.
HTTP body will contain multipart-encoded buffer with the file contents.

To save the uploaded file, use this code snippet:

```c
struct mg_str cb(struct mg_connection *c, struct mg_str file_name) {
  // Return the same filename. Do not actually do this except in test!
  // fname is user-controlled and needs to be sanitized.
  return file_name;
}

void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  switch (ev) {
    ...
    case MG_EV_HTTP_PART_BEGIN:
    case MG_EV_HTTP_PART_DATA:
    case MG_EV_HTTP_PART_END:
      mg_file_upload_handler(c, ev, ev_data, cb);
      break;
  }
}
```
# Examples

- [Client example](https://github.com/cesanta/mongoose/tree/master/examples/mqtt_client)
- [Server example](https://github.com/cesanta/mongoose/tree/master/examples/mqtt_broker)

# Build options

Mongoose source code ships in a single .c file that contains functionality
for all supported protocols (modules). Modules can be disabled at compile
time which reduces the executable's size. That can be done by setting preprocessor
flags. Also, some preprocessor flags can be used to tune internal Mongoose
parameters.

To set a preprocessor flag during compile time, use the `-D <PREPROCESSOR_FLAG>`
compiler option. For example, to disable both MQTT and CoAP,
compile the application `my_app.c` like this (assumed UNIX system):

```
  $ cc my_app.c mongoose.c -D MG_DISABLE_MQTT -D MG_DISABLE_COAP
```
## Enabling flags

- `MG_ENABLE_SSL` Enable [SSL/TLS support](https://docs.cesanta.com/mongoose/master/#/http/ssl.md/) (OpenSSL API)
- `MG_ENABLE_IPV6` Enable IPv6 support
- `MG_ENABLE_MQTT` enable [MQTT client](https://docs.cesanta.com/mongoose/master/#/mqtt/client_example.md/) (on by default, set to 0 to disable)
- `MG_ENABLE_MQTT_BROKER` enable [MQTT broker](https://docs.cesanta.com/mongoose/master/#/mqtt/server_example.md/)
- `MG_ENABLE_DNS_SERVER` enable DNS server
- `MG_ENABLE_COAP` enable CoAP protocol
- `MG_ENABLE_HTTP` Enable HTTP protocol support (on by default, set to 0 to disable)
- `MG_ENABLE_HTTP_CGI` Enable [CGI](https://docs.cesanta.com/mongoose/master/#/http/cgi.md/) support
- `MG_ENABLE_HTTP_SSI` Enable [Server Side Includes](https://docs.cesanta.com/mongoose/master/#/http/ssi.md/) support
- `MG_ENABLE_HTTP_SSI_EXEC` Enable SSI `exec` operator
- `MG_ENABLE_HTTP_WEBDAV` enable WebDAV extensions to HTTP
- `MG_ENABLE_HTTP_WEBSOCKET` enable WebSocket extension to HTTP (on by default, =0 to disable)
- `MG_ENABLE_BROADCAST` enable `mg_broadcast()` API
- `MG_ENABLE_GETADDRINFO` enable `getaddrinfo()` in `mg_resolve2()`
- `MG_ENABLE_THREADS` enable `mg_start_thread()` API

## Disabling flags

- `MG_DISABLE_HTTP_DIGEST_AUTH` disable HTTP Digest (MD5) authorisation support
- `CS_DISABLE_SHA1` disable SHA1 support (used by WebSocket)
- `CS_DISABLE_MD5` disable MD5 support (used by HTTP auth)
- `MG_DISABLE_HTTP_KEEP_ALIVE` useful for embedded systems to save resources

## Platform specific

Mongoose tries to detect the target platform whenever possible, but in some cases you have
to explicitly declare some peculiarities of your target, such as:

- `MG_CC3200`: enable workarounds for the TI CC3200 target.
- `MG_ESP8266`: enable workarounds for the ESP8266 target, add `RTOS_SDK` to specify the RTOS SDK flavour.

## Tunables

- `MG_MALLOC`, `MG_CALLOC`, `MG_REALLOC`, `MG_FREE` allow you to a use custom
  memory allocator, e.g. `-DMG_MALLOC=my_malloc`
- `MG_USE_READ_WRITE` when set replaces calls to `recv` with `read` and `send` with `write`,
  thus enabling to add any kind of file descriptor (files, serial devices) to an event manager.
- `MG_SSL_CRYPTO_MODERN`, `MG_SSL_CRYPTO_OLD` - choose either "Modern" or "Old" ciphers
  instead of the default "Intermediate" setting.
  See [this article](https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations) for details.
- `MG_USER_FILE_FUNCTIONS` allow you to use custom file operation, by defining you own `mg_stat`, `mg_fopen`, `mg_open`, `mg_fread` and `mg_fwrite` functions

# Design Concept

Mongoose has three basic data structures:

- `struct mg_mgr` is an event manager that holds all active connections
- `struct mg_connection` describes a connection
- `struct mbuf` describes data buffer (received or sent data)

Connections could be either *listening*, *outbound* or *inbound*. Outbound
connections are created by the `mg_connect()` call. Listening connections are
created by the `mg_bind()` call. Inbound connections are those accepted by a
listening connection. Each connection is described by the `struct mg_connection`
structure, which has a number of fields like socket, event handler function,
send/receive buffer, flags, etc.

An application that uses mongoose should follow a standard pattern of
event-driven application:

1. declare and initialise event manager:

    ```c
    struct mg_mgr mgr;
    mg_mgr_init(&mgr, NULL);
    ```
2. Create connections. For example, a server application should create
   listening connections:

   ```c
    struct mg_connection *c = mg_bind(&mgr, "80", ev_handler_function);
    mg_set_protocol_http_websocket(c);
   ```

3. create an event loop by calling `mg_mgr_poll()` in a loop:

    ```c
    for (;;) {
      mg_mgr_poll(&mgr, 1000);
    }
    ```

`mg_mgr_poll()` iterates over all sockets, accepts new connections, sends and
receives data, closes connections and calls event handler functions for the
respective events. For the full example, see
[Usage Example](#/overview/usage-example.md/)
which implements TCP echo server.
# Connection flags

Each connection has a `flags` bit field. Some flags are set by Mongoose, for
example if a user creates an outbound UDP connection using a `udp://1.2.3.4:5678`
address, Mongoose is going to set a `MG_F_UDP` flag for that connection. Other
flags are meant to be set only by the user event handler to tell Mongoose how to
behave.  Below is a list of connection flags that are meant to be set by event
handlers:

* `MG_F_SEND_AND_CLOSE` tells Mongoose that all data has been appended
  to the `send_mbuf`. As soon as Mongoose sends it to the socket, the
  connection will be closed.
* `MG_F_BUFFER_BUT_DONT_SEND` tells Mongoose to append data to the `send_mbuf`
  but hold on sending it, because the data will be modified later and then will
  be sent by clearing the `MG_F_BUFFER_BUT_DONT_SEND` flag.
* `MG_F_CLOSE_IMMEDIATELY` tells Mongoose to close the connection immediately,
  usually after an error.
* `MG_F_USER_1`, `MG_F_USER_2`, `MG_F_USER_3`, `MG_F_USER_4` could be used by a
  developer to store an application-specific state.

Flags below are set by Mongoose:

* `MG_F_SSL_HANDSHAKE_DONE` SSL only, set when SSL handshake is done.
* `MG_F_CONNECTING` set when the connection is in connecting state after
  `mg_connect()` call but connect did not finish yet.
* `MG_F_LISTENING` set for all listening connections.
* `MG_F_UDP` set if the connection is UDP.
* `MG_F_IS_WEBSOCKET` set if the connection is a WebSocket connection.
* `MG_F_WEBSOCKET_NO_DEFRAG` should be set by a user if the user wants to switch
  off automatic WebSocket frame defragmentation.
# Event handler function

Each connection has an event handler function associated with it. That function
must be implemented by the user. Event handler is the key element of the Mongoose
application, since it defines the application's behaviour. This is what an event
handler function looks like:

```c
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  switch (ev) {
    /* Event handler code that defines behavior of the connection */
    ...
  }
}
```

- `struct mg_connection *nc`: Connection that has received an event.
- `int ev`: Event number, defined in `mongoose.h`. For example, when data
  arrives on an inbound connection, `ev` would be `MG_EV_RECV`.
- `void *ev_data`: This pointer points to the event-specific data, and it has
  a different meaning for different events. For example, for an `MG_EV_RECV` event,
  `ev_data` is an `int *` pointer, pointing to the number of bytes received
  from the remote peer and saved into the receive IO buffer. The exact meaning of
  `ev_data` is described for each event. Protocol-specific events usually have
  `ev_data` pointing to structures that hold protocol-specific information.

NOTE: `struct mg_connection` has `void *user_data` which is a placeholder for
application-specific data. Mongoose does not use that pointer. Event handler
can store any kind of information there.
# Events

Mongoose accepts incoming connections, reads and writes data and calls
specified event handlers for each connection when appropriate. A typical event
sequence is this:

- For an outbound connection: `MG_EV_CONNECT` -> (`MG_EV_RECV`, `MG_EV_SEND`,
  `MG_EV_POLL` ...) -> `MG_EV_CLOSE`
- For an inbound connection: `MG_EV_ACCEPT` ->  (`MG_EV_RECV`, `MG_EV_SEND`,
  `MG_EV_POLL` ...) -> `MG_EV_CLOSE`


Below is a list of core events triggered by Mongoose (note that each protocol
triggers protocol-specific events in addition to the core ones):

- `MG_EV_ACCEPT`: sent when a new server connection is accepted by a listening
  connection. `void *ev_data` is `union socket_address` of the remote peer.

- `MG_EV_CONNECT`: sent when a new outbound connection created by `mg_connect()`
  either failed or succeeded. `void *ev_data` is `int *success`.  If `success`
  is 0, then the connection has been established, otherwise it contains an error code.
  See `mg_connect_opt()` function for code example.

- `MG_EV_RECV`: New data is received and appended to the end of `recv_mbuf`.
  `void *ev_data` is `int *num_received_bytes`. Typically, event handler should
  check received data in `nc->recv_mbuf`, discard processed data by calling
  `mbuf_remove()`, set connection flags `nc->flags` if necessary (see `struct
  mg_connection`) and write data the remote peer by output functions like
  `mg_send()`.

  **WARNING**: Mongoose uses `realloc()` to expand the receive buffer. It is
  the user's responsibility to discard processed data from the beginning of the receive
  buffer, note the `mbuf_remove()` call in the example above.

- `MG_EV_SEND`: Mongoose has written data to the remote peer and discarded
  written data from the `mg_connection::send_mbuf`. `void *ev_data` is `int
  *num_sent_bytes`.

  **NOTE**: Mongoose output functions only append data to the
  `mg_connection::send_mbuf`. They do not do any socket writes. An actual IO
  is done by `mg_mgr_poll()`. An `MG_EV_SEND` event is just a notification about
  an IO has been done.

- `MG_EV_POLL`: Sent to all connections on each invocation of `mg_mgr_poll()`.
  This event could be used to do any housekeeping, for example check whether a
  certain timeout has expired and closes the connection or send heartbeat
  message, etc.

- `MG_EV_TIMER`: Sent to the connection if `mg_set_timer()` was called.

# Introduction

Mongoose is a networking library written in C.
It is a swiss army knife for embedded network programming.
It implements event-driven non-blocking APIs for TCP, UDP, HTTP,
WebSocket, CoAP, MQTT for client and server mode.
Features include:

- Cross-platform: works on Linux/UNIX, MacOS, QNX, eCos, Windows, Android,
  iPhone, FreeRTOS
- Native support for [PicoTCP embedded TCP/IP stack](http://www.picotcp.com),
  [LWIP embedded TCP/IP stack](https://en.wikipedia.org/wiki/LwIP)
- Works on a variety of embedded boards: TI CC3200, TI MSP430, STM32, ESP8266;
  on all Linux-based boards like Raspberry PI, BeagleBone, etc
- Single-threaded, asynchronous, non-blocking core with simple event-based API
- Built-in protocols:
   - plain TCP, plain UDP, SSL/TLS (one-way or two-way), client and server
   - HTTP client and server
   - WebSocket client and server
   - MQTT client and server
   - CoAP client and server
   - DNS client and server
   - asynchronous DNS resolver
- Tiny static and run-time footprint
- Source code is both ISO C and ISO C++ compliant
- Very easy to integrate: just copy
  [mongoose.c](https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c) and
  [mongoose.h](https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h)
  files to your build tree
# Memory buffers

Each connection has a send and receive buffer, `struct mg_connection::send_mbuf`
and `struct mg_connection::recv_mbuf` respectively. When data arrives,
Mongoose appends received data to the `recv_mbuf` and triggers an `MG_EV_RECV`
event. The user may send data back by calling one of the output functions, like
`mg_send()` or `mg_printf()`. Output functions append data to the `send_mbuf`.
When Mongoose successfully writes data to the socket, it discards data from
`struct mg_connection::send_mbuf` and sends an `MG_EV_SEND` event. When the connection
is closed, an `MG_EV_CLOSE` event is sent.

![](/docs/media/mbuf.png)
# Example - TCP echo server

- Copy `mongoose.c` and `mongoose.h` to your build tree
- Write code that uses the Mongoose API, e.g. in `my_app.c`
- Compile application: `$ cc my_app.c mongoose.c`

```c
#include "mongoose.h"  // Include Mongoose API definitions

// Define an event handler function
static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct mbuf *io = &nc->recv_mbuf;

  switch (ev) {
    case MG_EV_RECV:
      // This event handler implements simple TCP echo server
      mg_send(nc, io->buf, io->len);  // Echo received data back
      mbuf_remove(io, io->len);      // Discard data from recv buffer
      break;
    default:
      break;
  }
}

int main(void) {
  struct mg_mgr mgr;

  mg_mgr_init(&mgr, NULL);  // Initialize event manager object

  // Note that many connections can be added to a single event manager
  // Connections can be created at any point, e.g. in event handler function
  mg_bind(&mgr, "1234", ev_handler);  // Create listening connection and add it to the event manager

  for (;;) {  // Start infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);
  return 0;
}
```

