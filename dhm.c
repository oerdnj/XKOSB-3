/*
 * SPDX-FileCopyrightText: Ondřej Surý
 *
 * SPDX-License-Identifier: WTFPL
 */

#include <assert.h>
#include <getopt.h>
#include <gmp.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define DEFAULT_BACKLOG 10

#define IN  0
#define OUT 1

#define DEFAULT_PRIME_BITS 512
#define PROBAB_PRIME_ITERS 50

#if __linux__

#define ntohll(big_endian_64bits) be64toh(big_endian_64bits)
#define htonll(host_64bits)	  htobe64(host_64bits)

#endif

/* Type-casting helpers */

#define uv_handle_set_data(handle, data) uv_handle_set_data((uv_handle_t *)(handle), (data))
#define uv_handle_get_data(handle)	 uv_handle_get_data((const uv_handle_t *)(handle))
#define uv_req_set_data(handle, data)	 uv_handle_set_data((uv_handle_t *)(handle), (data))
#define uv_req_get_data(handle)		 uv_handle_get_data((const uv_handle_t *)(handle))
#define uv_close(handle, close_cb)	 uv_close((uv_handle_t *)handle, close_cb)

typedef enum op_mode { no_mode = 0, client_mode, server_mode } op_mode_t;

typedef enum {
	READ_NONE,
	READ_P,	     /* Read DH modulus */
	READ_G,	     /* Read DH base */
	READ_PUB,    /* Read DH public key */
	READ_HEADER, /* Read stream cipher header */
	READ_DATA,   /* Read stream cipher data */
	READ_DONE,   /* Future -> when shutting down */
} readstate_t;

typedef struct state {
	struct { /* DH */
		mpz_t p;
		mpz_t g;
		mpz_t private;
		mpz_t public;
		mpz_t secret;
	};

	bool tty_initialized;
	uv_tty_t tty[2];

	readstate_t rstate;
	union {
		struct __attribute__((__packed__)) {
			size_t len;
			char base[2 * 65536];
		};
		char buffer[(2 * 65536) + sizeof(size_t)];
	} read_s;
	size_t readlen;

	union {
		struct sockaddr addr;
		struct sockaddr_storage addr_ss;
	};

	struct { /* XChaCha20-Poly1305 */
		uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
		uint8_t header[2][crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		crypto_secretstream_xchacha20poly1305_state state[2];
	} stream;
} state_t;

state_t *
state_new(void) {
	state_t *state = calloc(1, sizeof(*state));

	mpz_inits(state->p, state->g, state->private, state->public, state->secret, NULL);

	return state;
}

void
state_free(state_t *state) {
	mpz_clears(state->p, state->g, state->private, state->public, state->secret, NULL);
	free(state);
}

void
state_close_cb(uv_handle_t *handle) {
	state_t *state = uv_handle_get_data(handle);

	state_free(state);
}

void
state_close(uv_stream_t *stream, state_t *state) {
	/*
	 * TODO: Send the final tag to other party instead of just
	 * closing connection
	 */

	/*
	 * This need to be in reverse order as the uv_loop queue is processed in
	 * reverse.
	 */
	uv_close(stream, state_close_cb);
	if (state->tty_initialized) {
		uv_close(&state->tty[1], NULL);
		uv_close(&state->tty[0], NULL);
	}
}

typedef struct write {
	uv_write_t req;
	uv_buf_t wbuf[2];
	size_t wlen;
	void *data;
} write_t;

write_t *
write_new(uv_stream_t *stream) {
	write_t *write = calloc(1, sizeof(*write));

	write->wbuf[0].base = (char *)&write->wlen;
	write->wbuf[0].len = sizeof(write->wlen);
	write->data = stream;

	uv_req_set_data(&write->req, write);

	return write;
}

void *
write_get_data(write_t *write) {
	return write->data;
}

void
write_free(write_t *write) {
	if (write->wbuf[1].base != NULL) {
		free(write->wbuf[1].base);
	}
	if (write->wbuf[0].base != (char *)&write->wlen) {
		free(write->wbuf[0].base);
	}
	free(write);
}

void
write_buf(uv_stream_t *stream, uv_buf_t *buf, uv_write_cb cb) {
	write_t *write = write_new(stream);
	write->wbuf[1] = *buf;
	write->wlen = htonll(buf->len);

	int r = uv_write(&write->req, stream, write->wbuf, 2, cb);
	assert(r == 0);
}

/* Global random state */
gmp_randstate_t randstate;

static inline void
mpz_urandomm1(mpz_t rop, gmp_randstate_t randstate, const mpz_t n);

void
alloc_cb(uv_handle_t *handle __attribute__((__unused__)), size_t suggested_size, uv_buf_t *buf) {
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

void
write_prompt(uv_stream_t *stream, state_t *state);

void
on_write_data(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	write_free(write);
}

void
write_data(uv_stream_t *stream, const uv_buf_t *buf) {
	state_t *state = uv_handle_get_data(stream);
	unsigned long long clen = buf->len + crypto_secretstream_xchacha20poly1305_ABYTES;
	uint8_t *c = malloc(clen);

	crypto_secretstream_xchacha20poly1305_push(&state->stream.state[OUT], c, &clen, (uint8_t *)buf->base, buf->len,
						   NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
	uv_buf_t tmp = {
		.base = (char *)c,
		.len = clen,
	};

	write_buf(stream, &tmp, on_write_data);
}

void
on_tty_write(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	uv_stream_t *stream = write_get_data(write);
	state_t *state = uv_handle_get_data(stream);

	write_free(write);

	write_prompt(stream, state);
}

readstate_t
read_data(uv_stream_t *stream, state_t *state, uv_buf_t *buf) {
	uint8_t *m = malloc(buf->len - crypto_secretstream_xchacha20poly1305_ABYTES);
	unsigned long long mlen;
	unsigned char tag;

	if (crypto_secretstream_xchacha20poly1305_pull(&state->stream.state[IN], m, &mlen, &tag, (uint8_t *)buf->base,
						       buf->len, NULL, 0) != 0)
	{
		/* Invalid/incomplete/corrupted ciphertext - abort */
		/* FIXME: Close gracefully */
		abort();
	}

	write_t *write = write_new(stream);
	write->wbuf[0] = (uv_buf_t){
		.base = strdup("\r< "),
		.len = 3,
	};
	write->wbuf[1] = (uv_buf_t){
		.base = (char *)m,
		.len = mlen,
	};

	int r = uv_write(&write->req, (uv_stream_t *)&state->tty[OUT], write->wbuf, 2, on_tty_write);
	assert(r == 0);

	switch (tag) {
	case crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
		/* Ordinary message, continue reading */
		return READ_DATA;
	case crypto_secretstream_xchacha20poly1305_TAG_FINAL:
		/* End of the message, shutdown the stream */
		return READ_DONE;
	default:
		abort();
	}
}

void
tty_read_cb(uv_stream_t *tty, ssize_t nread, const uv_buf_t *buf) {
	uv_stream_t *stream = uv_handle_get_data(tty);
	state_t *state = uv_handle_get_data(stream);

	if (nread < 0) {
		if (buf->base != NULL) {
			free(buf->base);
		}

		state_close(stream, state);

		return;
	}

	int r = uv_read_stop(tty);
	assert(r == 0);

	uv_buf_t tmp = {
		.base = buf->base,
		.len = nread,
	};

	write_data(stream, &tmp);

	free(buf->base);

	write_prompt(stream, state);
}

void
on_write_prompt(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	uv_stream_t *stream = write_get_data(write);
	state_t *state = uv_handle_get_data(stream);

	if (!uv_is_active((uv_handle_t *)&state->tty[IN])) {
		/* Prompt written, start reading from tty */
		int r = uv_read_start((uv_stream_t *)&state->tty[IN], alloc_cb, tty_read_cb);
		assert(r == 0);
	}

	write_free(write);
}

void
write_prompt(uv_stream_t *stream, state_t *state) {
	write_t *write = write_new(stream);
	write->wbuf[0] = (uv_buf_t){
		.base = strdup("> "),
		.len = 2,
	};

	int r = uv_write(&write->req, (uv_stream_t *)&state->tty[OUT], write->wbuf, 1, on_write_prompt);
	assert(r == 0);
}

void
on_write_header(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	uv_stream_t *stream = write_get_data(write);
	state_t *state = uv_handle_get_data(stream);
	uv_loop_t *loop = uv_default_loop();

	/* Initialize reading from stdin */
	int r = uv_tty_init(loop, &state->tty[IN], IN, 0);
	assert(r == 0);
	uv_handle_set_data(&state->tty[IN], stream);

	r = uv_tty_init(loop, &state->tty[OUT], OUT, 0);
	assert(r == 0);
	uv_handle_set_data(&state->tty[OUT], stream);

	state->tty_initialized = true;

	write_prompt(stream, state);

	free(req);
}

void
write_header(uv_stream_t *stream) {
	state_t *state = uv_handle_get_data(stream);

	uv_buf_t buf = {
		.base = (char *)state->stream.header[OUT],
		.len = sizeof(state->stream.header[OUT]),
	};

	write_buf(stream, &buf, on_write_header);
}

readstate_t
read_header(state_t *state, uv_buf_t *buf) {
	assert(buf->len == crypto_secretstream_xchacha20poly1305_HEADERBYTES);

	memmove(state->stream.header[IN], buf->base, crypto_secretstream_xchacha20poly1305_HEADERBYTES);

	/* Decrypt the stream: initializes the state, using the key and a header */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&state->stream.state[IN], state->stream.header[IN],
							    state->stream.key) != 0)
	{
		/* FIXME: Close the stream gracefully */
		abort();
	}

	return READ_DATA;
}

void
on_write_pub(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);

	write_free(write);
}

void
write_pub(uv_stream_t *stream) {
	uv_buf_t buf;
	state_t *state = uv_handle_get_data(stream);

	buf.base = mpz_export(NULL, &buf.len, 1, sizeof(uint8_t), 1, 0, state->public);

	write_buf(stream, &buf, on_write_pub);
}

void
on_write_g(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	uv_stream_t *stream = write_get_data(write);

	write_free(write);

	write_pub(stream);
}

void
write_g(uv_stream_t *stream) {
	uv_buf_t buf;
	state_t *state = uv_handle_get_data(stream);

	buf.base = mpz_export(NULL, &buf.len, 1, sizeof(uint8_t), 1, 0, state->g);

	write_buf(stream, &buf, on_write_g);
}

void
on_write_p(uv_write_t *req, int status) {
	assert(status == 0);

	write_t *write = uv_req_get_data(req);
	uv_stream_t *stream = write_get_data(write);

	write_free(write);

	write_g(stream);
}

void
write_p(uv_stream_t *stream) {
	uv_buf_t buf;
	state_t *state = uv_handle_get_data(stream);

	buf.base = mpz_export(NULL, &buf.len, 1, sizeof(uint8_t), 1, 0, state->p);

	write_buf(stream, &buf, on_write_p);
}

void
compute_key(state_t *state) {
	/* Now compute key and header for XChaCha20-Poly1309 */

	uv_buf_t keybuf;
	keybuf.base = mpz_export(NULL, &keybuf.len, 1, sizeof(uint8_t), 1, 0, state->secret);

	crypto_generichash(state->stream.key, sizeof(state->stream.key), (uint8_t *)keybuf.base, keybuf.len, NULL, 0);

	free(keybuf.base);

	printf("Hashed XChaCha20-Poly1309 key is ");
	for (size_t i = 0; i < sizeof(state->stream.key); i++) {
		printf("%x", state->stream.key[i]);
	}
	printf("\n");
}

void
compute_header(state_t *state) {
	/* Now header for XChaCha20-Poly1309 */
	crypto_secretstream_xchacha20poly1305_init_push(&state->stream.state[OUT], state->stream.header[OUT],
							state->stream.key);
}

readstate_t
read_pub(state_t *state, uv_buf_t *buf) {
	mpz_t other_public;
	mpz_init(other_public);

	mpz_import(other_public, buf->len, 1, sizeof(uint8_t), 1, 0, buf->base);
	gmp_printf("Other public key   is %Zd\n", other_public);

	mpz_powm(state->secret, other_public, state->private, state->p);
	gmp_printf("Computed secret key is %Zd\n", state->secret);

	mpz_clear(other_public);

	return (READ_HEADER);
}

void
compute_pub(state_t *state) {
	/* choose a secret integer for client private key */
	mpz_urandomm1(state->private, randstate, state->p);
	gmp_printf("Client private key is %Zd\n", state->private);

	/* Calculate client public key */
	mpz_powm(state->public, state->g, state->private, state->p);
	gmp_printf("Client public key  is %Zd\n", state->public);
}

readstate_t
read_g(state_t *state, uv_buf_t *buf) {
	mpz_import(state->g, buf->len, 1, sizeof(uint8_t), 1, 0, buf->base);
	gmp_printf("Client base (g)    is %Zd\n", state->g);

	return (READ_PUB);
}

readstate_t
read_p(state_t *state, uv_buf_t *buf) {
	mpz_import(state->p, buf->len, 1, sizeof(uint8_t), 1, 0, buf->base);
	gmp_printf("Client modulus (p) is %Zd\n", state->p);

	return (READ_G);
}

void
read_buf(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	state_t *state = uv_handle_get_data(stream);

	if (nread < 0) {
		if (buf->base != NULL) {
			free(buf->base);
		}

		/* Close the stream */
		state_close(stream, state);

		return;
	}

	assert(state->readlen + nread < sizeof(state->read_s.buffer));

	/* Copy received data into own internal buffer */
	memmove(&state->read_s.buffer[state->readlen], buf->base, nread);
	state->readlen += nread;

	free(buf->base);

again:
	/* Not enough data for a header length */
	if (state->readlen < sizeof(state->read_s.len)) {
		/* continue reading */
		return;
	}

	uv_buf_t rbuf = {
		.base = state->read_s.base,
		.len = ntohll(state->read_s.len),
	};

	size_t consumed = rbuf.len + sizeof(rbuf.len);

	/* Not enough data read so far */
	if (state->readlen < consumed) {
		/* continue reading */
		return;
	}

	switch (state->rstate) {
	case READ_P:
		state->rstate = read_p(state, &rbuf);
		break;
	case READ_G:
		state->rstate = read_g(state, &rbuf);

		/* Now we have both p and g, so we can finally calculate our a and A */
		compute_pub(state);
		/* Now write the public key to the other party */
		write_pub(stream);
		break;
	case READ_PUB:
		state->rstate = read_pub(state, &rbuf);

		/* Now we have p, g and other party's public key */
		compute_key(state);
		compute_header(state);

		/* Write the stream cipher header */
		write_header(stream);
		break;
	case READ_HEADER:
		state->rstate = read_header(state, &rbuf);
		break;
	case READ_DATA:
		state->rstate = read_data(stream, state, &rbuf);
		break;
	default:
		abort();
	}

	/* Move the consumed data in the buffer */
	size_t newlen = state->readlen - consumed;
	if (newlen > 0) {
		memmove(state->read_s.buffer, state->read_s.buffer + consumed, newlen);
	}
	state->readlen -= consumed;

	/* try to consume more data from the buffer */
	goto again;
}

void
on_new_connection(uv_stream_t *server, int status) {
	assert(status == 0);

	state_t *sstate = uv_handle_get_data(server);
	uv_tcp_t *client = malloc(sizeof(*client));
	uv_loop_t *loop = uv_default_loop();
	state_t *cstate = state_new();

	int r = uv_tcp_init(loop, client);
	assert(r == 0);

	r = uv_accept(server, (uv_stream_t *)client);
	assert(r == 0);

	/* Copy p and g from server state */
	mpz_set(cstate->p, sstate->p);
	mpz_set(cstate->g, sstate->g);

	/* Choose a secret integer for the private key in <1, p-1> range */
	mpz_urandomm1(cstate->private, randstate, cstate->p);
	gmp_printf("Server private key is %Zd\n", cstate->private);

	/* Calculate the public key */
	mpz_powm(cstate->public, cstate->g, cstate->private, cstate->p);
	gmp_printf("Server public key  is %Zd\n", cstate->public);

	cstate->rstate = READ_PUB;

	uv_handle_set_data(client, cstate);

	write_p((uv_stream_t *)client);

	r = uv_read_start((uv_stream_t *)client, alloc_cb, read_buf);
	assert(r == 0);
}

int
gen_safe_prime(mpz_t rop, mp_bitcnt_t n) {
	int r = 0;
	mpz_t prime;
	mpz_t prime0;
	mpz_t rem;

	printf("Generating DH parameters, %lu bit long safe prime\n", n);

	mpz_inits(prime, prime0, rem, NULL);

	/* Generate a starting point */
	mpz_rrandomb(prime, randstate, n);
	r = mpz_probab_prime_p(prime, PROBAB_PRIME_ITERS);

	/*
	 * FIXME: Check for the overflow <- restart if we have more bits than
	 * requested
	 */
	do {
		if (r == 0) {
			mpz_nextprime(prime, prime);
		}

		mpz_sub_ui(prime0, prime, 1);
		mpz_tdiv_qr_ui(prime0, rem, prime0, 2);

		assert(mpz_cmp_ui(rem, 0) == 0);

		/* Check if (p - 1)/2 is also prime */
		r = mpz_probab_prime_p(prime0, PROBAB_PRIME_ITERS);
		printf(r > 0 ? "+\n" : ".");
		fflush(stdout);
	} while (!r);

	mpz_set(rop, prime);
	mpz_clears(prime, prime0, rem, NULL);

	return r;
}

void
usage(int argc __attribute__((__unused__)), char **argv) {
	fprintf(stderr,
		"usage: %s [--client|--server] [--bits <bits>] [--modulus <prime>] [--base <prime root>] <address> "
		"<port>\n",
		argv[0]);
	exit(1);
}

static inline void
mpz_urandomm1(mpz_t rop, gmp_randstate_t randstate, const mpz_t n) {
	mpz_t n1;
	mpz_t rnd;
	mpz_inits(n1, rnd, NULL);

	mpz_sub_ui(n1, n, 1);
	mpz_urandomm(rnd, randstate, n1);
	mpz_add_ui(rnd, rnd, 1);
	mpz_set(rop, rnd);
	mpz_clears(n1, rnd, NULL);
}

int
server(state_t *state) {
	gmp_printf("Server modulus (p) is %Zd\n", state->p);
	gmp_printf("Server base (g)    is %Zd\n", state->g);

	uv_tcp_t tcp;
	uv_loop_t *loop = uv_default_loop();

	int r = uv_tcp_init(loop, &tcp);
	assert(r == 0);
	uv_handle_set_data(&tcp, state);

	r = uv_tcp_nodelay(&tcp, 1);
	assert(r == 0);

	r = uv_tcp_bind(&tcp, &state->addr, 0);
	assert(r == 0);

	r = uv_listen((uv_stream_t *)&tcp, 10, on_new_connection);
	assert(r == 0);

	r = uv_run(loop, UV_RUN_DEFAULT);
	assert(r == 0);

	uv_loop_close(loop);

	return 0;
}

void
on_connect(uv_connect_t *req, int status) {
	assert(status == 0);

	uv_stream_t *stream = uv_req_get_data(req);
	state_t *state = uv_handle_get_data(stream);

	state->rstate = READ_P;

	int r = uv_read_start(stream, alloc_cb, read_buf);
	assert(r == 0);

	free(req);
}

int
client(state_t *state) {
	uv_tcp_t tcp;
	uv_loop_t *loop = uv_default_loop();

	int r = uv_tcp_init(loop, &tcp);
	assert(r == 0);
	uv_handle_set_data(&tcp, state);

	r = uv_tcp_nodelay(&tcp, 1);
	assert(r == 0);

	uv_connect_t *req = malloc(sizeof(*req));
	uv_req_set_data(req, &tcp);

	r = uv_tcp_connect(req, &tcp, &state->addr, on_connect);
	assert(r == 0);

	r = uv_run(loop, UV_RUN_DEFAULT);

	uv_loop_close(loop);

	return 0;
}

void
init(void) {
	/* Initialize global randomstate */
	unsigned int randseed;
	int r = uv_random(NULL, NULL, &randseed, sizeof(randseed), 0, NULL);
	assert(r == 0);
	gmp_randinit_default(randstate);
	gmp_randseed_ui(randstate, randseed);

	if (sodium_init() == -1) {
		abort();
	}
}

void
cleanup(void) {
	/* Cleanup randstate */
	gmp_randclear(randstate);
}

/* C program to demonstrate the Diffie-Hellman algorithm */
int
main(int argc, char **argv) {
	op_mode_t op_mode = no_mode;
	state_t *state = state_new();
	int rv = 0;
	int ch;
	int prime_bits = DEFAULT_PRIME_BITS;

	init();

	static struct option longopts[] = {
		{ "bits", required_argument, NULL, 'b' }, { "client", no_argument, NULL, 'c' },
		{ "server", no_argument, NULL, 's' },	  { "modulus", required_argument, NULL, 'p' },
		{ "base", required_argument, NULL, 'g' },
	};

	bool have_p = false;
	bool have_g = false;
	while ((ch = getopt_long(argc, argv, "b:csp:g:", longopts, NULL)) != -1) {
		switch (ch) {
		case 'b':
			prime_bits = atoi(optarg);
			if (prime_bits < 3) {
				fprintf(stderr, "ERROR: Prime bits must be at least 3 bits\n");
				rv = 1;
				goto out;
			}
			break;
		case 'c':
			if (op_mode == server_mode) {
				fprintf(stderr, "ERROR: You cannot specify both client and server\n");
				rv = 1;
				goto out;
			}
			op_mode = client_mode;
			break;
		case 's':
			if (op_mode == client_mode) {
				fprintf(stderr, "ERROR: You cannot specify both client and server\n");
				rv = 1;
				goto out;
			}
			op_mode = server_mode;
			break;
		case 'p':
			if (mpz_set_str(state->p, optarg, 10) == -1) {
				fprintf(stderr, "ERROR: Invalid modulus: %s\n", optarg);
				rv = 1;
				goto out;
			}
			have_p = true;
			break;
		case 'g':
			if (mpz_set_str(state->g, optarg, 10) == -1) {
				fprintf(stderr, "ERROR: Invalid base: %s\n", optarg);
				rv = 1;
				goto out;
			}
			have_g = true;
			break;
		default:
			usage(argc, argv);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		fprintf(stderr, "ERROR: Missing IP address and port\n");
		argc += optind;
		argv -= optind;
		usage(argc, argv);
	}

	char *ip = argv[0];
	int port = atoi(argv[1]);

	/* Initialize the server (and) client sockaddr */
	uv_ip6_addr(ip, port, (struct sockaddr_in6 *)&state->addr);

	if ((have_p && !have_g) || (!have_p && have_g)) {
		fprintf(stderr, "You either need to set both p and g or none!\n");
		rv = 1;
		goto out;
	}

	switch (op_mode) {
	case server_mode:
		/* Generate our p and g */
		if (!have_p && !have_g) {
			int r = gen_safe_prime(state->p, prime_bits);
			assert(r > 0);
		}
		/* Generator can be 2 for any safe prime */
		mpz_init_set_ui(state->g, 2);

		rv = server(state);
		break;
	case client_mode:
		rv = client(state);
		break;
	default:
		abort();
	}

out:
	cleanup();
	return rv;
}
