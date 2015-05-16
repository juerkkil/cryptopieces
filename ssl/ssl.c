/* Simple HTTPS Client & certificate validator
 *
 * Compiling:
 * gcc -std=c99 ssl.c -o ssl -lcrypto -lssl
 *
 * Usage: ./ssl hostname port
 * Connects to server through socket, verifies the certificate chain and
 * dumps the contents of request URL to stdout.
 *
 * Written for Aalto University course T-110.5241 Network Security
 *
 * Jussi-Pekka Erkkilä, 2012
 */

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Where to look for pre-installed root CAs */
#define CERTIFICATE_DIRECTORY "/etc/ssl/certs"

/* First we define a structure, to make it easier passing variables between functions */
typedef struct {
  int socket;
  SSL *ssl_handle;
  SSL_CTX *ssl_context;
} ssl_conn;

char * request_url;

void ssl_write_data(ssl_conn *c, char *text);
int create_tcp_connection(char * hostname, int port);
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
ssl_conn * ssl_create_connection(char * hostname, unsigned int port);
void ssl_disconnect(ssl_conn *c);
char * ssl_read_data(ssl_conn *c);

int main(int argc, char **argv) {
  if(argc < 3) {
    printf("Usage: ./ssl [hostname] [port]\n");
    return 1;
  } 
  unsigned int port = atoi(argv[2]);
  request_url = argv[1];
  char * read_data;
  ssl_conn *c;

  c = ssl_create_connection(request_url, port);

  // Make HTTP request
  ssl_write_data(c, "GET / HTTP/1.1\r\n\r\n");
  // Read and print HTTP response
  read_data = ssl_read_data(c);
  printf("%s\n", read_data);

  ssl_disconnect(c);
  free(read_data);
  return 0;
}


// Set up normal TCP connection, return tcp-handle or zero if error
int create_tcp_connection(char * hostname, int port) {
  struct hostent * destination;
  struct sockaddr_in address;
  destination = gethostbyname(hostname);
  int tcp_handle = socket(AF_INET, SOCK_STREAM, 0);
  if(tcp_handle == -1) {
    printf("Exiting due to error: Unable to create TCP socket\n");
    exit(1);
  }

  memset(&(address.sin_zero), '\0', 8);
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr = *((struct in_addr *) destination->h_addr_list[0]);
  if(connect(tcp_handle,(struct sockaddr *)&address, sizeof(struct sockaddr)) == -1) {
    printf("Exiting due to error: Unable to open TCP socket\n");
    exit(1);
  }

  return tcp_handle;
}

/* Callback function for checking certificate chain - this function is called 
 * separately for each certificate of the chain. */

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  X509 *err_cert;
  int err, depth;
  char CN[256] = "";
  char ON[256] ="";
  char OU[256] = "";
  int fail = 0;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  printf("Certificate OK: ");
  if(preverify_ok) 
    printf("yes\n");
  else { 
    printf("no\n");
    printf("Problem: %s\n", X509_verify_cert_error_string(err));
  }

  /* Get and print subject info */
  printf("Certificate subject:\n");
  X509_NAME_get_text_by_NID( X509_get_subject_name(err_cert),  
    NID_commonName, CN, 256); 
  X509_NAME_get_text_by_NID( X509_get_subject_name(err_cert),  
    NID_organizationName, ON, 256); 
  X509_NAME_get_text_by_NID( X509_get_subject_name(err_cert),  
    NID_organizationalUnitName, OU, 256); 
  if(strlen(CN) > 0)
    printf(" - Common name: %s\n", CN);
  if(strlen(ON) > 0)
    printf(" - Organization name: %s\n", ON);
  if(strlen(OU) > 0)
    printf(" - Organizational unit: %s\n", OU);
  if(depth == 0) {
    if(strcmp(request_url, CN) != 0)
      fail = 1;
  }

  /* Empty values so that issuer info will not be mixed up with these */
  CN[0]='\0';
  ON[0]='\0';
  OU[0]='\0';

  /* Get and print certificate issuer info */
  printf("Certificate issuer:\n");
  X509_NAME_get_text_by_NID( X509_get_issuer_name(err_cert),  
    NID_commonName, CN, 256); 
  X509_NAME_get_text_by_NID( X509_get_issuer_name(err_cert),  
    NID_organizationName, ON, 256); 
  X509_NAME_get_text_by_NID( X509_get_issuer_name(err_cert),  
    NID_organizationalUnitName, OU, 256); 
  if(strlen(CN) > 0)
    printf(" - Common name: %s\n", CN);
  if(strlen(ON) > 0)
    printf(" - Organization name: %s\n", ON);
  if(strlen(OU) > 0)
    printf(" - Organizational unit: %s\n", OU);

  printf("===\n");
  if(!preverify_ok){
    printf("Exiting due to error: SSL Error, %s\n", X509_verify_cert_error_string(err));
    exit(1);
  }
  if(depth==0 && fail) {
    printf("Exiting due to error: Subject's CN does not match to hostname\n");
    exit(1);
  }
  return preverify_ok;
}


/* Create new connection on SSL layer */
ssl_conn * ssl_create_connection(char * hostname, unsigned int port) {
  // Allocate & init the structure
  ssl_conn * conn = malloc(sizeof(ssl_conn));
  conn->ssl_handle = NULL;
  conn->ssl_context = NULL;

  /* Create TCP socket */
  conn->socket = create_tcp_connection(hostname, port);
  if(conn->socket) {
    /* If socket initialized succesfully, create set up SSL connection */
    SSL_load_error_strings();
    SSL_library_init();

    conn->ssl_context = SSL_CTX_new(TLSv1_client_method());
    if(conn->ssl_context == NULL) {
      printf("Exiting due to error: \n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }

    /* Load root CAs from local machine */
    if(!SSL_CTX_load_verify_locations(conn->ssl_context, NULL, CERTIFICATE_DIRECTORY)) {
      printf("Exiting due to error:\n Cannot load certificates at %s\n", CERTIFICATE_DIRECTORY);
      exit(1);
    }

    /* Set verify_callback function and maximum verify depth level */
    SSL_CTX_set_verify(conn->ssl_context, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(conn->ssl_context, 5);

    // Create an SSL struct for the connection
    conn->ssl_handle = SSL_new(conn->ssl_context);
    if(conn->ssl_handle == NULL) {
      printf("Exiting due to error: \n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }

    // Connect the SSL struture to TCP socket
    if(!SSL_set_fd(conn->ssl_handle, conn->socket)) {
      printf("Exiting due to error: \n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    // SSL Handshake
    SSL_connect(conn->ssl_handle);

  } else {
    printf("Exiting due to error: Connection failed\n");
  }
  return conn;
}

// Close socket and SSL connection, free resources
// NOTE: parts of the code copy-pasted, see README
void ssl_disconnect(ssl_conn *c)
{
  ssl_write_data(c, "Connection: close\r\n\r\n");
  // Close socket
  if(c->socket)
    close(c->socket);
  // Close SSL handle
  if(c->ssl_handle) {
    SSL_shutdown(c->ssl_handle);
    SSL_free(c->ssl_handle);
  }
  // And free SSL Context
  if(c->ssl_context)
    SSL_CTX_free(c->ssl_context);
  free(c);
}

// Read all available text from the connection
// NOTE: parts of the code copy-pasted, see README
char * ssl_read_data(ssl_conn *c) {
  const int buffer_size = 1024;
  char *rc = NULL;
  int received, count = 0;
  char buffer[buffer_size];

  if(c) {
    while(1) {
      if(!rc)
        rc = malloc(buffer_size * sizeof(char) + 1);
      else
        rc = realloc(rc, (count + 1) * buffer_size * sizeof(char) + 1);
      received = SSL_read(c->ssl_handle, buffer, buffer_size);
      buffer[received] = '\0';
      if(received > 0)
        strcat(rc, buffer);
      if(received < buffer_size)
        break;
      count++;
    }
  }
  return rc;
}

/* Write to the socket through SSL connection */
void ssl_write_data(ssl_conn *c, char *text) {
  if(c)
    SSL_write(c->ssl_handle, text, strlen(text));
}

