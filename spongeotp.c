// Copyright 2015 Yahoo! Inc.
// LICENSE: Apache2

#include "keccak-tiny/shakemac.h"

#include <time.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


static const uint8_t sotp_alpha[24] = "ybndrfgejkmcpqxotuwiszah";

static const uint8_t EXAMPLE_SECRET[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

#define sotp_state keccak_sponge

/** Initialize an SOTP generator.
 *
 * @param username [in]     The username.
 * @param usernamelen [in]  The length of the username.
 * @param secret [in]       A pointer to a 32-byte secret.
 */
int sotp_init(sotp_state* st,
              const uint8_t* username,
              size_t usernamelen,
              const uint8_t* secret) {
  int err = mac_init(st, secret, 32);
  if (err != 0) {
    return err;
  }
  err = mac_absorb(st, username, usernamelen);
  return err;
}

int sotp_gen(sotp_state* st,
             uint8_t* out,
             size_t outlen) {
  time_t t = time(NULL);
  if (t == ((time_t)-1)) {
    // An error occurred getting the time. This can occur according
    // to the POSIX standard, though I don't know of any systems
    // that actually do this... (They usually merrily return any
    // arbitrary number they want.)
    return -1;
  }
  // Truncate to 8 seconds. (TODO: Use reasonable rounding method
  // and make configurable.)
  //
  // Serialize the time in little-endian order.
  uint8_t tbuf[4] = {
    (uint8_t)(t & 0xff),
    (uint8_t)((t >> 8) & 0xff),
    (uint8_t)((t >> 16) & 0xff),
    (uint8_t)((t >> 24) & 0xff),
  };
  printf("tbuf: %02x %02x %02x %02x\n", tbuf[0], tbuf[1], tbuf[2], tbuf[3]);
  sotp_state temp;
  memcpy(&temp, st, sizeof(sotp_state));
  int err = shake256_absorb(&temp, tbuf, 4);
  shake256_squeeze(&temp, tbuf, 4);
  printf("tbuf: %02x %02x %02x %02x\n", tbuf[0], tbuf[1], tbuf[2], tbuf[3]);
  assert(err == 0);
  err = shake256_squeezemax(&temp, out, outlen, sizeof(sotp_alpha));
  assert(err == 0);
  memset(&temp, 0, sizeof(temp));
  return 0;
}

int sotp_translate(uint8_t* io, size_t iolen) {
  while (iolen) {
    if (*io > sizeof(sotp_alpha)) {
      printf("%zu: %x\n", iolen, *io);
      assert(NULL && "failed to be valid in alphabet");
      return -1;
    }
    *io = sotp_alpha[*io];
    io++, iolen--;
  }
  return 0;
}

int main(void) {
  // Initialize the SOTP generator.
  uint8_t username[] = "dgil@yahoo-inc.com";

  int err = 0;

  sotp_state st;
  err = sotp_init(&st, username, sizeof(username), EXAMPLE_SECRET); // this is not quite what you should do
  printf("got here\n");
  assert(err == 0);
  // Generate an SOTP every second.
  // (Please don't use sleep in real applications.)
  while (true) {
    uint8_t buf[16] = {0};
    err = sotp_gen(&st, buf, 16);
    printf("\ngot past gen\n");
    assert(err == 0);
    //err = sotp_translate(buf, 16);
    printf("got past translate\n");
    assert(err == 0);
    printf("0x%08lx:", time(NULL));
    for (size_t i = 0; i < 16; i++) {
      if ((i % 4) == 0) {
        printf(" ");
      }
      printf("%02u ", buf[i]);
    }
    printf("\n");

    fflush(stdout);
    sleep(1);
  }
  return 0;
}






