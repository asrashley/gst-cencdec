/* GStreamer ISO MPEG DASH common encryption decryptor
 * Copyright (C) 2013 YouView TV Ltd. <alex.ashley@youview.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */

#include <openssl/opensslv.h>
#include <openssl/aes.h>

#if OPENSSL_VERSION_NUMBER > 0x010100000
#include <openssl/modes.h>
#endif

#include <string.h>

#include "gstaesctr.h"

struct _AesCtrState
{
  volatile gint refcount;
  AES_KEY key;
  unsigned char ivec[16];
  unsigned int num;
  unsigned char ecount[16];
};

AesCtrState *
gst_aes_ctr_decrypt_new (GBytes * key, GBytes * iv)
{
  unsigned char *buf;
  gsize iv_length;
  AesCtrState *state;

  g_return_val_if_fail (key != NULL, NULL);
  g_return_val_if_fail (iv != NULL, NULL);

  state = g_slice_new (AesCtrState);
  if (!state) {
    GST_ERROR ("Failed to allocate AesCtrState");
    return NULL;
  }
  g_return_val_if_fail (g_bytes_get_size (key) == 16, NULL);
  AES_set_encrypt_key ((const unsigned char *) g_bytes_get_data (key, NULL),
      8 * g_bytes_get_size (key), &state->key);

  buf = (unsigned char *) g_bytes_get_data (iv, &iv_length);
  g_return_val_if_fail (buf != NULL, NULL);
  g_return_val_if_fail (iv_length == 8 || iv_length == 16, NULL);
  state->num = 0;
  memset (state->ecount, 0, 16);
  if (iv_length == 8) {
    memset (state->ivec + 8, 0, 8);
    memcpy (state->ivec, buf, 8);
  } else {
    memcpy (state->ivec, buf, 16);
  }
  return state;
}

AesCtrState *
gst_aes_ctr_decrypt_ref (AesCtrState * state)
{
  g_return_val_if_fail (state != NULL, NULL);

  g_atomic_int_inc (&state->refcount);

  return state;
}

void
gst_aes_ctr_decrypt_unref (AesCtrState * state)
{
  g_return_if_fail (state != NULL);

  if (g_atomic_int_dec_and_test (&state->refcount)) {
    g_slice_free (AesCtrState, state);
  }
}


void
gst_aes_ctr_decrypt_ip (AesCtrState * state, unsigned char *data, int length)
{
#if OPENSSL_VERSION_NUMBER > 0x010100000
  CRYPTO_ctr128_encrypt (data, data, length, &state->key, state->ivec,
      state->ecount, &state->num, (block128_f) AES_encrypt);
#else
  AES_ctr128_encrypt (data, data, length, &state->key, state->ivec,
      state->ecount, &state->num);
#endif
}

G_DEFINE_BOXED_TYPE (AesCtrState, gst_aes_ctr,
    (GBoxedCopyFunc) gst_aes_ctr_decrypt_ref,
    (GBoxedFreeFunc) gst_aes_ctr_decrypt_unref);
