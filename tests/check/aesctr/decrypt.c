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

#include <gst/check/gstcheck.h>
#include <gst/gst.h>
#include <gst/cencdrm/gstaesctr.h>

static AesCtrState *
setup_aes_decrypt(void)
{
/* NIST SP800-38a section F.5.2; CTR-AES128 Decrypt */
  const guint8 Key[]={ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  const guint8 IV[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
 AesCtrState *state;
 GBytes *gkey;
 GBytes *giv;

 gkey = g_bytes_new_static(Key,sizeof(Key));
 fail_if(gkey==NULL);
 giv = g_bytes_new_static(IV,sizeof(IV));
 fail_if(giv==NULL);
 state = gst_aes_ctr_decrypt_new(gkey, giv);
 fail_if(state==NULL);
 g_bytes_unref(gkey);
 g_bytes_unref(giv);

 return state;
}

static void decrypt_block(AesCtrState *state,
                          const guint8 *Ciphertext,
                          const guint8 *Plaintext,
                          guint length)
{
 GstBuffer *buf;
 GstMapInfo info;
 gboolean rv;
 gsize i;

 buf = gst_buffer_new_allocate (NULL,length,NULL);
 fail_if(buf==NULL);
 gst_buffer_fill(buf,0,Ciphertext,length);
 rv = gst_buffer_map(buf,&info,GST_MAP_READWRITE);
 fail_unless(rv==TRUE);
 gst_aes_ctr_decrypt_ip(state, info.data, info.size);
 for (i=0; i<info.size; ++i){
   fail_unless_equals_int(info.data[i],Plaintext[i]);
 }
 gst_buffer_unmap(buf,&info);
 gst_buffer_unref(buf);
}

GST_START_TEST (test_nist_aes_ctr) {
  /*Block #1*/
  const guint8 Ciphertext1[] ={ 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce};
  const guint8 Plaintext1[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
  /*Block #2*/
  const guint8 Ciphertext2[]={ 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff };
  const guint8 Plaintext2[]={ 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
  /*Block #3 */
  const guint8 Ciphertext3[]={ 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab };
  const guint8 Plaintext3[]={ 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
  /* Block #4 */
  const guint8 Ciphertext4[]={ 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee};
  const guint8 Plaintext4[]={ 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
  AesCtrState *state;

  state = setup_aes_decrypt();
  fail_if(state==NULL);
  decrypt_block(state,Ciphertext1, Plaintext1, sizeof(Ciphertext1));
  decrypt_block(state,Ciphertext2, Plaintext2, sizeof(Ciphertext2));
  decrypt_block(state,Ciphertext3, Plaintext3, sizeof(Ciphertext3));
  decrypt_block(state,Ciphertext4, Plaintext4, sizeof(Ciphertext4));
  gst_aes_ctr_decrypt_unref(state);
}
GST_END_TEST

static Suite *
aesctr_suite (void)
{
  Suite *s = suite_create ("aesctr");
  TCase *tc_chain = tcase_create ("general");

  suite_add_tcase (s, tc_chain);
  tcase_add_test (tc_chain, test_nist_aes_ctr);

  return s;
}

int
main (int argc, char **argv)
{
  int nf;

  Suite *s = aesctr_suite ();
  SRunner *sr = srunner_create (s);

  gst_check_init (&argc, &argv);

  srunner_run_all (sr, CK_NORMAL);
  nf = srunner_ntests_failed (sr);
  srunner_free (sr);

  return nf;
}
