This package provides an example GStreamer element that implements
DASH Common Encryption (ISO/IEC23001-7 Information technology — MPEG 
systems technologies — Part 7: Common encryption in ISO base media 
file format files).

It takes video or audio (of type "application/x-cenc")
from qtdemux and performs the AES-CTR decryption and outputs the decrypted
content on a source pad.

Requirements
------------
*   gstreamer 1.4
*   Openssl >=1.0.0h
*   [DASH CENC patches] [1] for gst-plugins-base, qtdemux and dashdemux

Usage
-----
The decryptor implements a fake DRM system. It requires a PSSH box in
the initialisation segment that has a system ID of:

    78f32170-d883-11e0-9572-0800200c9a66

In this PSSH box it has the following syntax:

    version    [1 byte] = 1
    unused     [19 bytes]
    key_count  [4 bytes, uint32]
    for(i=0; i<key_count; ++i){
        key_id [16 bytes]
    }
    for(i=0; i<key_count; ++i){
        url_length  [1 byte]
        url         [url_length bytes]
    }

The element will attempt to download the keys from the given URL.

For example:

    gst-launch-1.0 playbin uri='http://test-media.youview.co.uk/ondemand/bbb/avc3/1/client_manifest.mpd'


[1]: https://bugzilla.gnome.org/show_bug.cgi?id=705991

