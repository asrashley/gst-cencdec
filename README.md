This package provides an example GStreamer element that implements
DASH Common Encryption (ISO/IEC23001-7 Information technology — MPEG 
systems technologies — Part 7: Common encryption in ISO base media 
file format files).

It takes video or audio (of type "application/x-cenc")
from qtdemux and performs the AES-CTR decryption and outputs the decrypted
content on a source pad.

Requirements
------------
*    gstreamer 1.4
*    Openssl >=1.0.0h
*    [DASH CENC patches] [1] for gst-plugins-base, qtdemux and dashdemux


Usage
-----
The decryptor does not implement a real DRM system. It performs a sha1
hash of the KID, converts that to a hex string and then looks for a file
/tmp/<hash string>.key that contains the binary data of the key.

    ./store-key.py 00000000000000000000000000000000 0123456789ABCDEF0123456789ABCDEF
    ./store-key.py 0bbc0bbc0bbc0bbc0bbc0bbc0bbc1bbc ABCDEF0123456789ABCDEF0123456789
    gst-launch-1.0 playbin uri='http://test-media.youview.co.uk/ondemand/bbb/avc3/1/2drm_manifest.mpd'


[1]: https://bugzilla.gnome.org/show_bug.cgi?id=705991
