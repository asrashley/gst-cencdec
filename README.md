This package provides an example GStreamer element that implements
DASH Common Encryption (ISO/IEC23001-7 Information technology — MPEG 
systems technologies — Part 7: Common encryption in ISO base media 
file format files).

It takes video or audio (of type "application/x-cenc")
from qtdemux and performs the AES-CTR decryption and outputs the decrypted
content on a source pad.

Requirements
------------
*    gstreamer 1.11
*    Openssl >=1.0.0h

Usage
-----
The decryptor does not implement a real DRM system. It provides partial
support for Marlin and Clearkey protection systems, in that it advertises
these two systems in its supported content protection system IDs.

It has no support for robustly acquiring the keys, it just looks in the
local filesystem for a file that contains the key.

In the case of Marlin, it performs a sha1 hash of the content ID, converts
that to a hex string and then looks for a file
/tmp/\<hash string\>.key that contains the binary data of the key.

In the case of Clearkey, it converts the KID to a hex string and then looks
for a file /tmp/\<hex KID string\>.key that contains the binary data of the key.

There is a store-key.py Python application that will write the key into the
appropriate location. The usage is:

    ./store-key.py <KID> <KEY>

Where:
  <KID> is the hex value of the key ID
  <KEY> is either the hex or base64 encoded value of the key

Example usage:

    ./store-key.py 00000000000000000000000000000000 0123456789ABCDEF0123456789ABCDEF
    ./store-key.py 0bbc0bbc0bbc0bbc0bbc0bbc0bbc1bbc ABCDEF0123456789ABCDEF0123456789
    gst-launch-1.0 playbin uri='http://test-media.youview.co.uk/ondemand/bbb/avc3/1/2drm_manifest.mpd'


Clearkey example:
    ./store-key.py 0872786e-f9e7-465f-a3a2-4e5b0ef8fa45 'wyYRebq2Hu7JedLUBpURzw=='
    ./store-key.py 2d6e9387-60ca-4145-aec2-c40837b4b026 'QtC/8bYPe+SfF9YDSE0MuQ=='
    ./store-key.py 4222bd78-bc45-41bf-b63e-6f814dc391df 'GAMi9v92b9ca5yBwaptN+Q=='
    ./store-key.py 585f233f-3072-46f1-9fa4-6dc22c66a014 'jayKpC3tmPq4YKXkapa8FA=='
    ./store-key.py 9eb4050de44b4802932e27d75083e266 166634c675823c235a4a9446fad52e4d
    ./store-key.py c14f0709-f2b9-4427-916b-61b52586506a '7fsXeXJHs8enQ0SEfkhTBQ=='
    ./store-key.py de02f07f-a098-4ee0-b556-907c0d17fbbc 'GQnGyyKBez4x8aNTD6cNzw=='
    gst-launch-1.0 playbin uri='https://media.axprod.net/TestVectors/v7-MultiDRM-MultiKey-MultiPeriod/Manifest_1080p_ClearKey.mpd'

or

    gst-launch-1.0 playbin uri='https://media.axprod.net/TestVectors/v7-MultiDRM-MultiKey/Manifest_AudioOnly_ClearKey.mpd'
