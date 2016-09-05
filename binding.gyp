{
  "targets": [
    {
      "target_name": "sha512_crypt",
      "sources": [ "sha512crypt.cc" ],
      "include_dirs" : [ "<!(node -e \"require('nan')\")" ]
    }
  ]
}
