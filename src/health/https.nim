## HTTPS probe (TCP + mbedTLS). Compile with -d:https to enable.

when defined(https):
  type
    HttpsSocket* = object
      fd*: cint
