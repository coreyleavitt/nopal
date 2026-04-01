## HTTP HEAD probe (TCP port 80).

type
  HttpSocket* = object
    fd*: cint
